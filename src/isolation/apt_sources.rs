//! Writing APT keyrings, repositories and preferences into a rootfs.
//!
//! [`AptChanges::apply`] writes what `prepare.apt` or `assemble.apt` declares. Nothing it
//! writes is taken back: `prepare.apt` configures the rootfs the image ships with, and
//! `assemble.apt` writes over it where the image should differ. [`configure`] is the
//! prepare-phase entry point, run while the mounts are up, and hands out the evidence the
//! resolv.conf guard requires.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use camino::Utf8Path;
use tracing::info;

use crate::config::MountEntry;
use crate::error::RsdebstrapError;
use crate::isolation::mount::Mounted;
use crate::phase::prepare::AptTask;
use crate::phase::prepare::apt::{
    AptKeySource, AptKeyring, AptPreference, AptRepository, KEYRINGS_DIR, KeyFormat, MAX_KEY_SIZE,
    SignedBy, sources_list_path,
};
use crate::rootfs::{FileMode, RelPath, RootfsOps};

/// Mode `/etc/apt/keyrings` is created with, the one apt's own package ships it with. apt
/// reads keyrings as the unprivileged `_apt` user, so the directory has to be searchable by
/// others.
const KEYRINGS_DIR_MODE: FileMode = FileMode::new(0o755);

/// Mode keyrings, `.sources` and `.pref` files are written with, readable by `_apt` for that
/// reason.
const FILE_MODE: FileMode = FileMode::new(0o644);

/// Downloads a keyring given by `url`. A function pointer rather than a call to
/// [`fetch_https`] so tests can run without a network.
pub(crate) type KeyFetcher = fn(&str) -> Result<Vec<u8>>;

/// Downloads `url` over https, refusing a body over [`MAX_KEY_SIZE`].
///
/// `https_only` covers redirects too, so a server cannot bounce the request to plain http.
/// The certificate is checked against the host's trust store rather than a bundled one, so
/// a key served behind an internal CA verifies the way the host's own tools would.
pub(crate) fn fetch_https(url: &str) -> Result<Vec<u8>> {
    use ureq::tls::{RootCerts, TlsConfig};

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .timeout_global(Some(Duration::from_secs(60)))
        .tls_config(
            TlsConfig::builder()
                .root_certs(RootCerts::PlatformVerifier)
                .build(),
        )
        .build()
        .into();
    let mut response = agent
        .get(url)
        .call()
        .with_context(|| format!("failed to download apt keyring from {}", url))?;
    response
        .body_mut()
        .with_config()
        .limit(MAX_KEY_SIZE)
        .read_to_vec()
        .with_context(|| format!("failed to read apt keyring from {}", url))
}

/// The apt configuration one phase writes: its entries, and whether it removes
/// `/etc/apt/sources.list`.
pub(crate) struct AptChanges<'a> {
    pub(crate) keyrings: &'a [AptKeyring],
    pub(crate) repositories: &'a [AptRepository],
    pub(crate) preferences: &'a [AptPreference],
    pub(crate) remove_sources_list: bool,
}

impl<'a> From<&'a AptTask> for AptChanges<'a> {
    fn from(task: &'a AptTask) -> Self {
        Self {
            keyrings: &task.keyrings,
            repositories: &task.repositories,
            preferences: &task.preferences,
            remove_sources_list: task.remove_sources_list,
        }
    }
}

impl AptChanges<'_> {
    /// Writes every keyring, repository and preference, replacing whatever is at their paths,
    /// then removes `/etc/apt/sources.list` if asked to.
    ///
    /// Every keyring is read, downloaded and checked before the first change, so a key that
    /// is missing, fails its `sha256`, or is not a public key fails with the rootfs untouched.
    /// The removal comes last, so that a failed write leaves the bootstrap's sources in
    /// place. Nothing is rolled back after the first change: a failure here fails the build,
    /// and what it leaves is not an image anyone is handed.
    ///
    /// `/etc/apt/keyrings` is made by [`RootfsOps::create_dir`] when missing, which is what
    /// keeps this safe under privilege: it resolves `/etc/apt` without following anything,
    /// and never adopts a symlink at `keyrings` as the directory -- which would otherwise
    /// send every keyring written next, as root, wherever the link points.
    pub(crate) fn apply(
        &self,
        ops: &dyn RootfsOps,
        rootfs: &Utf8Path,
        dry_run: bool,
        fetch: KeyFetcher,
    ) -> Result<()> {
        if dry_run {
            for keyring in self.keyrings {
                info!("would write apt keyring '{}' to {}", keyring.name, rootfs);
            }
            for repo in self.repositories {
                info!("would write apt repository {} to {}", repo.sources_path(), rootfs);
            }
            for preference in self.preferences {
                info!(
                    "would write apt preferences {} to {}",
                    preference.preferences_path(),
                    rootfs
                );
            }
            if self.remove_sources_list {
                info!("would remove {}{}", rootfs, sources_list_path());
            }
            return Ok(());
        }

        let files = self.render(fetch)?;
        if !self.keyrings.is_empty() {
            let dir = crate::config::rootfs_path(KEYRINGS_DIR);
            if ops
                .create_dir(&dir, KEYRINGS_DIR_MODE)
                .with_context(|| format!("failed to create {}{}", rootfs, dir))?
            {
                info!("created {}{}", rootfs, dir);
            }
        }
        for (path, content) in files {
            ops.write_file(&path, &content, FILE_MODE)
                .with_context(|| format!("failed to write {}{}", rootfs, path))?;
        }
        info!(
            "configured {} apt keyring(s), {} repository(ies) and {} preference file(s) in {}",
            self.keyrings.len(),
            self.repositories.len(),
            self.preferences.len(),
            rootfs
        );

        if self.remove_sources_list {
            let path = sources_list_path();
            // `take` rather than `remove`: it says whether there was one, and it refuses
            // anything but a file or a symlink -- a directory there is not ours to delete.
            let removed = ops
                .take(&path)
                .with_context(|| format!("failed to remove {}{}", rootfs, path))?
                .is_some();
            if removed {
                info!("removed {}{}", rootfs, path);
            }
        }
        Ok(())
    }

    /// Obtains every keyring and renders every repository and preference, in that order.
    fn render(&self, fetch: KeyFetcher) -> Result<Vec<(RelPath, Vec<u8>)>> {
        let mut keyring_paths = HashMap::new();
        let mut files = Vec::new();
        for keyring in self.keyrings {
            let bytes = keyring_bytes(keyring, fetch)
                .with_context(|| format!("apt keyring '{}'", keyring.name))?;
            let path = keyring.path(KeyFormat::detect(&bytes)?);
            keyring_paths.insert(keyring.name.as_str(), path.clone());
            files.push((path, bytes));
        }
        for repo in self.repositories {
            let signed_by = match repo.signed_by()? {
                Some(SignedBy::Keyring(name)) => {
                    Some(keyring_paths.get(name).cloned().ok_or_else(|| {
                        RsdebstrapError::Validation(format!(
                            "apt repository '{}': signed_by '{}' names no entry in keyrings",
                            repo.name, name
                        ))
                    })?)
                }
                Some(SignedBy::Path(path)) => Some(path),
                None => None,
            };
            files.push((repo.sources_path(), repo.render_sources(signed_by.as_ref()).into_bytes()));
        }
        for preference in self.preferences {
            files.push((preference.preferences_path(), preference.render().into_bytes()));
        }
        Ok(files)
    }
}

/// Obtains a keyring's bytes and checks them. Reading the host file happens here rather
/// than in `RootfsOps` for the reason the resolv.conf guard gives: the ops may be the
/// privileged helper, and what crosses to it should be bytes, not a host path.
fn keyring_bytes(keyring: &AptKeyring, fetch: KeyFetcher) -> Result<Vec<u8>> {
    let bytes = match &keyring.source {
        AptKeySource::Path(path) => crate::phase::read_host_file(path, "apt keyring")?,
        AptKeySource::Content(content) => content.as_bytes().to_vec(),
        AptKeySource::Url(url) => {
            info!("downloading apt keyring from {}", url);
            fetch(url)?
        }
    };
    if bytes.len() as u64 > MAX_KEY_SIZE {
        return Err(RsdebstrapError::Validation(format!(
            "key is {} bytes, refusing a key over {} bytes",
            bytes.len(),
            MAX_KEY_SIZE
        ))
        .into());
    }
    keyring.check_sha256(&bytes)?;
    Ok(bytes)
}

/// Evidence that the mounts are up and `prepare.apt` has been written.
///
/// [`RootfsResolvConf::setup`](crate::isolation::resolv_conf::RootfsResolvConf::setup)
/// requires one, so the `Prepared` it yields cannot exist unless [`configure`] ran. It holds
/// the [`Mounted`] it was given, so the mount guard cannot be torn down while it is alive,
/// and it names the apt task it wrote so the pipeline can compare it against its own
/// `prepare.apt`.
#[must_use]
#[derive(Debug)]
pub(crate) struct AptConfigured<'a> {
    mounted: Mounted<'a>,
    apt: Option<&'a AptTask>,
}

impl<'a> AptConfigured<'a> {
    /// The rootfs the mounts were established for.
    pub(crate) fn rootfs(&self) -> &'a Utf8Path {
        self.mounted.rootfs()
    }

    /// The mount entries the mount guard was built for.
    pub(crate) fn mounts(&self) -> &'a [MountEntry] {
        self.mounted.entries()
    }

    /// The apt task that was written, if any.
    pub(crate) fn apt(&self) -> Option<&'a AptTask> {
        self.apt
    }
}

/// Writes what `prepare.apt` declares into the mounted rootfs.
///
/// It takes [`Mounted`] because the write has to land inside the mounted window: with a
/// `prepare.mount` over `/etc`, a write before the mounts are up would go to the directory
/// underneath, and provisioning would not see it.
///
/// # Errors
///
/// Returns an error if a keyring cannot be obtained or checked, or if a change cannot be
/// made. See [`AptChanges::apply`].
pub(crate) fn configure<'a>(
    mounted: Mounted<'a>,
    apt: Option<&'a AptTask>,
    ops: &dyn RootfsOps,
    dry_run: bool,
    fetch: KeyFetcher,
) -> Result<AptConfigured<'a>> {
    if let Some(task) = apt {
        AptChanges::from(task).apply(ops, mounted.rootfs(), dry_run, fetch)?;
    }
    Ok(AptConfigured { mounted, apt })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    use camino::Utf8PathBuf;

    use super::*;
    use crate::phase::prepare::apt::{AptPin, AptSourceType};
    use crate::rootfs::LocalRootfsOps;

    const ARMORED: &str =
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQINBF\n-----END PGP PUBLIC KEY BLOCK-----\n";

    // `/etc/apt/keyrings` is deliberately absent: most tests exercise creating it.
    fn rootfs_with_apt_dirs() -> (tempfile::TempDir, Utf8PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        fs::create_dir_all(rootfs.join("etc/apt/sources.list.d")).unwrap();
        fs::create_dir_all(rootfs.join("etc/apt/preferences.d")).unwrap();
        (temp, rootfs)
    }

    fn preference(name: &str) -> AptPreference {
        AptPreference {
            name: name.to_string(),
            pins: vec![AptPin {
                packages: vec!["*".to_string()],
                pin: "release n=trixie-backports".to_string(),
                priority: 500,
                explanation: None,
            }],
        }
    }

    fn repo(name: &str, signed_by: Option<&str>) -> AptRepository {
        AptRepository {
            name: name.to_string(),
            types: vec![AptSourceType::Deb],
            uris: vec!["https://example.com/debian".to_string()],
            suites: vec!["trixie".to_string()],
            components: vec!["main".to_string()],
            architectures: vec![],
            signed_by: signed_by.map(str::to_string),
        }
    }

    fn keyring(name: &str, source: AptKeySource) -> AptKeyring {
        AptKeyring {
            name: name.to_string(),
            source,
            sha256: None,
        }
    }

    fn inline(name: &str) -> AptKeyring {
        keyring(name, AptKeySource::Content(ARMORED.into()))
    }

    fn no_network(url: &str) -> Result<Vec<u8>> {
        panic!("tests must not download {}", url)
    }

    fn serve_armored(_url: &str) -> Result<Vec<u8>> {
        Ok(ARMORED.as_bytes().to_vec())
    }

    fn task(keyrings: Vec<AptKeyring>, repositories: Vec<AptRepository>) -> AptTask {
        AptTask {
            keyrings,
            repositories,
            preferences: vec![],
            remove_sources_list: false,
        }
    }

    fn apply_with(
        rootfs: &Utf8Path,
        task: &AptTask,
        dry_run: bool,
        fetch: KeyFetcher,
    ) -> Result<()> {
        let ops = LocalRootfsOps::open(rootfs).unwrap();
        AptChanges::from(task).apply(&ops, rootfs, dry_run, fetch)
    }

    fn apply(rootfs: &Utf8Path, task: &AptTask) -> Result<()> {
        apply_with(rootfs, task, false, no_network)
    }

    fn is_empty_dir(path: &Utf8Path) -> bool {
        fs::read_dir(path).unwrap().next().is_none()
    }

    #[test]
    fn apply_writes_keyring_and_sources_readable_by_apt() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        apply(&rootfs, &task(vec![inline("k")], vec![repo("x", Some("k"))])).unwrap();

        let dir = rootfs.join("etc/apt/keyrings");
        let key = dir.join("k.asc");
        let content = fs::read_to_string(rootfs.join("etc/apt/sources.list.d/x.sources")).unwrap();
        assert!(content.contains("Signed-By: /etc/apt/keyrings/k.asc\n"), "{}", content);
        assert_eq!(fs::read_to_string(&key).unwrap(), ARMORED);
        // apt drops privileges to `_apt` to verify signatures, so both have to be readable
        // (and the directory searchable) by others.
        assert_eq!(fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o644);
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o755);
    }

    #[test]
    fn a_keyring_is_shared_by_the_repositories_that_name_it() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        apply(
            &rootfs,
            &task(vec![inline("k")], vec![repo("a", Some("k")), repo("b", Some("k"))]),
        )
        .unwrap();
        for name in ["a", "b"] {
            let path = rootfs.join(format!("etc/apt/sources.list.d/{name}.sources"));
            assert!(
                fs::read_to_string(path)
                    .unwrap()
                    .contains("Signed-By: /etc/apt/keyrings/k.asc")
            );
        }
    }

    // The keyring is the rootfs's own, so nothing is written for it and `/etc/apt/keyrings`
    // is not created.
    #[test]
    fn a_rootfs_path_is_written_as_signed_by_verbatim() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let key = "/usr/share/keyrings/debian-archive-keyring.gpg";
        apply(&rootfs, &task(vec![], vec![repo("x", Some(key))])).unwrap();

        let content = fs::read_to_string(rootfs.join("etc/apt/sources.list.d/x.sources")).unwrap();
        assert!(content.contains(&format!("Signed-By: {key}\n")), "{}", content);
        assert!(!rootfs.join("etc/apt/keyrings").exists());
    }

    #[test]
    fn an_existing_keyrings_dir_is_used() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let dir = rootfs.join("etc/apt/keyrings");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        apply(&rootfs, &task(vec![inline("k")], vec![])).unwrap();
        assert!(dir.join("k.asc").exists());
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "the rootfs's own directory is not this task's to change"
        );
    }

    #[test]
    fn a_symlinked_keyrings_dir_is_refused_and_nothing_is_written_through_it() {
        let (temp, rootfs) = rootfs_with_apt_dirs();
        let elsewhere = temp.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, rootfs.join("etc/apt/keyrings")).unwrap();

        let err = apply(&rootfs, &task(vec![inline("k")], vec![repo("x", Some("k"))])).unwrap_err();
        assert!(format!("{:#}", err).contains("symlink"), "{:#}", err);
        assert!(is_empty_dir(Utf8Path::from_path(&elsewhere).unwrap()));
        assert!(is_empty_dir(&rootfs.join("etc/apt/sources.list.d")));
    }

    // How a repository replaces a deb822 file the bootstrap wrote, such as Ubuntu's
    // `ubuntu.sources`: by name. What it replaced is gone for good.
    #[test]
    fn a_repository_replaces_a_file_of_the_same_name() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let existing = rootfs.join("etc/apt/sources.list.d/x.sources");
        fs::write(&existing, "original\n").unwrap();

        apply(&rootfs, &task(vec![], vec![repo("x", None)])).unwrap();

        let content = fs::read_to_string(&existing).unwrap();
        assert!(content.contains("Types: deb"), "{}", content);
    }

    #[test]
    fn a_binary_keyring_is_written_with_the_gpg_extension() {
        let (temp, rootfs) = rootfs_with_apt_dirs();
        let host_key = Utf8PathBuf::from_path_buf(temp.path().join("host-key.gpg")).unwrap();
        fs::write(&host_key, [0x99, 0x01, 0x0d, 0x04]).unwrap();

        apply(
            &rootfs,
            &task(vec![keyring("k", AptKeySource::Path(host_key))], vec![repo("x", Some("k"))]),
        )
        .unwrap();

        assert!(rootfs.join("etc/apt/keyrings/k.gpg").exists());
        let sources = fs::read_to_string(rootfs.join("etc/apt/sources.list.d/x.sources")).unwrap();
        assert!(sources.contains("Signed-By: /etc/apt/keyrings/k.gpg\n"), "{}", sources);
    }

    #[test]
    fn a_url_keyring_goes_through_the_fetcher() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let url = AptKeySource::Url("https://example.com/key".into());
        apply_with(&rootfs, &task(vec![keyring("k", url)], vec![]), false, serve_armored).unwrap();
        assert_eq!(fs::read_to_string(rootfs.join("etc/apt/keyrings/k.asc")).unwrap(), ARMORED);
    }

    #[test]
    fn a_keyring_failing_its_checks_fails_before_anything_is_written() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let mut bad = keyring("bad", AptKeySource::Url("https://e.com/k".into()));
        bad.sha256 = Some("0".repeat(64));
        // The first keyring and the repository are valid: nothing of them may be written
        // either, because keyrings are all checked before the first change.
        let t = task(vec![inline("good"), bad], vec![repo("x", None)]);

        let err = apply_with(&rootfs, &t, false, serve_armored).unwrap_err();
        assert!(format!("{:#}", err).contains("sha256 mismatch"), "{:#}", err);
        assert!(is_empty_dir(&rootfs.join("etc/apt/sources.list.d")));
        assert!(!rootfs.join("etc/apt/keyrings").exists());
    }

    #[test]
    fn a_downloaded_page_that_is_not_a_key_is_refused() {
        fn serve_html(_url: &str) -> Result<Vec<u8>> {
            Ok(b"<!doctype html><title>Not Found</title>".to_vec())
        }
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let url = AptKeySource::Url("https://example.com/key".into());
        let err = apply_with(&rootfs, &task(vec![keyring("k", url)], vec![]), false, serve_html)
            .unwrap_err();
        assert!(format!("{:#}", err).contains("not an OpenPGP public key"), "{:#}", err);
    }

    #[test]
    fn preferences_are_written_readable_by_apt() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let t = AptTask {
            preferences: vec![preference("p")],
            ..task(vec![], vec![])
        };
        apply(&rootfs, &t).unwrap();

        let path = rootfs.join("etc/apt/preferences.d/p.pref");
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("Pin: release n=trixie-backports\n"), "{}", content);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o644);
    }

    #[test]
    fn dry_run_writes_nothing_and_downloads_nothing() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let sources_list = rootfs.join("etc/apt/sources.list");
        fs::write(&sources_list, "deb https://e.com/debian trixie main\n").unwrap();
        let t = AptTask {
            keyrings: vec![keyring("k", AptKeySource::Url("https://e.com/k".into()))],
            repositories: vec![repo("x", Some("k"))],
            preferences: vec![preference("p")],
            remove_sources_list: true,
        };

        apply_with(&rootfs, &t, true, no_network).unwrap();

        assert!(is_empty_dir(&rootfs.join("etc/apt/sources.list.d")));
        assert!(is_empty_dir(&rootfs.join("etc/apt/preferences.d")));
        assert!(!rootfs.join("etc/apt/keyrings").exists());
        assert!(sources_list.exists());
    }

    fn removing_sources_list(repositories: Vec<AptRepository>) -> AptTask {
        AptTask {
            remove_sources_list: true,
            ..task(vec![], repositories)
        }
    }

    #[test]
    fn remove_sources_list_removes_it_after_writing_the_repositories() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let sources_list = rootfs.join("etc/apt/sources.list");
        fs::write(&sources_list, "deb https://e.com/debian trixie main\n").unwrap();

        apply(&rootfs, &removing_sources_list(vec![repo("x", None)])).unwrap();

        assert!(!sources_list.exists());
        assert!(rootfs.join("etc/apt/sources.list.d/x.sources").exists());
    }

    #[test]
    fn removing_an_absent_sources_list_is_not_an_error() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        apply(&rootfs, &removing_sources_list(vec![])).unwrap();
        assert!(!rootfs.join("etc/apt/sources.list").exists());
    }

    // A write failing before the removal leaves the bootstrap's sources where they were, so
    // the rootfs is not left with no sources at all.
    #[test]
    fn a_failed_write_leaves_the_sources_list_in_place() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let sources_list = rootfs.join("etc/apt/sources.list");
        fs::write(&sources_list, "original\n").unwrap();
        fs::remove_dir(rootfs.join("etc/apt/sources.list.d")).unwrap();

        assert!(apply(&rootfs, &removing_sources_list(vec![repo("x", None)])).is_err());
        assert_eq!(fs::read_to_string(&sources_list).unwrap(), "original\n");
    }

    #[test]
    fn a_directory_at_sources_list_is_refused() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        fs::create_dir(rootfs.join("etc/apt/sources.list")).unwrap();

        let err = apply(&rootfs, &removing_sources_list(vec![])).unwrap_err();
        assert!(format!("{:#}", err).contains("sources.list"), "{:#}", err);
        assert!(rootfs.join("etc/apt/sources.list").is_dir());
    }

    // Needs the network, so it is `#[ignore]`d; run it with `cargo test -- --ignored` to check
    // the TLS setup against a real server and the host's trust store.
    #[test]
    #[ignore]
    fn fetch_https_downloads_a_real_key() {
        let bytes = fetch_https("https://download.docker.com/linux/debian/gpg").unwrap();
        assert_eq!(KeyFormat::detect(&bytes).unwrap(), KeyFormat::Armored);
    }

    // `Mounted` borrows the guard it came from, so this runs through a real mount guard with
    // no entries, as the resolv.conf guard's tests do: `mount()` on one touches nothing and
    // cannot fail.
    #[test]
    fn configure_writes_the_task_and_names_it_in_the_evidence() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let mut mounts = crate::isolation::mount::RootfsMounts::new(
            &rootfs,
            Vec::new(),
            Arc::new(crate::executor::RealCommandExecutor::new(true)),
            None,
        );
        let ops = LocalRootfsOps::open(&rootfs).unwrap();
        let t = task(vec![], vec![repo("x", None)]);

        let configured =
            configure(mounts.mount().unwrap(), Some(&t), &ops, false, no_network).unwrap();

        assert_eq!(configured.apt(), Some(&t));
        assert_eq!(configured.rootfs(), rootfs);
        assert!(rootfs.join("etc/apt/sources.list.d/x.sources").exists());
    }
}
