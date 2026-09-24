//! APT keyring and repository lifecycle within a rootfs.
//!
//! [`RootfsAptSources`] is an RAII guard that writes the keyrings and repositories
//! `prepare.apt` declares, so provisioning can install from them, and afterwards removes the
//! ones not marked `keep`, putting back whatever they replaced.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use tracing::{info, warn};

use crate::config::MountEntry;
use crate::error::RsdebstrapError;
use crate::isolation::mount::Mounted;
use crate::isolation::resolv_conf::Restored;
use crate::phase::prepare::AptTask;
use crate::phase::prepare::apt::{AptKeySource, AptKeyring, KEYRINGS_DIR, KeyFormat, MAX_KEY_SIZE};
use crate::rootfs::{FileMode, RelPath, RootfsOps, TakenEntry};

/// Mode `/etc/apt/keyrings` is created with, the one apt's own package ships it with. apt
/// reads keyrings as the unprivileged `_apt` user, so the directory has to be searchable by
/// others.
const KEYRINGS_DIR_MODE: FileMode = FileMode::new(0o755);

/// Mode keyrings and `.sources` files are written with, readable by `_apt` for that reason.
const FILE_MODE: FileMode = FileMode::new(0o644);

/// Downloads a keyring given by `url`. A function pointer rather than a call to
/// [`fetch_https`] so the guard's tests can run without a network.
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

/// Evidence that the mounts are up and the apt keyrings and repositories are written.
///
/// [`RootfsResolvConf::setup`](crate::isolation::resolv_conf::RootfsResolvConf::setup)
/// requires one, so the `Prepared` it yields cannot exist unless this guard ran. Like
/// [`Mounted`], it carries the borrow of the mount guard forward and adds its own, so
/// neither guard can be torn down while it is alive, and it names what it is evidence
/// about so the pipeline can compare it against its own `prepare.apt`.
#[must_use]
#[derive(Debug)]
pub(crate) struct AptConfigured<'a> {
    rootfs: &'a Utf8Path,
    mounts: &'a [MountEntry],
    apt: Option<&'a AptTask>,
    guard: PhantomData<&'a RootfsAptSources>,
}

impl<'a> AptConfigured<'a> {
    /// The rootfs both guards were built for.
    pub(crate) fn rootfs(&self) -> &'a Utf8Path {
        self.rootfs
    }

    /// The mount entries the mount guard was built for.
    pub(crate) fn mounts(&self) -> &'a [MountEntry] {
        self.mounts
    }

    /// The apt task this guard was built for, if any.
    pub(crate) fn apt(&self) -> Option<&'a AptTask> {
        self.apt
    }
}

/// Evidence that the entries not marked `keep` have been removed again.
///
/// [`RootfsMounts::unmount_before_assembly`](crate::isolation::mount::RootfsMounts::unmount_before_assembly)
/// requires one. The removal has to land inside the mounted window for the reason
/// [`RootfsResolvConf::restore`](crate::isolation::resolv_conf::RootfsResolvConf::restore)
/// gives: a `prepare.mount` over `/etc` would otherwise take it to the directory underneath.
/// It is taken after the resolv.conf restore, so the two guards unwind in the reverse of
/// the order they were set up in.
#[must_use]
#[derive(Debug)]
pub(crate) struct AptRestored(());

impl AptRestored {
    /// For a run with no prepare guard, where nothing was ever written.
    ///
    /// The only way to obtain an `AptRestored` without removing anything, and it still
    /// requires the resolv.conf restore to have happened first.
    pub(crate) fn nothing_was_written(_restored: Restored) -> Self {
        Self(())
    }
}

/// One change this guard made, and what undoing it means.
enum Written {
    /// A file written over whatever was at `path` before, if anything.
    File {
        path: RelPath,
        original: Option<TakenEntry>,
        keep: bool,
    },
    /// A directory this guard created because none was there.
    Dir { path: RelPath, keep: bool },
}

impl Written {
    fn keep(&self) -> bool {
        match self {
            Self::File { keep, .. } | Self::Dir { keep, .. } => *keep,
        }
    }
}

/// RAII guard for the keyrings and APT repositories `prepare.apt` declares.
///
/// Setup detaches whatever is at each path it writes, holding it in memory as a
/// [`TakenEntry`] the way the resolv.conf guard does, and creates `/etc/apt/keyrings` if the
/// rootfs has none. Teardown undoes those changes for the entries not marked `keep`, and
/// forgets them for the ones that are. `Drop` retries a teardown the caller never finished.
pub(crate) struct RootfsAptSources {
    ops: Arc<dyn RootfsOps>,
    config: Option<AptTask>,
    fetch: KeyFetcher,
    /// For log lines only.
    rootfs: Utf8PathBuf,
    /// In the order they were made; undone in reverse.
    written: Vec<Written>,
    used: bool,
    dry_run: bool,
}

impl RootfsAptSources {
    /// Creates a guard over `rootfs`. If `config` is `None`, setup and teardown are no-ops.
    pub(crate) fn new(
        rootfs: &Utf8Path,
        config: Option<AptTask>,
        ops: Arc<dyn RootfsOps>,
        dry_run: bool,
        fetch: KeyFetcher,
    ) -> Self {
        Self {
            ops,
            config,
            fetch,
            rootfs: rootfs.to_owned(),
            written: Vec::new(),
            used: false,
            dry_run,
        }
    }

    /// Writes every declared keyring and repository.
    ///
    /// Every keyring is read, downloaded and checked before the first change, so a key that
    /// is missing, fails its `sha256`, or is not a public key fails setup with the rootfs
    /// untouched.
    ///
    /// # Errors
    ///
    /// Returns an error if a keyring cannot be obtained or checked, or if a change cannot be
    /// made. A failed change rolls back every one made so far, `keep` ones included, so a
    /// failed setup leaves the rootfs as it was found. If that rollback fails too, the error
    /// says so and the retry is left to `Drop`.
    pub(crate) fn setup<'a>(&'a mut self, mounted: Mounted<'a>) -> Result<AptConfigured<'a>> {
        if mounted.rootfs() != self.rootfs {
            return Err(RsdebstrapError::Isolation(format!(
                "the mounts were established for {} but this guard is over {}",
                mounted.rootfs(),
                self.rootfs
            ))
            .into());
        }
        // A second setup would detach the files the first one wrote as if they were the
        // rootfs's own, and teardown would then put the temporary ones back.
        if self.used {
            return Err(RsdebstrapError::Isolation(
                "setup() called on an already-used RootfsAptSources".to_string(),
            )
            .into());
        }
        self.used = true;

        let Some(config) = &self.config else {
            return Ok(self.evidence(mounted));
        };

        if self.dry_run {
            for keyring in &config.keyrings {
                info!("would write apt keyring '{}' to {}", keyring.name, self.rootfs);
            }
            for repo in &config.repositories {
                info!("would write apt repository {} to {}", repo.sources_path(), self.rootfs);
            }
            return Ok(self.evidence(mounted));
        }

        let mut keyring_paths = HashMap::new();
        let mut files = Vec::new();
        for keyring in &config.keyrings {
            let bytes = self
                .keyring_bytes(keyring)
                .with_context(|| format!("apt keyring '{}'", keyring.name))?;
            let path = keyring.path(KeyFormat::detect(&bytes)?);
            keyring_paths.insert(keyring.name.as_str(), path.clone());
            files.push((path, bytes, keyring.keep));
        }
        for repo in &config.repositories {
            let signed_by = match &repo.signed_by {
                Some(name) => Some(keyring_paths.get(name.as_str()).ok_or_else(|| {
                    RsdebstrapError::Validation(format!(
                        "apt repository '{}': signed_by '{}' names no entry in keyrings",
                        repo.name, name
                    ))
                })?),
                None => None,
            };
            let sources = repo.render_sources(signed_by).into_bytes();
            files.push((repo.sources_path(), sources, repo.keep));
        }
        let count = (config.keyrings.len(), config.repositories.len());
        // Kept if any keyring in it is: removing it would take a kept keyring with it.
        let keyrings_dir =
            (!config.keyrings.is_empty()).then(|| config.keyrings.iter().any(|k| k.keep));

        let applied = keyrings_dir
            .map_or(Ok(()), |keep| self.ensure_keyrings_dir(keep))
            .and_then(|()| {
                files
                    .into_iter()
                    .try_for_each(|(path, content, keep)| self.install(path, &content, keep))
            });
        if let Err(err) = applied {
            if let Err(rollback_err) = self.unwind(true) {
                return Err(err.context(format!(
                    "rolling back the apt changes already made failed too ({:#}); the \
                    originals are held in memory until cleanup retries",
                    rollback_err
                )));
            }
            return Err(err);
        }

        info!(
            "configured {} apt keyring(s) and {} repository(ies) in {}",
            count.0, count.1, self.rootfs
        );
        Ok(self.evidence(mounted))
    }

    /// Removes the entries not marked `keep`, in exchange for the token the unmount
    /// requires. It asks for [`Mounted`] again for the reason `RootfsResolvConf::restore`
    /// does.
    ///
    /// # Errors
    ///
    /// Returns an error if an entry cannot be removed or put back. `Drop` retries those.
    pub(crate) fn restore(
        &mut self,
        _restored: Restored,
        mounted: Mounted<'_>,
    ) -> Result<AptRestored> {
        if mounted.rootfs() != self.rootfs {
            return Err(RsdebstrapError::Isolation(format!(
                "the mounts still in place are for {} but this guard is over {}",
                mounted.rootfs(),
                self.rootfs
            ))
            .into());
        }
        self.teardown()?;
        Ok(AptRestored(()))
    }

    /// Removes the entries not marked `keep`, putting back what they replaced. Idempotent:
    /// an entry dealt with once is not revisited.
    pub(crate) fn teardown(&mut self) -> Result<()> {
        let had_entries = self.written.iter().any(|w| !w.keep());
        self.unwind(false)?;
        if had_entries {
            info!("removed temporary apt keyrings and repositories from {}", self.rootfs);
        }
        Ok(())
    }

    fn evidence<'a>(&'a self, mounted: Mounted<'a>) -> AptConfigured<'a> {
        AptConfigured {
            rootfs: mounted.rootfs(),
            mounts: mounted.entries(),
            apt: self.config.as_ref(),
            guard: PhantomData,
        }
    }

    /// Obtains a keyring's bytes and checks them. Reading the host file happens here rather
    /// than in `RootfsOps` for the reason the resolv.conf guard gives: the ops may be the
    /// privileged helper, and what crosses to it should be bytes, not a host path.
    fn keyring_bytes(&self, keyring: &AptKeyring) -> Result<Vec<u8>> {
        let bytes = match &keyring.source {
            AptKeySource::Path(path) => crate::phase::read_host_file(path, "apt keyring")?,
            AptKeySource::Content(content) => content.as_bytes().to_vec(),
            AptKeySource::Url(url) => {
                info!("downloading apt keyring from {}", url);
                (self.fetch)(url)?
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

    /// Creates `/etc/apt/keyrings` if the rootfs has none, recording it for removal.
    ///
    /// The directory is made by [`RootfsOps::create_dir`], which is what keeps this safe
    /// under privilege: it resolves `/etc/apt` without following anything, and never adopts
    /// a symlink at `keyrings` as the directory -- which would otherwise send every keyring
    /// written next, as root, wherever the link points.
    fn ensure_keyrings_dir(&mut self, keep: bool) -> Result<()> {
        let path = crate::config::rootfs_path(KEYRINGS_DIR);
        let created = self
            .ops
            .create_dir(&path, KEYRINGS_DIR_MODE)
            .with_context(|| format!("failed to create {}{}", self.rootfs, path))?;
        if created {
            info!("created {}{}", self.rootfs, path);
            self.written.push(Written::Dir { path, keep });
        }
        Ok(())
    }

    /// Detaches whatever is at `path` and writes `content` there.
    ///
    /// The detached entry is recorded before the write, so a failed write still leaves it
    /// where [`Self::unwind`] can put it back.
    fn install(&mut self, path: RelPath, content: &[u8], keep: bool) -> Result<()> {
        let original = self
            .ops
            .take(&path)
            .with_context(|| format!("failed to detach {}{}", self.rootfs, path))?;
        self.written.push(Written::File {
            path: path.clone(),
            original,
            keep,
        });
        self.ops
            .write_file(&path, content, FILE_MODE)
            .with_context(|| format!("failed to write {}{}", self.rootfs, path))
    }

    /// Undoes each change, newest first. Kept entries are left in place and forgotten
    /// unless `include_kept`, which a failed setup uses to leave the rootfs as it was found.
    /// Entries that fail stay recorded for the next attempt.
    fn unwind(&mut self, include_kept: bool) -> Result<()> {
        let mut first_err = None;
        let mut remaining = Vec::new();
        for entry in std::mem::take(&mut self.written).into_iter().rev() {
            if entry.keep() && !include_kept {
                continue;
            }
            let result = match &entry {
                Written::File {
                    path,
                    original: Some(original),
                    ..
                } => self.ops.put_back(path, original).map(|()| true),
                Written::File {
                    path,
                    original: None,
                    ..
                } => self.ops.remove(path).map(|()| true),
                Written::Dir { path, .. } => self.ops.remove_dir(path),
            };
            match result {
                Ok(true) => {}
                // Something provisioning put there. It is not this guard's to delete, and
                // the directory is harmless left behind, so it stays.
                Ok(false) => warn!(
                    "{}{} was created for apt keyrings but is not empty, leaving it in place",
                    self.rootfs, KEYRINGS_DIR
                ),
                Err(e) => {
                    let path = match &entry {
                        Written::File { path, .. } | Written::Dir { path, .. } => path,
                    };
                    first_err.get_or_insert_with(|| {
                        anyhow::Error::new(e)
                            .context(format!("failed to restore {}{}", self.rootfs, path))
                    });
                    remaining.push(entry);
                }
            }
        }
        remaining.reverse();
        self.written = remaining;
        first_err.map_or(Ok(()), Err)
    }
}

impl Drop for RootfsAptSources {
    fn drop(&mut self) {
        if !self.written.is_empty()
            && let Err(e) = self.teardown()
        {
            tracing::error!(
                "failed to remove temporary apt keyrings and repositories during cleanup: \
                {:#}. {} may still hold them",
                e,
                self.rootfs
            );
        }
    }
}

// Omits the detached originals and the fetcher: neither says anything about the guard's
// state, which is what a reader of this wants.
impl std::fmt::Debug for RootfsAptSources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootfsAptSources")
            .field("rootfs", &self.rootfs)
            .field("used", &self.used)
            .field("pending", &self.written.len())
            .field("dry_run", &self.dry_run)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::phase::prepare::apt::{AptRepository, AptSourceType};
    use crate::rootfs::LocalRootfsOps;

    const ARMORED: &str =
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQINBF\n-----END PGP PUBLIC KEY BLOCK-----\n";

    // `/etc/apt/keyrings` is deliberately absent: most tests exercise creating it.
    fn rootfs_with_apt_dirs() -> (tempfile::TempDir, Utf8PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        fs::create_dir_all(rootfs.join("etc/apt/sources.list.d")).unwrap();
        (temp, rootfs)
    }

    fn repo(name: &str, keep: bool, signed_by: Option<&str>) -> AptRepository {
        AptRepository {
            name: name.to_string(),
            types: vec![AptSourceType::Deb],
            uris: vec!["https://example.com/debian".to_string()],
            suites: vec!["trixie".to_string()],
            components: vec!["main".to_string()],
            architectures: vec![],
            signed_by: signed_by.map(str::to_string),
            keep,
        }
    }

    fn keyring(name: &str, keep: bool, source: AptKeySource) -> AptKeyring {
        AptKeyring {
            name: name.to_string(),
            source,
            sha256: None,
            keep,
        }
    }

    fn inline(name: &str, keep: bool) -> AptKeyring {
        keyring(name, keep, AptKeySource::Content(ARMORED.into()))
    }

    fn no_network(url: &str) -> Result<Vec<u8>> {
        panic!("tests must not download {}", url)
    }

    fn serve_armored(_url: &str) -> Result<Vec<u8>> {
        Ok(ARMORED.as_bytes().to_vec())
    }

    fn guard(
        rootfs: &Utf8Path,
        keyrings: Vec<AptKeyring>,
        repositories: Vec<AptRepository>,
    ) -> RootfsAptSources {
        guard_with(rootfs, keyrings, repositories, no_network)
    }

    fn guard_with(
        rootfs: &Utf8Path,
        keyrings: Vec<AptKeyring>,
        repositories: Vec<AptRepository>,
        fetch: KeyFetcher,
    ) -> RootfsAptSources {
        let ops = Arc::new(LocalRootfsOps::open(rootfs).unwrap());
        let config = AptTask {
            keyrings,
            repositories,
        };
        RootfsAptSources::new(rootfs, Some(config), ops, false, fetch)
    }

    // `Mounted` borrows the guard it came from, so no helper can hand one back. This runs
    // setup through a real mount guard with no entries instead, as the resolv.conf guard's
    // tests do: `mount()` on one touches nothing and cannot fail.
    fn setup_guard(g: &mut RootfsAptSources) -> Result<()> {
        let rootfs = g.rootfs.clone();
        let mut mounts = crate::isolation::mount::RootfsMounts::new(
            &rootfs,
            Vec::new(),
            Arc::new(crate::executor::RealCommandExecutor::new(true)),
            None,
        );
        let mounted = mounts.mount().expect("an empty mount guard mounts nothing");
        let _configured = g.setup(mounted)?;
        Ok(())
    }

    fn is_empty_dir(path: &Utf8Path) -> bool {
        fs::read_dir(path).unwrap().next().is_none()
    }

    #[test]
    fn setup_writes_keyring_and_sources_and_teardown_removes_both_and_the_dir() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let mut g = guard(&rootfs, vec![inline("k", false)], vec![repo("x", false, Some("k"))]);
        setup_guard(&mut g).unwrap();

        let dir = rootfs.join("etc/apt/keyrings");
        let key = dir.join("k.asc");
        let sources = rootfs.join("etc/apt/sources.list.d/x.sources");
        let content = fs::read_to_string(&sources).unwrap();
        assert!(content.contains("Signed-By: /etc/apt/keyrings/k.asc\n"), "{}", content);
        assert_eq!(fs::read_to_string(&key).unwrap(), ARMORED);
        // apt drops privileges to `_apt` to verify signatures, so both have to be readable
        // (and the directory searchable) by others.
        assert_eq!(fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o644);
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o755);

        g.teardown().unwrap();
        assert!(!sources.exists());
        assert!(!dir.exists(), "a directory this guard created goes with its keyrings");
    }

    #[test]
    fn a_keyring_is_shared_by_the_repositories_that_name_it() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let mut g = guard(
            &rootfs,
            vec![inline("k", false)],
            vec![repo("a", false, Some("k")), repo("b", false, Some("k"))],
        );
        setup_guard(&mut g).unwrap();
        for name in ["a", "b"] {
            let path = rootfs.join(format!("etc/apt/sources.list.d/{name}.sources"));
            assert!(
                fs::read_to_string(path)
                    .unwrap()
                    .contains("Signed-By: /etc/apt/keyrings/k.asc")
            );
        }
    }

    #[test]
    fn an_existing_keyrings_dir_is_used_and_left_in_place() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let dir = rootfs.join("etc/apt/keyrings");
        fs::create_dir(&dir).unwrap();
        let mut g = guard(&rootfs, vec![inline("k", false)], vec![]);
        setup_guard(&mut g).unwrap();
        g.teardown().unwrap();
        assert!(dir.is_dir(), "the rootfs's own directory is not this guard's to remove");
        assert!(is_empty_dir(&dir));
    }

    #[test]
    fn a_symlinked_keyrings_dir_is_refused_and_nothing_is_written_through_it() {
        let (temp, rootfs) = rootfs_with_apt_dirs();
        let elsewhere = temp.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, rootfs.join("etc/apt/keyrings")).unwrap();

        let mut g = guard(&rootfs, vec![inline("k", false)], vec![repo("x", false, Some("k"))]);
        let err = setup_guard(&mut g).unwrap_err();
        assert!(format!("{:#}", err).contains("symlink"), "{:#}", err);
        assert!(is_empty_dir(Utf8Path::from_path(&elsewhere).unwrap()));
        assert!(is_empty_dir(&rootfs.join("etc/apt/sources.list.d")));
    }

    #[test]
    fn a_kept_keyring_keeps_the_dir_it_created() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let mut g = guard(&rootfs, vec![inline("kept", true), inline("temp", false)], vec![]);
        setup_guard(&mut g).unwrap();
        g.teardown().unwrap();
        assert!(rootfs.join("etc/apt/keyrings/kept.asc").exists());
        assert!(!rootfs.join("etc/apt/keyrings/temp.asc").exists());
    }

    #[test]
    fn a_created_dir_that_provisioning_filled_is_left_in_place() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let mut g = guard(&rootfs, vec![inline("k", false)], vec![]);
        setup_guard(&mut g).unwrap();
        let theirs = rootfs.join("etc/apt/keyrings/theirs.gpg");
        fs::write(&theirs, b"x").unwrap();

        g.teardown().unwrap();
        assert!(theirs.exists());
        assert!(g.written.is_empty(), "a directory left in place is not retried by Drop");
    }

    #[test]
    fn teardown_leaves_kept_repositories_in_place() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let mut g =
            guard(&rootfs, vec![], vec![repo("kept", true, None), repo("temp", false, None)]);
        setup_guard(&mut g).unwrap();
        g.teardown().unwrap();

        assert!(rootfs.join("etc/apt/sources.list.d/kept.sources").exists());
        assert!(!rootfs.join("etc/apt/sources.list.d/temp.sources").exists());
        assert!(!rootfs.join("etc/apt/keyrings").exists(), "no keyrings, no directory");
    }

    #[test]
    fn teardown_puts_back_an_entry_the_repository_replaced() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let existing = rootfs.join("etc/apt/sources.list.d/x.sources");
        fs::write(&existing, "original\n").unwrap();

        let mut g = guard(&rootfs, vec![], vec![repo("x", false, None)]);
        setup_guard(&mut g).unwrap();
        assert!(
            fs::read_to_string(&existing)
                .unwrap()
                .contains("Types: deb")
        );

        g.teardown().unwrap();
        assert_eq!(fs::read_to_string(&existing).unwrap(), "original\n");
    }

    #[test]
    fn drop_removes_what_teardown_was_never_asked_to() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let mut g = guard(&rootfs, vec![inline("k", false)], vec![repo("x", false, Some("k"))]);
        setup_guard(&mut g).unwrap();
        drop(g);
        assert!(!rootfs.join("etc/apt/sources.list.d/x.sources").exists());
        assert!(!rootfs.join("etc/apt/keyrings").exists());
    }

    #[test]
    fn a_binary_keyring_is_written_with_the_gpg_extension() {
        let (temp, rootfs) = rootfs_with_apt_dirs();
        let host_key = Utf8PathBuf::from_path_buf(temp.path().join("host-key.gpg")).unwrap();
        fs::write(&host_key, [0x99, 0x01, 0x0d, 0x04]).unwrap();

        let mut g = guard(
            &rootfs,
            vec![keyring("k", false, AptKeySource::Path(host_key))],
            vec![repo("x", false, Some("k"))],
        );
        setup_guard(&mut g).unwrap();

        assert!(rootfs.join("etc/apt/keyrings/k.gpg").exists());
        let sources = fs::read_to_string(rootfs.join("etc/apt/sources.list.d/x.sources")).unwrap();
        assert!(sources.contains("Signed-By: /etc/apt/keyrings/k.gpg\n"), "{}", sources);
    }

    #[test]
    fn a_url_keyring_goes_through_the_fetcher() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let url = AptKeySource::Url("https://example.com/key".into());
        let mut g = guard_with(&rootfs, vec![keyring("k", false, url)], vec![], serve_armored);
        setup_guard(&mut g).unwrap();
        assert_eq!(fs::read_to_string(rootfs.join("etc/apt/keyrings/k.asc")).unwrap(), ARMORED);
    }

    #[test]
    fn a_keyring_failing_its_checks_fails_setup_before_anything_is_written() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let mut bad = keyring("bad", false, AptKeySource::Url("https://e.com/k".into()));
        bad.sha256 = Some("0".repeat(64));
        // The first keyring and the repository are valid: nothing of them may be written
        // either, because keyrings are all checked before the first change.
        let mut g = guard_with(
            &rootfs,
            vec![inline("good", true), bad],
            vec![repo("x", true, None)],
            serve_armored,
        );

        let err = setup_guard(&mut g).unwrap_err();
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
        let mut g = guard_with(&rootfs, vec![keyring("k", false, url)], vec![], serve_html);
        let err = setup_guard(&mut g).unwrap_err();
        assert!(format!("{:#}", err).contains("not an OpenPGP public key"), "{:#}", err);
    }

    #[test]
    fn a_failed_write_rolls_back_kept_entries_and_the_created_dir_too() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        // No sources.list.d: the repository's write fails after the keyring directory was
        // created and the keyring written into it.
        fs::remove_dir(rootfs.join("etc/apt/sources.list.d")).unwrap();
        let mut g = guard(&rootfs, vec![inline("k", true)], vec![repo("x", true, Some("k"))]);

        assert!(setup_guard(&mut g).is_err());
        assert!(!rootfs.join("etc/apt/keyrings").exists());
        assert!(g.written.is_empty(), "a completed rollback leaves nothing for Drop");
    }

    #[test]
    fn setup_refuses_a_second_run() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let mut g = guard(&rootfs, vec![], vec![repo("x", false, None)]);
        setup_guard(&mut g).unwrap();
        let err = setup_guard(&mut g).unwrap_err();
        assert!(err.to_string().contains("already-used"), "{}", err);
    }

    #[test]
    fn dry_run_writes_nothing_and_downloads_nothing() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let ops = Arc::new(LocalRootfsOps::open(&rootfs).unwrap());
        let config = AptTask {
            keyrings: vec![keyring(
                "k",
                false,
                AptKeySource::Url("https://e.com/k".into()),
            )],
            repositories: vec![repo("x", false, Some("k"))],
        };
        let mut g = RootfsAptSources::new(&rootfs, Some(config), ops, true, no_network);
        setup_guard(&mut g).unwrap();
        assert!(is_empty_dir(&rootfs.join("etc/apt/sources.list.d")));
        assert!(!rootfs.join("etc/apt/keyrings").exists());
    }

    // Needs the network, so it is `#[ignore]`d; run it with `cargo test -- --ignored` to check
    // the TLS setup against a real server and the host's trust store.
    #[test]
    #[ignore]
    fn fetch_https_downloads_a_real_key() {
        let bytes = fetch_https("https://download.docker.com/linux/debian/gpg").unwrap();
        assert_eq!(KeyFormat::detect(&bytes).unwrap(), KeyFormat::Armored);
    }

    #[test]
    fn a_guard_without_config_touches_nothing() {
        let (_temp, rootfs) = rootfs_with_apt_dirs();
        let ops = Arc::new(LocalRootfsOps::open(&rootfs).unwrap());
        let mut g = RootfsAptSources::new(&rootfs, None, ops, false, no_network);
        setup_guard(&mut g).unwrap();
        g.teardown().unwrap();
        assert!(is_empty_dir(&rootfs.join("etc/apt/sources.list.d")));
    }
}
