//! apt task implementation for the assemble phase.
//!
//! [`AssembleAptTask`] writes apt's configuration into the final rootfs where it should differ
//! from what the build used: keyrings, repositories and preferences with the same shape and
//! files as `prepare.apt`, replacing a file of the same name. It also removes the bootstrap's
//! `/etc/apt/sources.list` and empties apt's caches on request.

use std::borrow::Cow;

use camino::Utf8Path;
use schemars::JsonSchema;
use serde::Deserialize;

use super::dist_clean::DistClean;
use crate::error::RsdebstrapError;
use crate::isolation::RootfsContext;
use crate::isolation::apt_sources::{AptChanges, KeyFetcher, fetch_https};
use crate::phase::prepare::apt::{
    AptKeyring, AptPreference, AptRepository, entry_names, resolve_keyring_paths, validate_entries,
};
use crate::phase::{AssembleItem, PhaseItem};

/// apt task writing apt's configuration into the final rootfs.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssembleAptTask {
    /// Empty apt's download cache and package lists, as `apt-get distclean` would (default
    /// false). The image then needs `apt-get update` before it can install anything.
    #[serde(default)]
    pub dist_clean: bool,
    /// Remove `/etc/apt/sources.list`, where the bootstrap writes its mirrors, after the
    /// entries below are written (default false).
    #[serde(default)]
    pub remove_sources_list: bool,
    /// OpenPGP keyrings to write, as `prepare.apt.keyrings` does. A repository here uses one
    /// by naming it in `signed_by`, or names a keyring file in the rootfs by absolute path.
    #[serde(default, deserialize_with = "crate::de::null_to_default")]
    #[schemars(with = "Option<Vec<AptKeyring>>")]
    pub keyrings: Vec<AptKeyring>,
    /// APT repositories to write, each to `/etc/apt/sources.list.d/<name>.sources` in deb822
    /// format, replacing a file already there — one `prepare.apt` wrote included.
    #[serde(default, deserialize_with = "crate::de::null_to_default")]
    #[schemars(with = "Option<Vec<AptRepository>>")]
    pub repositories: Vec<AptRepository>,
    /// APT preferences to write, each to `/etc/apt/preferences.d/<name>.pref` (see
    /// apt_preferences(5)), replacing a file already there.
    #[serde(default, deserialize_with = "crate::de::null_to_default")]
    #[schemars(with = "Option<Vec<AptPreference>>")]
    pub preferences: Vec<AptPreference>,
}

impl AssembleAptTask {
    /// Resolves relative keyring paths against `base_dir` (the profile's directory).
    pub fn resolve_paths(&mut self, base_dir: &Utf8Path) {
        resolve_keyring_paths(&mut self.keyrings, base_dir);
    }

    /// Validates every entry as `prepare.apt` does, and that the task does something.
    pub fn validate(&self) -> Result<(), RsdebstrapError> {
        if !self.dist_clean
            && !self.remove_sources_list
            && self.keyrings.is_empty()
            && self.repositories.is_empty()
            && self.preferences.is_empty()
        {
            return Err(RsdebstrapError::Validation(
                "apt must declare at least one keyring, repository or preference, or set \
                dist_clean or remove_sources_list"
                    .to_string(),
            ));
        }
        validate_entries(&self.keyrings, &self.repositories, &self.preferences)
    }

    fn execute_with(&self, ctx: &dyn RootfsContext, fetch: KeyFetcher) -> anyhow::Result<()> {
        AptChanges {
            keyrings: &self.keyrings,
            repositories: &self.repositories,
            preferences: &self.preferences,
            remove_sources_list: self.remove_sources_list,
        }
        .apply(ctx.rootfs_ops(), ctx.rootfs(), ctx.dry_run(), fetch)?;
        if self.dist_clean {
            DistClean.execute(ctx)?;
        }
        Ok(())
    }
}

impl PhaseItem for AssembleAptTask {
    fn name(&self) -> Cow<'_, str> {
        let mut name =
            format!("apt:{}", entry_names(&self.keyrings, &self.repositories, &self.preferences));
        if self.remove_sources_list {
            name.push_str(",remove_sources_list");
        }
        if self.dist_clean {
            name.push_str(",dist_clean");
        }
        Cow::Owned(name)
    }

    fn validate(&self) -> Result<(), RsdebstrapError> {
        AssembleAptTask::validate(self)
    }
}

impl AssembleItem for AssembleAptTask {
    fn execute(&self, ctx: &dyn RootfsContext) -> anyhow::Result<()> {
        self.execute_with(ctx, fetch_https)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;

    use camino::Utf8PathBuf;

    use super::*;
    use crate::isolation::PlainRootfsContext;

    fn no_network(url: &str) -> anyhow::Result<Vec<u8>> {
        panic!("tests must not download {}", url)
    }

    fn parse(yaml: &str) -> AssembleAptTask {
        yaml_serde::from_str(yaml).unwrap()
    }

    // A rootfs as provisioning leaves it: the bootstrap's one-line sources.list, the build
    // mirror `prepare.apt` wrote, and package lists from `apt-get update`.
    fn provisioned_rootfs() -> (tempfile::TempDir, Utf8PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        fs::create_dir_all(rootfs.join("etc/apt/sources.list.d")).unwrap();
        fs::create_dir_all(rootfs.join("var/lib/apt/lists")).unwrap();
        fs::write(
            rootfs.join("etc/apt/sources.list"),
            "deb http://deb.debian.org/debian trixie main\n",
        )
        .unwrap();
        fs::write(
            rootfs.join("etc/apt/sources.list.d/debian.sources"),
            "URIs: https://mirror.internal/debian\n",
        )
        .unwrap();
        fs::write(rootfs.join("var/lib/apt/lists/InRelease"), b"x").unwrap();
        (temp, rootfs)
    }

    fn run(task: &AssembleAptTask, rootfs: &Utf8Path, dry_run: bool) -> anyhow::Result<()> {
        let ops = crate::rootfs::LocalRootfsOps::open(rootfs).expect("fixture rootfs opens");
        let ctx = PlainRootfsContext::new(rootfs, Arc::new(ops), dry_run);
        task.execute_with(&ctx, no_network)
    }

    // editorconfig-checker-disable
    const PUBLIC_MIRROR: &str = "\
dist_clean: true
remove_sources_list: true
repositories:
  - name: debian
    uris: [https://deb.debian.org/debian]
    suites: [trixie]
    components: [main]
";
    // editorconfig-checker-enable

    // What assemble.apt is for: provisioning installed from a build mirror, and the image
    // should point at the public one instead.
    #[test]
    fn execute_replaces_the_build_mirror_and_cleans_up() {
        let (_temp, rootfs) = provisioned_rootfs();

        run(&parse(PUBLIC_MIRROR), &rootfs, false).unwrap();

        let sources =
            fs::read_to_string(rootfs.join("etc/apt/sources.list.d/debian.sources")).unwrap();
        assert!(sources.contains("URIs: https://deb.debian.org/debian\n"), "{sources}");
        assert!(!rootfs.join("etc/apt/sources.list").exists());
        assert!(!rootfs.join("var/lib/apt/lists/InRelease").exists());
    }

    #[test]
    fn execute_dry_run_changes_nothing() {
        let (_temp, rootfs) = provisioned_rootfs();

        run(&parse(PUBLIC_MIRROR), &rootfs, true).unwrap();

        assert!(rootfs.join("etc/apt/sources.list").exists());
        assert!(rootfs.join("var/lib/apt/lists/InRelease").exists());
        assert_eq!(
            fs::read_to_string(rootfs.join("etc/apt/sources.list.d/debian.sources")).unwrap(),
            "URIs: https://mirror.internal/debian\n"
        );
    }

    #[test]
    fn execute_leaves_what_it_was_not_asked_to_touch() {
        let (_temp, rootfs) = provisioned_rootfs();

        run(&parse("dist_clean: true\n"), &rootfs, false).unwrap();

        assert!(rootfs.join("etc/apt/sources.list").exists());
        assert!(
            rootfs
                .join("etc/apt/sources.list.d/debian.sources")
                .exists()
        );
        assert!(!rootfs.join("var/lib/apt/lists/InRelease").exists());
    }

    #[test]
    fn deserialize_null_lists_mean_empty() {
        let task = parse("dist_clean: true\nkeyrings:\nrepositories:\npreferences:\n");
        assert!(task.keyrings.is_empty() && task.repositories.is_empty());
        assert!(task.validate().is_ok());
    }

    #[test]
    fn validate_rejects_a_task_that_does_nothing() {
        let err = parse("dist_clean: false\n").validate().unwrap_err();
        assert!(err.to_string().contains("at least one"), "{err}");
    }

    #[test]
    fn validate_checks_the_entries_as_prepare_does() {
        let task = parse(
            "repositories:\n  - name: x\n    uris: [https://e.com]\n    suites: [s]\n    \
            components: [main]\n    signed_by: k\n",
        );
        let err = task.validate().unwrap_err();
        assert!(err.to_string().contains("names no entry in keyrings"), "{err}");
    }

    #[test]
    fn name_lists_the_entries_and_the_flags() {
        assert_eq!(
            parse(PUBLIC_MIRROR).name(),
            "apt:keyrings[],repositories[debian],preferences[],remove_sources_list,dist_clean"
        );
    }
}
