//! apt_clean task implementation for the assemble phase.
//!
//! Empties apt's download cache and package lists in the final rootfs, as `apt-get
//! distclean` would. The assemble phase cannot run a program, so the removal is done
//! through [`RootfsOps::clear_dir`](crate::rootfs::RootfsOps) rather than by running
//! `apt-get` in the rootfs.

use std::borrow::Cow;

use tracing::info;

use crate::error::RsdebstrapError;
use crate::isolation::RootfsContext;
use crate::phase::{AssembleItem, PhaseItem};
use crate::rootfs::RelPath;

/// The task `assemble.apt_clean: true` runs.
///
/// Empties `/var/cache/apt` (downloaded `.deb` files, `pkgcache.bin`, `srcpkgcache.bin`)
/// and `/var/lib/apt/lists`. The `lock` files and the `archives` / `partial` directories
/// apt ships are kept; everything else, subdirectories included, is removed.
#[derive(Debug)]
pub(crate) struct AptCleanTask;

impl AptCleanTask {
    /// The directories emptied, each with the entries directly inside it that are kept.
    ///
    /// The `partial` directories and `lock` files are part of the `apt` package itself, so
    /// removing them would leave the image differing from what dpkg says is installed.
    const TARGETS: &[(&str, &[&str])] = &[
        ("/var/cache/apt/archives", &["lock", "partial"]),
        ("/var/cache/apt/archives/partial", &[]),
        ("/var/cache/apt", &["archives"]),
        ("/var/lib/apt/lists", &["lock", "partial"]),
        ("/var/lib/apt/lists/partial", &[]),
    ];

    /// Executes the assemble apt_clean task.
    ///
    /// A rootfs without apt's directories is not an error: there is nothing to remove.
    pub fn execute(&self, ctx: &dyn RootfsContext) -> anyhow::Result<()> {
        let rootfs = ctx.rootfs();
        for (dir, keep) in Self::TARGETS {
            if ctx.dry_run() {
                info!("would remove the contents of {} in {}", dir, rootfs);
                continue;
            }
            let path = RelPath::parse(dir)?;
            let keep: Vec<String> = keep.iter().map(|k| (*k).to_string()).collect();
            let removed = ctx.rootfs_ops().clear_dir(&path, &keep)?;
            info!("removed {} entries from {} in {}", removed, dir, rootfs);
        }
        Ok(())
    }
}

impl PhaseItem for AptCleanTask {
    fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed("apt_clean")
    }

    fn validate(&self) -> Result<(), RsdebstrapError> {
        Ok(())
    }
}

impl AssembleItem for AptCleanTask {
    fn execute(&self, ctx: &dyn RootfsContext) -> anyhow::Result<()> {
        AptCleanTask::execute(self, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::PlainRootfsContext;
    use camino::{Utf8Path, Utf8PathBuf};
    use std::sync::Arc;

    // The layout the `apt` package ships, populated the way a build that installed
    // something leaves it.
    fn apt_rootfs() -> (tempfile::TempDir, Utf8PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        for dir in [
            "var/cache/apt/archives/partial",
            "var/lib/apt/lists/partial",
            "var/lib/apt/lists/auxfiles",
        ] {
            std::fs::create_dir_all(rootfs.join(dir)).unwrap();
        }
        for file in [
            "var/cache/apt/pkgcache.bin",
            "var/cache/apt/srcpkgcache.bin",
            "var/cache/apt/archives/lock",
            "var/cache/apt/archives/curl_8.14.1-2_amd64.deb",
            "var/cache/apt/archives/partial/wget_1.25.0-2_amd64.deb",
            "var/lib/apt/lists/lock",
            "var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease",
            "var/lib/apt/lists/partial/deb.debian.org_debian_dists_trixie_InRelease",
            "var/lib/apt/lists/auxfiles/Packages",
        ] {
            std::fs::write(rootfs.join(file), b"x").unwrap();
        }
        (temp, rootfs)
    }

    fn entries(root: &Utf8Path) -> Vec<String> {
        let mut found = Vec::new();
        let mut stack = vec![root.to_owned()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = Utf8PathBuf::from_path_buf(entry.unwrap().path()).unwrap();
                if std::fs::symlink_metadata(&path).unwrap().is_dir() {
                    stack.push(path.clone());
                }
                found.push(path.strip_prefix(root).unwrap().to_string());
            }
        }
        found.sort();
        found
    }

    fn context(rootfs: &Utf8Path, dry_run: bool) -> PlainRootfsContext {
        let ops = crate::rootfs::LocalRootfsOps::open(rootfs).expect("fixture rootfs opens");
        PlainRootfsContext::new(rootfs, Arc::new(ops), dry_run)
    }

    #[test]
    fn execute_empties_the_cache_and_the_lists_and_their_subdirectories() {
        let (_temp, rootfs) = apt_rootfs();

        AptCleanTask.execute(&context(&rootfs, false)).unwrap();

        assert_eq!(
            entries(&rootfs),
            [
                "var",
                "var/cache",
                "var/cache/apt",
                "var/cache/apt/archives",
                "var/cache/apt/archives/lock",
                "var/cache/apt/archives/partial",
                "var/lib",
                "var/lib/apt",
                "var/lib/apt/lists",
                "var/lib/apt/lists/lock",
                "var/lib/apt/lists/partial",
            ]
        );
    }

    #[test]
    fn execute_without_apt_directories_removes_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();

        AptCleanTask.execute(&context(&rootfs, false)).unwrap();

        assert!(entries(&rootfs).is_empty());
    }

    #[test]
    fn execute_dry_run_removes_nothing() {
        let (_temp, rootfs) = apt_rootfs();
        let before = entries(&rootfs);

        AptCleanTask.execute(&context(&rootfs, true)).unwrap();

        assert_eq!(entries(&rootfs), before);
    }

    // A symlink planted in the cache is removed as a link; what it points at, outside the
    // directory being emptied, is left alone.
    #[test]
    fn execute_does_not_follow_a_symlink_in_the_cache() {
        let (_temp, rootfs) = apt_rootfs();
        std::fs::create_dir(rootfs.join("outside")).unwrap();
        std::fs::write(rootfs.join("outside/keep-me"), b"x").unwrap();
        std::os::unix::fs::symlink(
            rootfs.join("outside"),
            rootfs.join("var/cache/apt/archives/link"),
        )
        .unwrap();

        AptCleanTask.execute(&context(&rootfs, false)).unwrap();

        assert!(rootfs.join("outside/keep-me").exists());
        assert!(
            std::fs::symlink_metadata(rootfs.join("var/cache/apt/archives/link")).is_err(),
            "the link itself should be gone"
        );
    }

    #[test]
    fn execute_refuses_a_symlinked_cache_directory() {
        let (_temp, rootfs) = apt_rootfs();
        std::fs::create_dir(rootfs.join("outside")).unwrap();
        std::fs::write(rootfs.join("outside/keep-me"), b"x").unwrap();
        std::fs::remove_dir_all(rootfs.join("var/cache/apt/archives")).unwrap();
        std::os::unix::fs::symlink(rootfs.join("outside"), rootfs.join("var/cache/apt/archives"))
            .unwrap();

        let err = AptCleanTask.execute(&context(&rootfs, false)).unwrap_err();

        assert!(err.to_string().contains("symlink"), "unexpected error: {err}");
        assert!(rootfs.join("outside/keep-me").exists());
    }
}
