//! Filesystem mount management for rootfs isolation.
//!
//! This module provides [`RootfsMounts`], an RAII guard that manages filesystem
//! mounts within a rootfs directory. Mounts are set up in order and torn down
//! in reverse order, with guaranteed cleanup via `Drop`.
//!
//! Mount point directories are created using `openat`/`mkdirat` with `O_NOFOLLOW`
//! to prevent TOCTOU races between symlink validation and directory creation.

use std::marker::PhantomData;
use std::os::fd::OwnedFd;
use std::sync::Arc;

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use rustix::fs::{self as rfs, Mode, OFlags};
use tracing::info;

use crate::config::MountEntry;
use crate::error::RsdebstrapError;
use crate::executor::CommandExecutor;
use crate::isolation::resolv_conf::Restored;
use crate::privilege::PrivilegeMethod;
use crate::rootfs::RelPath;

/// Evidence that the pipeline's mounts are in place.
///
/// The front of the same chain [`Unmounted`] ends: provisioning happens with the mounts a
/// profile's `prepare.mount` declares, so the guard that establishes them hands out the
/// evidence rather than leaving the ordering to whoever wired the run up. Consumed by
/// [`RootfsResolvConf::setup`](crate::isolation::resolv_conf::RootfsResolvConf::setup),
/// which is what puts the mounts before the temporary resolv.conf it writes into them.
///
/// It borrows the guard it came from rather than standing for it. A token that did not
/// would say only that *some* mounts were established once: `Drop` releases them whatever
/// the caller does, so the guard could be gone by the time the token is presented.
/// Borrowing means the guard cannot be touched or dropped while the evidence is alive, so
/// "the mounts are in place" describes now rather than then.
///
/// The borrow cannot reach every point that needs it, though: it would still be alive at
/// the unmount that has to follow the restore, and `&mut self` cannot be taken while it is.
/// [`RootfsMounts::still_mounted`] is how the same claim is made at a point a borrow cannot
/// reach.
///
/// It also names what it is evidence *about* -- the rootfs and the entries the guard was
/// built for. A token is otherwise interchangeable between guards, so one from an empty
/// guard over an unrelated directory would satisfy a pipeline that declares real mounts;
/// [`Pipeline::run_prepare_and_provision`](crate::pipeline::Pipeline::run_prepare_and_provision)
/// compares these against what it is about to provision.
#[must_use]
#[derive(Debug)]
pub(crate) struct Mounted<'a> {
    rootfs: &'a Utf8Path,
    entries: &'a [MountEntry],
    guard: PhantomData<&'a RootfsMounts>,
}

impl<'a> Mounted<'a> {
    /// The rootfs the guard that produced this was built for.
    pub(crate) fn rootfs(&self) -> &'a Utf8Path {
        self.rootfs
    }

    /// The mount entries that guard was built for.
    pub(crate) fn entries(&self) -> &'a [MountEntry] {
        self.entries
    }
}

/// Evidence that the pipeline's mounts have been released.
///
/// [`Pipeline::run_assemble`](crate::pipeline::Pipeline::run_assemble) requires
/// one. Assemble writes the rootfs's final state — the state the image is built
/// from — so it must see the rootfs the way the image will: without `/proc`,
/// `/sys` and `/dev` bound over it.
#[must_use]
#[derive(Debug)]
pub(crate) struct Unmounted(());

impl Unmounted {
    /// For a run with no mount guard, where nothing was ever mounted.
    ///
    /// The only way to obtain an `Unmounted` without unmounting anything, and it
    /// still requires the resolv.conf restore to have happened first.
    pub(crate) fn nothing_was_mounted(_restored: Restored) -> Self {
        Self(())
    }
}

/// Opens a directory without following symlinks.
///
/// Returns `ELOOP` if the path is a symlink, `ENOTDIR` if it's not a directory.
fn open_dir_nofollow(dirfd: &OwnedFd, path: &str) -> rustix::io::Result<OwnedFd> {
    rfs::openat(
        dirfd,
        path,
        OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// The mode a mount point this code creates is left with, since it outlives the mount.
const MOUNT_POINT_MODE: Mode = Mode::RWXU
    .union(Mode::RGRP)
    .union(Mode::XGRP)
    .union(Mode::ROTH)
    .union(Mode::XOTH);

/// Maps an `openat`/`mkdirat` error to a typed `RsdebstrapError`.
fn map_openat_error(err: rustix::io::Errno, path: &Utf8Path, label: &str) -> anyhow::Error {
    match err {
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => RsdebstrapError::Isolation(format!(
            "symlink detected at {} while creating {}; \
                this could allow mount point redirection outside the rootfs",
            path, label,
        ))
        .into(),
        _ => {
            let io_err = std::io::Error::from(err);
            RsdebstrapError::io(format!("failed to create mount point component: {}", path), io_err)
                .into()
        }
    }
}

/// Creates mount point directories within rootfs using `openat`/`mkdirat` with `O_NOFOLLOW`.
///
/// This function atomically validates that no path component is a symlink and creates
/// directories as needed, preventing TOCTOU races between symlink checks and `create_dir_all`.
///
/// The rootfs itself is walked a component at a time by [`crate::rootfs::open_anchor`]: a
/// single `openat` of the whole path applies `O_NOFOLLOW` to the final component only, so an
/// intermediate directory swapped for a symlink would be followed and every `mkdirat` below
/// would be anchored wherever it points.
///
/// Returns the verified absolute path for use in mount/umount commands.
pub(crate) fn safe_create_mount_point(rootfs: &Utf8Path, target: &RelPath) -> Result<Utf8PathBuf> {
    let mut current_fd = crate::rootfs::open_anchor(rootfs)?;
    let mut current_path = rootfs.to_path_buf();

    for name in target.components() {
        let name = name.as_str();
        current_path.push(name);

        match open_dir_nofollow(&current_fd, name) {
            Ok(fd) => {
                current_fd = fd;
            }
            Err(rustix::io::Errno::NOENT) => {
                let created = match rfs::mkdirat(&current_fd, name, MOUNT_POINT_MODE) {
                    Ok(()) => true,
                    Err(rustix::io::Errno::EXIST) => {
                        // Race: another process created it between our check and create.
                        // Re-open it (still with O_NOFOLLOW for safety).
                        false
                    }
                    Err(e) => return Err(map_openat_error(e, &current_path, "mount point")),
                };
                let fd = open_dir_nofollow(&current_fd, name)
                    .map_err(|e| map_openat_error(e, &current_path, "mount point"))?;
                // `mkdirat`'s mode argument is masked by the process umask, so the mode has
                // to be set on the descriptor to land exactly. A mount point survives the
                // `umount` and ships in the image, so a directory the build's umask made
                // 0700 is one the built system's users cannot traverse. Only for the one
                // this call created: an existing directory's mode is the rootfs's business.
                if created {
                    rfs::fchmod(&fd, MOUNT_POINT_MODE)
                        .map_err(|e| map_openat_error(e, &current_path, "mount point"))?;
                }
                current_fd = fd;
            }
            Err(e) => {
                return Err(map_openat_error(e, &current_path, "mount point"));
            }
        }
    }

    Ok(current_path)
}

/// RAII guard for filesystem mounts within a rootfs.
///
/// Mounts are established in order and torn down in reverse order.
/// The `Drop` implementation ensures cleanup even on error paths.
///
/// Mount point directories are created atomically using `openat`/`mkdirat`
/// with `O_NOFOLLOW` to prevent TOCTOU races. Verified absolute paths are
/// stored and reused for `umount` commands, avoiding re-traversal of
/// potentially-tampered paths.
pub(crate) struct RootfsMounts {
    rootfs: Utf8PathBuf,
    entries: Vec<MountEntry>,
    /// Verified absolute paths for mounted entries (`Some` = mounted, `None` = not mounted).
    mounted_paths: Vec<Option<Utf8PathBuf>>,
    executor: Arc<dyn CommandExecutor>,
    privilege: Option<PrivilegeMethod>,
    dry_run: bool,
    /// Set once `mount` has established every entry. Distinct from "no entry is missing":
    /// a guard that has not been mounted yet has none missing either, and a guard whose
    /// `mount` failed part-way has had its cleanup roll the successful ones back.
    mounted: bool,
    torn_down: bool,
}

impl RootfsMounts {
    /// Creates a new `RootfsMounts` instance.
    ///
    /// No mounts are performed until [`mount()`](Self::mount) is called.
    /// Takes no `dry_run` of its own: the executor already answers that, and a mount
    /// guard that believed otherwise would either skip the `umount` for mounts that
    /// really happened or issue one for mounts that never did.
    pub(crate) fn new(
        rootfs: &Utf8Path,
        entries: Vec<MountEntry>,
        executor: Arc<dyn CommandExecutor>,
        privilege: Option<PrivilegeMethod>,
    ) -> Self {
        let mounted_paths = vec![None; entries.len()];
        let dry_run = executor.dry_run();
        Self {
            rootfs: rootfs.to_owned(),
            entries,
            mounted_paths,
            executor,
            privilege,
            dry_run,
            mounted: false,
            torn_down: false,
        }
    }

    /// Returns the number of currently mounted entries.
    fn mounted_count(&self) -> usize {
        self.mounted_paths.iter().filter(|p| p.is_some()).count()
    }

    /// Mounts all entries in order.
    ///
    /// Creates mount point directories as needed using `openat`/`mkdirat` with
    /// `O_NOFOLLOW` (skipped in dry-run mode). Verified absolute paths are stored
    /// and reused for `umount` commands.
    /// On failure, automatically unmounts any entries that were successfully mounted.
    ///
    /// Yields [`Mounted`], which the prepare guard downstream requires: a run cannot reach
    /// provisioning without having come through here, whether or not it had any entries to
    /// mount.
    pub(crate) fn mount(&mut self) -> Result<Mounted<'_>> {
        if self.torn_down || self.mounted_paths.iter().any(|p| p.is_some()) {
            return Err(RsdebstrapError::Isolation(
                "mount() called on already-used RootfsMounts".to_string(),
            )
            .into());
        }

        if self.entries.is_empty() {
            self.mounted = true;
            return Ok(self.evidence());
        }

        info!("mounting {} filesystem(s) in rootfs", self.entries.len());

        for (i, entry) in self.entries.iter().enumerate() {
            let abs_target = if self.dry_run {
                // Dry-run must not touch the filesystem.
                entry.target.to_host_path(&self.rootfs)
            } else {
                match safe_create_mount_point(&self.rootfs, &entry.target) {
                    Ok(path) => path,
                    Err(e) => return Err(self.cleanup_after_error(e)),
                }
            };

            info!("mounting {} on {}", entry.source, entry.target);
            let spec = entry.build_mount_spec_with_path(&abs_target, self.privilege);
            match self.executor.execute(&spec) {
                Ok(result) if result.success() => {
                    self.mounted_paths[i] = Some(abs_target);
                }
                Ok(result) => {
                    let status = result
                        .status
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    return Err(
                        self.cleanup_after_error(RsdebstrapError::execution(&spec, status).into())
                    );
                }
                Err(e) => {
                    return Err(self.cleanup_after_error(e));
                }
            }
        }

        self.mounted = true;
        Ok(self.evidence())
    }

    /// Unmounts previously mounted entries and returns the original error.
    fn cleanup_after_error(&mut self, error: anyhow::Error) -> anyhow::Error {
        if let Err(unmount_err) = self.unmount_internal() {
            tracing::error!("failed to unmount filesystems during cleanup: {}", unmount_err);
        }
        error
    }

    /// Unmounts all mounted entries in reverse order.
    ///
    /// This method is idempotent after a successful unmount. If unmount fails,
    /// subsequent calls will re-attempt only the entries that remain mounted.
    /// Errors from individual unmounts are collected and reported together
    /// after all entries have been attempted.
    ///
    /// Not public. Releasing the mounts before the resolv.conf restore is a real error --
    /// with a `prepare.mount` over `/etc`, setup replaced the entry on the mounted
    /// filesystem and the restore would land on the directory underneath it -- and there is
    /// no way to state "not yet" in a type here: evidence that borrows this guard cannot be
    /// handed back to a method that takes `&mut self`. So the ordered release is the only
    /// one callers outside the crate have, and it is
    /// [`unmount_before_assembly`](Self::unmount_before_assembly), which demands the
    /// restore's own token. Error paths inside the crate still need the unordered one.
    pub(crate) fn unmount(&mut self) -> Result<()> {
        if self.torn_down {
            return Ok(());
        }
        let result = self.unmount_internal();
        if result.is_ok() {
            self.torn_down = true;
        }
        result
    }

    /// Re-presents [`Mounted`] for a guard whose mounts are still in place.
    ///
    /// [`RootfsResolvConf::restore`](crate::isolation::resolv_conf::RootfsResolvConf::restore)
    /// asks for one, which is what keeps the mounts up across the restore. A borrow taken at
    /// [`mount`](Self::mount) and carried through provisioning could not do that job: it
    /// would still be alive at the unmount that has to follow, and `&mut self` cannot be
    /// taken while it is. Asking again at the point it matters can, and it catches the case
    /// a borrow never could -- a guard that was dropped has no `&self` left to ask.
    ///
    /// # Errors
    ///
    /// Returns an error if this guard has not mounted yet -- a fresh guard has nothing
    /// missing, and one whose `mount` failed part-way has had the successful entries rolled
    /// back, so neither state can be told from the entry list -- or has already unmounted.
    pub(crate) fn still_mounted(&self) -> Result<Mounted<'_>> {
        if !self.mounted {
            return Err(RsdebstrapError::Isolation(
                "the rootfs mounts have not been established".to_string(),
            )
            .into());
        }
        if self.torn_down {
            return Err(RsdebstrapError::Isolation(
                "the rootfs mounts have already been released".to_string(),
            )
            .into());
        }
        Ok(self.evidence())
    }

    /// The token for this guard, with no claim about its state. Both producers check that
    /// first; this is only what they hand back.
    fn evidence(&self) -> Mounted<'_> {
        Mounted {
            rootfs: &self.rootfs,
            entries: &self.entries,
            guard: PhantomData,
        }
    }

    /// Unmounts everything in exchange for the token the assemble phase requires.
    ///
    /// Taking [`Restored`] and yielding [`Unmounted`] is what places this between
    /// the resolv.conf restore and assembly: assembly cannot be called without the
    /// token, and the token cannot exist before the mounts are gone. A run that
    /// fails to unmount therefore never assembles, because the rootfs is not in
    /// the state assembly is defined against.
    pub(crate) fn unmount_before_assembly(&mut self, _restored: Restored) -> Result<Unmounted> {
        self.unmount()?;
        Ok(Unmounted(()))
    }

    /// Shared unmount logic called by both `unmount()` and `mount()` (for cleanup
    /// on mount failure). Uses the stored verified absolute paths from `mount()`,
    /// avoiding re-traversal of potentially-tampered paths. Tracks per-entry state
    /// so that retries only attempt entries that are still mounted.
    fn unmount_internal(&mut self) -> Result<()> {
        let count = self.mounted_count();
        if count == 0 {
            return Ok(());
        }

        info!("unmounting {} filesystem(s) from rootfs", count);

        let mut errors = Vec::new();

        for i in (0..self.entries.len()).rev() {
            let Some(abs_target) = &self.mounted_paths[i] else {
                continue;
            };
            let entry = &self.entries[i];
            info!("unmounting {}", entry.target);
            let spec = entry.build_umount_spec_with_path(abs_target, self.privilege);
            match self.executor.execute(&spec) {
                Ok(result) if result.success() => {
                    self.mounted_paths[i] = None;
                }
                Ok(result) => {
                    let status = result
                        .status
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    errors.push(format!("umount {} failed: {}", abs_target, status));
                }
                Err(e) => {
                    errors.push(format!("umount {} failed: {}", abs_target, e));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(RsdebstrapError::Isolation(format!(
                "failed to unmount {} filesystem(s): {}",
                errors.len(),
                errors.join("; ")
            ))
            .into())
        }
    }
}

impl Drop for RootfsMounts {
    fn drop(&mut self) {
        if !self.torn_down
            && self.mounted_paths.iter().any(|p| p.is_some())
            && let Err(e) = self.unmount()
        {
            tracing::error!(
                "failed to unmount {} filesystem(s) during cleanup: {}. \
                Manual cleanup may be required: findmnt | grep {}",
                self.mounted_count(),
                e,
                self.rootfs
            );
        }
    }
}

// Reports the guard's own state. The executor behind it and the full mount table are
// collaborators, not state a reader of this guard is asking about.
impl std::fmt::Debug for RootfsMounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootfsMounts")
            .field("rootfs", &self.rootfs)
            .field("mounted", &self.mounted_count())
            .field("of", &self.entries.len())
            .field("dry_run", &self.dry_run)
            .field("torn_down", &self.torn_down)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::{CommandSpec, ExecutionResult};
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::sync::Mutex;

    struct MockMountExecutor {
        calls: Mutex<Vec<Vec<String>>>,
        // What this executor answers for the run; the guard derives its own behaviour
        // from it rather than being told separately.
        dry_run: bool,
        // Privilege recorded per call, positionally aligned with `calls`.
        privileges: Mutex<Vec<Option<PrivilegeMethod>>>,
        // Call index that returns non-zero exit status.
        fail_on_call: Option<usize>,
        // Call indices that return non-zero exit status (for umount failures).
        fail_umount_on_calls: Vec<usize>,
        // Call index that returns `Err(anyhow!(...))`.
        return_err_on_call: Option<usize>,
    }

    impl MockMountExecutor {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                dry_run: false,
                privileges: Mutex::new(Vec::new()),
                fail_on_call: None,
                fail_umount_on_calls: vec![],
                return_err_on_call: None,
            }
        }

        fn dry_run() -> Self {
            Self {
                dry_run: true,
                ..Self::new()
            }
        }

        fn failing_on(call_index: usize) -> Self {
            Self {
                fail_on_call: Some(call_index),
                ..Self::new()
            }
        }

        fn failing_umount_on(call_indices: Vec<usize>) -> Self {
            Self {
                fail_umount_on_calls: call_indices,
                ..Self::new()
            }
        }

        fn returning_err_on(call_index: usize) -> Self {
            Self {
                return_err_on_call: Some(call_index),
                ..Self::new()
            }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }

        fn privileges(&self) -> Vec<Option<PrivilegeMethod>> {
            self.privileges.lock().unwrap().clone()
        }
    }

    impl CommandExecutor for MockMountExecutor {
        fn dry_run(&self) -> bool {
            self.dry_run
        }

        fn execute(&self, spec: &CommandSpec) -> Result<ExecutionResult> {
            let mut calls = self.calls.lock().unwrap();
            let index = calls.len();
            let mut args = vec![spec.command().to_string()];
            args.extend(spec.args().iter().cloned());
            calls.push(args);
            self.privileges.lock().unwrap().push(spec.privilege());
            drop(calls);

            if self.return_err_on_call == Some(index) {
                return Err(anyhow::anyhow!("executor error on call {}", index));
            }

            if self.fail_on_call == Some(index) || self.fail_umount_on_calls.contains(&index) {
                Ok(ExecutionResult {
                    status: Some(ExitStatus::from_raw(1 << 8)),
                })
            } else {
                Ok(ExecutionResult {
                    status: Some(ExitStatus::from_raw(0)),
                })
            }
        }
    }

    fn test_entries() -> Vec<MountEntry> {
        vec![
            MountEntry {
                source: "proc".to_string(),
                target: crate::config::rootfs_path("/proc"),
                options: vec![],
            },
            MountEntry {
                source: "sysfs".to_string(),
                target: crate::config::rootfs_path("/sys"),
                options: vec![],
            },
        ]
    }

    #[test]
    fn mount_and_unmount_in_order() {
        let executor = Arc::new(MockMountExecutor::new());
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None);
        let _ = mounts.mount().unwrap();
        mounts.unmount().unwrap();

        let calls = executor.calls();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0][0], "mount");
        assert_eq!(calls[1][0], "mount");
        assert_eq!(calls[2][0], "umount");
        assert_eq!(calls[3][0], "umount");

        // Unmounts should be in reverse order
        assert!(calls[2][1].contains("sys"));
        assert!(calls[3][1].contains("proc"));
    }

    #[test]
    fn empty_entries_is_noop() {
        let executor = Arc::new(MockMountExecutor::new());
        let mut mounts =
            RootfsMounts::new(Utf8Path::new("/tmp/rootfs"), vec![], executor.clone(), None);
        assert!(mounts.entries.is_empty());
        let _ = mounts.mount().unwrap();
        mounts.unmount().unwrap();
        assert_eq!(executor.calls().len(), 0);
    }

    #[test]
    fn mount_failure_triggers_partial_unmount() {
        let executor = Arc::new(MockMountExecutor::failing_on(1));
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None);
        let err = mounts.mount().unwrap_err();
        assert!(err.to_string().contains("command execution failed"));

        let calls = executor.calls();
        // mount proc (success), mount sys (fail), umount proc
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0][0], "mount");
        assert_eq!(calls[1][0], "mount");
        assert_eq!(calls[2][0], "umount");
    }

    #[test]
    fn drop_triggers_unmount() {
        let executor = Arc::new(MockMountExecutor::new());
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        {
            let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None);
            let _ = mounts.mount().unwrap();
            // Drop without calling unmount()
        }

        let calls = executor.calls();
        assert_eq!(calls.len(), 4); // 2 mounts + 2 umounts
    }

    #[test]
    fn dry_run_skips_mkdir() {
        let executor = Arc::new(MockMountExecutor::dry_run());
        let mut mounts = RootfsMounts::new(
            Utf8Path::new("/nonexistent/rootfs"),
            test_entries(),
            executor.clone(),
            None,
        );
        let _ = mounts.mount().unwrap();
        mounts.unmount().unwrap();

        let calls = executor.calls();
        assert_eq!(calls.len(), 4);
    }

    #[test]
    fn unmount_is_idempotent() {
        let executor = Arc::new(MockMountExecutor::new());
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None);
        let _ = mounts.mount().unwrap();
        mounts.unmount().unwrap();
        mounts.unmount().unwrap();

        let calls = executor.calls();
        assert_eq!(calls.len(), 4); // Still 2 mounts + 2 umounts
    }

    #[test]
    fn mount_with_privilege() {
        let executor = Arc::new(MockMountExecutor::new());
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let entries = vec![MountEntry {
            source: "proc".to_string(),
            target: crate::config::rootfs_path("/proc"),
            options: vec![],
        }];

        let mut mounts =
            RootfsMounts::new(&rootfs, entries, executor.clone(), Some(PrivilegeMethod::Sudo));
        let _ = mounts.mount().unwrap();
        mounts.unmount().unwrap();

        // Both the mount and the matching umount must carry the escalation:
        // a rootfs mounted with sudo cannot be torn down without it.
        assert_eq!(executor.calls().len(), 2);
        assert_eq!(
            executor.privileges(),
            vec![Some(PrivilegeMethod::Sudo), Some(PrivilegeMethod::Sudo)],
        );
    }

    #[test]
    fn mount_without_privilege_leaves_commands_unescalated() {
        let executor = Arc::new(MockMountExecutor::new());
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let entries = vec![MountEntry {
            source: "proc".to_string(),
            target: crate::config::rootfs_path("/proc"),
            options: vec![],
        }];

        let mut mounts = RootfsMounts::new(&rootfs, entries, executor.clone(), None);
        let _ = mounts.mount().unwrap();
        mounts.unmount().unwrap();

        // Negative control for `mount_with_privilege`: without a configured
        // method nothing is prepended.
        assert_eq!(executor.privileges(), vec![None, None]);
    }

    #[test]
    fn mount_executor_error_triggers_partial_unmount() {
        // 2 entries: first mount succeeds, second mount returns Err
        let executor = Arc::new(MockMountExecutor::returning_err_on(1));
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None);
        let err = mounts.mount().unwrap_err();
        assert!(
            err.to_string().contains("executor error"),
            "should contain executor error: {}",
            err
        );

        let calls = executor.calls();
        // mount proc (success), mount sys (Err), umount proc (cleanup)
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0][0], "mount");
        assert_eq!(calls[1][0], "mount");
        assert_eq!(calls[2][0], "umount");
    }

    #[test]
    fn drop_retries_after_unmount_failure() {
        // 2 mounts succeed, first unmount() call fails, Drop should retry
        let executor = Arc::new(MockMountExecutor::failing_umount_on(vec![2, 3]));
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        {
            let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None);
            let _ = mounts.mount().unwrap();

            let err = mounts.unmount();
            assert!(err.is_err(), "first unmount should fail");
            assert!(!mounts.torn_down, "torn_down should be false after failed unmount");

            // Drop will call unmount() again since torn_down is false
        }

        let calls = executor.calls();
        // 2 mounts + 2 failed umounts (first unmount()) + 2 retry umounts (Drop)
        assert_eq!(calls.len(), 6);
        assert_eq!(calls[4][0], "umount");
        assert_eq!(calls[5][0], "umount");
    }

    #[test]
    fn mount_first_entry_failure_does_not_unmount() {
        let executor = Arc::new(MockMountExecutor::failing_on(0));
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None);
        let err = mounts.mount().unwrap_err();
        assert!(err.to_string().contains("command execution failed"));

        let calls = executor.calls();
        // Only 1 mount call (fails), no unmount calls since nothing was mounted
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0][0], "mount");
    }

    #[test]
    fn unmount_failure_collects_all_errors() {
        // 2 mounts succeed (calls 0, 1), both umounts fail (calls 2, 3)
        let executor = Arc::new(MockMountExecutor::failing_umount_on(vec![2, 3]));
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None);
        let _ = mounts.mount().unwrap();

        let err = mounts.unmount().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("2 filesystem"), "error should report 2 failures: {}", msg);
    }

    #[test]
    fn unmount_partial_success_tracks_per_entry_state() {
        // 2 mounts succeed (calls 0, 1), first umount (reverse: /sys) fails (call 2),
        // second umount (reverse: /proc) succeeds (call 3)
        let executor = Arc::new(MockMountExecutor::failing_umount_on(vec![2]));
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None);
        let _ = mounts.mount().unwrap();

        let err = mounts.unmount().unwrap_err();
        assert!(err.to_string().contains("1 filesystem"));

        // /proc (index 0) was successfully unmounted, /sys (index 1) remains mounted
        assert!(mounts.mounted_paths[0].is_none());
        assert!(mounts.mounted_paths[1].is_some());
    }

    #[test]
    fn unmount_retry_targets_only_failed_entries() {
        // 2 mounts succeed (calls 0, 1), first umount (reverse: /sys) fails (call 2),
        // second umount (reverse: /proc) succeeds (call 3).
        // On retry, only /sys should be attempted.
        let executor = Arc::new(MockMountExecutor::failing_umount_on(vec![2]));
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None);
        let _ = mounts.mount().unwrap();

        // First unmount: /sys fails, /proc succeeds
        let _ = mounts.unmount();

        // Retry: only /sys should be attempted (call index 4)
        let _ = mounts.unmount();

        let calls = executor.calls();
        // 2 mounts + 2 umounts (first attempt) + 1 umount (retry /sys only) = 5
        assert_eq!(calls.len(), 5);
        assert_eq!(calls[4][0], "umount");
        assert!(calls[4][1].contains("sys"), "retry should target /sys only");
    }

    #[test]
    fn mount_rejects_symlink_in_target_path() {
        let executor = Arc::new(MockMountExecutor::new());
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let symlink_path = rootfs.join("proc");
        std::os::unix::fs::symlink("/tmp", &symlink_path).unwrap();

        let entries = vec![MountEntry {
            source: "proc".to_string(),
            target: crate::config::rootfs_path("/proc"),
            options: vec![],
        }];

        let mut mounts = RootfsMounts::new(&rootfs, entries, executor.clone(), None);
        let err = mounts.mount().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("symlink detected"), "should detect symlink: {}", msg);
    }

    #[test]
    fn mount_rejects_symlink_in_intermediate_path() {
        let executor = Arc::new(MockMountExecutor::new());
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let symlink_path = rootfs.join("dev");
        std::os::unix::fs::symlink("/tmp", &symlink_path).unwrap();

        let entries = vec![MountEntry {
            source: "devpts".to_string(),
            target: crate::config::rootfs_path("/dev/pts"),
            options: vec![],
        }];

        let mut mounts = RootfsMounts::new(&rootfs, entries, executor.clone(), None);
        let err = mounts.mount().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("symlink detected"),
            "should detect symlink in intermediate component: {}",
            msg
        );
    }

    #[test]
    fn safe_create_mount_point_creates_nested_directories() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let result = safe_create_mount_point(&rootfs, &crate::config::rootfs_path("/dev/pts"));
        assert!(result.is_ok());
        let abs = result.unwrap();
        assert_eq!(abs, rootfs.join("dev/pts"));
        assert!(abs.exists());
    }

    #[test]
    fn safe_create_mount_point_handles_existing_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        std::fs::create_dir_all(rootfs.join("proc")).unwrap();

        let result = safe_create_mount_point(&rootfs, &crate::config::rootfs_path("/proc"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), rootfs.join("proc"));
    }

    #[test]
    fn safe_create_mount_point_rejects_symlink_at_component() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        std::os::unix::fs::symlink("/tmp", rootfs.join("dev")).unwrap();

        let err =
            safe_create_mount_point(&rootfs, &crate::config::rootfs_path("/dev/pts")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("symlink detected"), "should detect symlink at component: {}", msg);
    }

    #[test]
    fn safe_create_mount_point_rejects_symlink_in_rootfs() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs_link = Utf8PathBuf::from_path_buf(temp_dir.path().join("rootfs_link")).unwrap();
        let real_dir = Utf8PathBuf::from_path_buf(temp_dir.path().join("real_rootfs")).unwrap();
        std::fs::create_dir(&real_dir).unwrap();
        std::os::unix::fs::symlink(&real_dir, &rootfs_link).unwrap();

        let err = safe_create_mount_point(&rootfs_link, &crate::config::rootfs_path("/proc"))
            .unwrap_err();
        // The refusal comes from `open_anchor`, which walks the rootfs a component at a
        // time; a single `openat` of the whole path would have caught this final component
        // but not a symlink at any of the ones before it.
        let msg = err.to_string();
        assert!(msg.contains("symlink"), "should detect rootfs symlink: {}", msg);
    }

    // The component `O_NOFOLLOW` on a whole-path `openat` would have missed: it applies to
    // the last one only, so an intermediate directory swapped for a symlink is followed and
    // every mount point below it is created somewhere else entirely.
    #[test]
    fn safe_create_mount_point_rejects_a_symlink_above_the_rootfs() {
        let temp_dir = tempfile::tempdir().unwrap();
        let base = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();
        let real = base.join("real");
        std::fs::create_dir_all(real.join("rootfs")).unwrap();
        std::os::unix::fs::symlink(&real, base.join("link")).unwrap();

        let err = safe_create_mount_point(
            &base.join("link/rootfs"),
            &crate::config::rootfs_path("/proc"),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("symlink"), "should detect the intermediate symlink: {}", msg);
        assert!(!real.join("rootfs/proc").exists(), "created a mount point through the symlink");
    }

    // The restore asks for this token, and the point of asking again rather than carrying
    // one is that a guard whose mounts are gone cannot produce it. A `prepare.mount` over
    // the directory the restore writes into is the case that makes the ordering matter.
    // A fresh guard has no entry missing, and one whose `mount` failed has had the
    // successful entries rolled back, so "nothing is unmounted" is true in both states and
    // is not the question. The token has to mean the mounts were established.
    #[test]
    fn still_mounted_refuses_before_the_mounts_are_established() {
        let executor = Arc::new(MockMountExecutor::new());
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None);
        let err = mounts
            .still_mounted()
            .expect_err("a guard that has not mounted cannot claim its mounts are in place");
        assert!(err.to_string().contains("have not been established"), "unexpected: {err:#}");
    }

    #[test]
    fn still_mounted_refuses_after_a_failed_mount() {
        let executor = Arc::new(MockMountExecutor::failing_on(1));
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None);
        mounts.mount().expect_err("the second entry fails");

        let err = mounts
            .still_mounted()
            .expect_err("a partly-mounted guard has rolled back and has nothing to claim");
        assert!(err.to_string().contains("have not been established"), "unexpected: {err:#}");
    }

    #[test]
    fn still_mounted_refuses_once_the_mounts_are_released() {
        let executor = Arc::new(MockMountExecutor::new());
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None);
        let _ = mounts.mount().unwrap();
        let _ = mounts
            .still_mounted()
            .expect("a mounted guard still has its mounts");

        mounts.unmount().unwrap();

        let err = mounts
            .still_mounted()
            .expect_err("an unmounted guard cannot claim its mounts are in place");
        assert!(err.to_string().contains("already been released"), "unexpected error: {err:#}");
    }

    #[test]
    fn unmount_uses_stored_paths() {
        let executor = Arc::new(MockMountExecutor::new());
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None);
        let _ = mounts.mount().unwrap();

        assert!(mounts.mounted_paths[0].is_some());
        assert!(mounts.mounted_paths[1].is_some());

        let path0 = mounts.mounted_paths[0].as_ref().unwrap().clone();
        let path1 = mounts.mounted_paths[1].as_ref().unwrap().clone();
        assert!(path0.as_str().contains("proc"));
        assert!(path1.as_str().contains("sys"));

        mounts.unmount().unwrap();

        let calls = executor.calls();
        // Unmount in reverse order: sys first, then proc
        assert_eq!(calls[2][1], path1.to_string());
        assert_eq!(calls[3][1], path0.to_string());
    }
}
