//! Filesystem mount management for rootfs isolation.
//!
//! This module provides [`RootfsMounts`], an RAII guard that manages filesystem
//! mounts within a rootfs directory. Mounts are set up in order and torn down
//! in reverse order, with guaranteed cleanup via `Drop`.
//!
//! Mount point directories are created using `openat`/`mkdirat` with `O_NOFOLLOW`
//! to prevent TOCTOU races between symlink validation and directory creation.

use std::os::fd::OwnedFd;
use std::sync::Arc;

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use rustix::fs::{self as rfs, CWD, Mode, OFlags};
use tracing::info;

use crate::config::MountEntry;
use crate::error::RsdebstrapError;
use crate::executor::CommandExecutor;
use crate::privilege::PrivilegeMethod;

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
/// The rootfs directory itself is also verified (opened with `O_NOFOLLOW`) to ensure it
/// is not a symlink.
///
/// Returns the verified absolute path for use in mount/umount commands.
pub fn safe_create_mount_point(rootfs: &Utf8Path, target: &Utf8Path) -> Result<Utf8PathBuf> {
    let relative = target.strip_prefix("/").unwrap_or(target);

    // Open rootfs with O_NOFOLLOW to verify it's not a symlink
    let rootfs_fd = rfs::openat(
        CWD,
        rootfs.as_str(),
        OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| map_openat_error(e, rootfs, "rootfs directory"))?;

    let mut current_fd = rootfs_fd;
    let mut current_path = rootfs.to_path_buf();

    for component in relative.components() {
        let name = component.as_str();
        current_path.push(name);

        // Try to open the existing directory
        match open_dir_nofollow(&current_fd, name) {
            Ok(fd) => {
                current_fd = fd;
            }
            Err(rustix::io::Errno::NOENT) => {
                // Directory doesn't exist, create it
                match rfs::mkdirat(
                    &current_fd,
                    name,
                    Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
                ) {
                    Ok(()) => {}
                    Err(rustix::io::Errno::EXIST) => {
                        // Race: another process created it between our check and create.
                        // Re-open it (still with O_NOFOLLOW for safety).
                    }
                    Err(e) => return Err(map_openat_error(e, &current_path, "mount point")),
                }
                // Open the just-created (or racing) directory
                current_fd = open_dir_nofollow(&current_fd, name)
                    .map_err(|e| map_openat_error(e, &current_path, "mount point"))?;
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
pub struct RootfsMounts {
    rootfs: Utf8PathBuf,
    entries: Vec<MountEntry>,
    /// Verified absolute paths for mounted entries (`Some` = mounted, `None` = not mounted).
    mounted_paths: Vec<Option<Utf8PathBuf>>,
    executor: Arc<dyn CommandExecutor>,
    privilege: Option<PrivilegeMethod>,
    dry_run: bool,
    torn_down: bool,
}

impl RootfsMounts {
    /// Creates a new `RootfsMounts` instance.
    ///
    /// No mounts are performed until [`mount()`](Self::mount) is called.
    pub fn new(
        rootfs: &Utf8Path,
        entries: Vec<MountEntry>,
        executor: Arc<dyn CommandExecutor>,
        privilege: Option<PrivilegeMethod>,
        dry_run: bool,
    ) -> Self {
        let mounted_paths = vec![None; entries.len()];
        Self {
            rootfs: rootfs.to_owned(),
            entries,
            mounted_paths,
            executor,
            privilege,
            dry_run,
            torn_down: false,
        }
    }

    /// Returns the number of currently mounted entries.
    fn mounted_count(&self) -> usize {
        self.mounted_paths.iter().filter(|p| p.is_some()).count()
    }

    /// Returns true if there are no mount entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Mounts all entries in order.
    ///
    /// Creates mount point directories as needed using `openat`/`mkdirat` with
    /// `O_NOFOLLOW` (skipped in dry-run mode). Verified absolute paths are stored
    /// and reused for `umount` commands.
    /// On failure, automatically unmounts any entries that were successfully mounted.
    pub fn mount(&mut self) -> Result<()> {
        if self.torn_down || self.mounted_paths.iter().any(|p| p.is_some()) {
            return Err(RsdebstrapError::Isolation(
                "mount() called on already-used RootfsMounts".to_string(),
            )
            .into());
        }

        if self.entries.is_empty() {
            return Ok(());
        }

        info!("mounting {} filesystem(s) in rootfs", self.entries.len());

        for (i, entry) in self.entries.iter().enumerate() {
            // Create mount point directory with symlink-safe openat/mkdirat
            let abs_target = if self.dry_run {
                // In dry-run mode, compute path by string concatenation (no filesystem access)
                self.rootfs
                    .join(entry.target.strip_prefix("/").unwrap_or(&entry.target))
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

        Ok(())
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
    pub fn unmount(&mut self) -> Result<()> {
        if self.torn_down {
            return Ok(());
        }
        let result = self.unmount_internal();
        if result.is_ok() {
            self.torn_down = true;
        }
        result
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::{CommandSpec, ExecutionResult};
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::sync::Mutex;

    struct MockMountExecutor {
        calls: Mutex<Vec<Vec<String>>>,
        /// Call index that returns non-zero exit status.
        fail_on_call: Option<usize>,
        /// Call indices that return non-zero exit status (for umount failures).
        fail_umount_on_calls: Vec<usize>,
        /// Call index that returns `Err(anyhow!(...))`.
        return_err_on_call: Option<usize>,
    }

    impl MockMountExecutor {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail_on_call: None,
                fail_umount_on_calls: vec![],
                return_err_on_call: None,
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
    }

    impl CommandExecutor for MockMountExecutor {
        fn execute(&self, spec: &CommandSpec) -> Result<ExecutionResult> {
            let mut calls = self.calls.lock().unwrap();
            let index = calls.len();
            let mut args = vec![spec.command.clone()];
            args.extend(spec.args.iter().cloned());
            calls.push(args);
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
                target: "/proc".into(),
                options: vec![],
            },
            MountEntry {
                source: "sysfs".to_string(),
                target: "/sys".into(),
                options: vec![],
            },
        ]
    }

    #[test]
    fn mount_and_unmount_in_order() {
        let executor = Arc::new(MockMountExecutor::new());
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None, false);
        mounts.mount().unwrap();
        mounts.unmount().unwrap();

        let calls = executor.calls();
        // 2 mounts + 2 umounts = 4 calls
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
            RootfsMounts::new(Utf8Path::new("/tmp/rootfs"), vec![], executor.clone(), None, true);
        assert!(mounts.is_empty());
        mounts.mount().unwrap();
        mounts.unmount().unwrap();
        assert_eq!(executor.calls().len(), 0);
    }

    #[test]
    fn mount_failure_triggers_partial_unmount() {
        let executor = Arc::new(MockMountExecutor::failing_on(1));
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None, false);
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
            let mut mounts =
                RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None, false);
            mounts.mount().unwrap();
            // Drop without calling unmount()
        }

        let calls = executor.calls();
        assert_eq!(calls.len(), 4); // 2 mounts + 2 umounts
    }

    #[test]
    fn dry_run_skips_mkdir() {
        let executor = Arc::new(MockMountExecutor::new());
        let mut mounts = RootfsMounts::new(
            Utf8Path::new("/nonexistent/rootfs"),
            test_entries(),
            executor.clone(),
            None,
            true,
        );
        // Should not fail even though rootfs doesn't exist (dry-run skips mkdir)
        mounts.mount().unwrap();
        mounts.unmount().unwrap();

        let calls = executor.calls();
        assert_eq!(calls.len(), 4);
    }

    #[test]
    fn unmount_is_idempotent() {
        let executor = Arc::new(MockMountExecutor::new());
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None, false);
        mounts.mount().unwrap();
        mounts.unmount().unwrap();
        mounts.unmount().unwrap(); // second call should be no-op

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
            target: "/proc".into(),
            options: vec![],
        }];

        let mut mounts = RootfsMounts::new(
            &rootfs,
            entries,
            executor.clone(),
            Some(PrivilegeMethod::Sudo),
            false,
        );
        mounts.mount().unwrap();
        mounts.unmount().unwrap();

        // The mock executor doesn't track privilege in its simple format,
        // but we verify the calls were made
        let calls = executor.calls();
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn unmount_failure_collects_errors() {
        // 2 mounts succeed, then umount of second entry (call index 2) fails
        let executor = Arc::new(MockMountExecutor::failing_umount_on(vec![2]));
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None, false);
        mounts.mount().unwrap();

        let err = mounts.unmount().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("failed to unmount"),
            "error should describe unmount failure: {}",
            msg
        );
        assert!(msg.contains("1"), "error should contain failure count: {}", msg);

        let calls = executor.calls();
        // 2 mounts + 2 umount attempts (both attempted even though first fails)
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[2][0], "umount");
        assert_eq!(calls[3][0], "umount");

        // mounted_count should NOT be reset (unmount failed)
        assert!(!mounts.torn_down, "torn_down should be false after unmount failure");
    }

    #[test]
    fn mount_executor_error_triggers_partial_unmount() {
        // 2 entries: first mount succeeds, second mount returns Err
        let executor = Arc::new(MockMountExecutor::returning_err_on(1));
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None, false);
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
            let mut mounts =
                RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None, false);
            mounts.mount().unwrap();

            // First unmount fails
            let err = mounts.unmount();
            assert!(err.is_err(), "first unmount should fail");
            assert!(!mounts.torn_down, "torn_down should be false after failed unmount");

            // Drop will call unmount() again since torn_down is false
        }

        let calls = executor.calls();
        // 2 mounts + 2 failed umounts (first unmount()) + 2 retry umounts (Drop)
        assert_eq!(calls.len(), 6);
        // Verify Drop triggered the retry
        assert_eq!(calls[4][0], "umount");
        assert_eq!(calls[5][0], "umount");
    }

    #[test]
    fn mount_first_entry_failure_does_not_unmount() {
        let executor = Arc::new(MockMountExecutor::failing_on(0));
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None, false);
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

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None, false);
        mounts.mount().unwrap();

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

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None, false);
        mounts.mount().unwrap();

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

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None, false);
        mounts.mount().unwrap();

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

        // Create a symlink at rootfs/proc -> /tmp
        let symlink_path = rootfs.join("proc");
        std::os::unix::fs::symlink("/tmp", &symlink_path).unwrap();

        let entries = vec![MountEntry {
            source: "proc".to_string(),
            target: "/proc".into(),
            options: vec![],
        }];

        let mut mounts = RootfsMounts::new(&rootfs, entries, executor.clone(), None, false);
        let err = mounts.mount().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("symlink detected"), "should detect symlink: {}", msg);
    }

    #[test]
    fn mount_rejects_symlink_in_intermediate_path() {
        let executor = Arc::new(MockMountExecutor::new());
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        // Create a symlink at rootfs/dev -> /tmp
        let symlink_path = rootfs.join("dev");
        std::os::unix::fs::symlink("/tmp", &symlink_path).unwrap();

        let entries = vec![MountEntry {
            source: "devpts".to_string(),
            target: "/dev/pts".into(),
            options: vec![],
        }];

        let mut mounts = RootfsMounts::new(&rootfs, entries, executor.clone(), None, false);
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

        let result = safe_create_mount_point(&rootfs, Utf8Path::new("/dev/pts"));
        assert!(result.is_ok());
        let abs = result.unwrap();
        assert_eq!(abs, rootfs.join("dev/pts"));
        assert!(abs.exists());
    }

    #[test]
    fn safe_create_mount_point_handles_existing_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        // Create the directory first
        std::fs::create_dir_all(rootfs.join("proc")).unwrap();

        let result = safe_create_mount_point(&rootfs, Utf8Path::new("/proc"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), rootfs.join("proc"));
    }

    #[test]
    fn safe_create_mount_point_rejects_symlink_at_component() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        // Create a symlink at rootfs/dev -> /tmp
        std::os::unix::fs::symlink("/tmp", rootfs.join("dev")).unwrap();

        let err = safe_create_mount_point(&rootfs, Utf8Path::new("/dev/pts")).unwrap_err();
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

        let err = safe_create_mount_point(&rootfs_link, Utf8Path::new("/proc")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("symlink detected"), "should detect rootfs symlink: {}", msg);
    }

    #[test]
    fn unmount_uses_stored_paths() {
        let executor = Arc::new(MockMountExecutor::new());
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        let mut mounts = RootfsMounts::new(&rootfs, test_entries(), executor.clone(), None, false);
        mounts.mount().unwrap();

        // Verify that mounted_paths contain the expected paths
        assert!(mounts.mounted_paths[0].is_some());
        assert!(mounts.mounted_paths[1].is_some());

        let path0 = mounts.mounted_paths[0].as_ref().unwrap().clone();
        let path1 = mounts.mounted_paths[1].as_ref().unwrap().clone();
        assert!(path0.as_str().contains("proc"));
        assert!(path1.as_str().contains("sys"));

        mounts.unmount().unwrap();

        // After unmount, the umount commands should use the stored paths
        let calls = executor.calls();
        // Unmount in reverse order: sys first, then proc
        assert_eq!(calls[2][1], path1.to_string());
        assert_eq!(calls[3][1], path0.to_string());
    }
}
