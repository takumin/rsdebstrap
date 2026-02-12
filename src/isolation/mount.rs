//! Filesystem mount management for rootfs isolation.
//!
//! This module provides [`RootfsMounts`], an RAII guard that manages filesystem
//! mounts within a rootfs directory. Mounts are set up in order and torn down
//! in reverse order, with guaranteed cleanup via `Drop`.

use std::fs;
use std::sync::Arc;

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use tracing::info;

use crate::config::MountEntry;
use crate::error::RsdebstrapError;
use crate::executor::CommandExecutor;
use crate::privilege::PrivilegeMethod;

/// Validates that no component of the target path within rootfs is a symlink.
///
/// This prevents symlink-based attacks where a malicious rootfs could redirect
/// mount points to arbitrary locations on the host filesystem.
fn validate_no_symlinks(rootfs: &Utf8Path, target: &Utf8Path) -> Result<()> {
    let relative = target.strip_prefix("/").unwrap_or(target);
    let mut current = rootfs.to_path_buf();

    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(RsdebstrapError::Isolation(format!(
                        "symlink detected at {} in rootfs mount target path {}; \
                        this could allow mount point redirection outside the rootfs",
                        current, target,
                    ))
                    .into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Path doesn't exist yet; remaining components will be created by create_dir_all
                break;
            }
            Err(e) => {
                return Err(RsdebstrapError::io(
                    format!("failed to check mount target path component: {}", current),
                    e,
                )
                .into());
            }
        }
    }

    Ok(())
}

/// RAII guard for filesystem mounts within a rootfs.
///
/// Mounts are established in order and torn down in reverse order.
/// The `Drop` implementation ensures cleanup even on error paths.
pub struct RootfsMounts {
    rootfs: Utf8PathBuf,
    entries: Vec<MountEntry>,
    mounted: Vec<bool>,
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
        let mounted = vec![false; entries.len()];
        Self {
            rootfs: rootfs.to_owned(),
            entries,
            mounted,
            executor,
            privilege,
            dry_run,
            torn_down: false,
        }
    }

    /// Returns the number of currently mounted entries.
    fn mounted_count(&self) -> usize {
        self.mounted.iter().filter(|&&m| m).count()
    }

    /// Returns true if there are no mount entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Mounts all entries in order.
    ///
    /// Creates mount point directories as needed (skipped in dry-run mode).
    /// On failure, automatically unmounts any entries that were successfully mounted.
    pub fn mount(&mut self) -> Result<()> {
        debug_assert!(
            self.mounted.iter().all(|m| !m) && !self.torn_down,
            "mount() called on already-used RootfsMounts"
        );

        if self.entries.is_empty() {
            return Ok(());
        }

        info!("mounting {} filesystem(s) in rootfs", self.entries.len());

        for (i, entry) in self.entries.iter().enumerate() {
            let abs_target = self
                .rootfs
                .join(entry.target.strip_prefix("/").unwrap_or(&entry.target));

            // Validate no symlinks in target path before creating directories
            if !self.dry_run
                && let Err(e) = validate_no_symlinks(&self.rootfs, &entry.target)
            {
                return Err(self.cleanup_after_error(e));
            }

            // Create mount point directory if needed
            if !self.dry_run
                && let Err(e) = fs::create_dir_all(&abs_target)
            {
                return Err(self.cleanup_after_error(
                    RsdebstrapError::io(format!("failed to create mount point: {}", abs_target), e)
                        .into(),
                ));
            }

            info!("mounting {} on {}", entry.source, entry.target);
            let spec = entry.build_mount_spec(&self.rootfs, self.privilege);
            match self.executor.execute(&spec) {
                Ok(result) if result.success() => {
                    self.mounted[i] = true;
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
    /// on mount failure). Tracks per-entry state so that retries only attempt
    /// entries that are still mounted.
    fn unmount_internal(&mut self) -> Result<()> {
        let count = self.mounted_count();
        if count == 0 {
            return Ok(());
        }

        info!("unmounting {} filesystem(s) from rootfs", count);

        let mut errors = Vec::new();

        for i in (0..self.entries.len()).rev() {
            if !self.mounted[i] {
                continue;
            }
            let entry = &self.entries[i];
            info!("unmounting {}", entry.target);
            let spec = entry.build_umount_spec(&self.rootfs, self.privilege);
            match self.executor.execute(&spec) {
                Ok(result) if result.success() => {
                    self.mounted[i] = false;
                }
                Ok(result) => {
                    let status = result
                        .status
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    errors.push(format!("umount {} failed: {}", entry.target, status));
                }
                Err(e) => {
                    errors.push(format!("umount {} failed: {}", entry.target, e));
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
            && self.mounted.iter().any(|&m| m)
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
        assert!(!mounts.mounted[0]);
        assert!(mounts.mounted[1]);
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
    fn validate_no_symlinks_passes_for_regular_dirs() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        // Create a regular directory at rootfs/proc
        fs::create_dir_all(rootfs.join("proc")).unwrap();

        let result = validate_no_symlinks(&rootfs, Utf8Path::new("/proc"));
        assert!(result.is_ok());
    }

    #[test]
    fn validate_no_symlinks_passes_for_nonexistent_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();

        // rootfs/proc doesn't exist — should pass (create_dir_all will create it)
        let result = validate_no_symlinks(&rootfs, Utf8Path::new("/proc"));
        assert!(result.is_ok());
    }
}
