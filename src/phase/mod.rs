//! Phase module for pipeline task definitions.
//!
//! This module provides phase-specific task enums and the internal `PhaseItem`
//! trait used by the pipeline to process tasks generically across phases.
//!
//! ## Phase structure
//!
//! - [`prepare`] — Preparation tasks before main provisioning (currently empty)
//! - [`provision`] — Main provisioning tasks (Shell, Mitamae)
//! - [`assemble`] — Finalization tasks after provisioning (currently empty)
//!
//! Adding a new phase requires:
//! 1. Creating a new module with a `#[non_exhaustive]` enum
//! 2. Implementing `PhaseItem` for the enum
//! 3. Adding a field to `Profile` and `Pipeline`

pub mod assemble;
pub mod prepare;
pub mod provision;

use std::borrow::Cow;
use std::fs;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use tracing::info;

pub use assemble::AssembleResolvConfTask;
pub use assemble::AssembleTask;
pub use prepare::MountTask;
pub use prepare::PrepareTask;
pub use prepare::ResolvConfTask;
pub use provision::MitamaeTask;
pub use provision::ProvisionTask;
pub use provision::ShellTask;

use crate::config::IsolationConfig;
use crate::error::RsdebstrapError;
use crate::executor::ExecutionResult;
use crate::isolation::IsolationContext;
use crate::privilege::PrivilegeMethod;

/// Script source for task execution.
///
/// Represents exactly one of `script` (external file) or `content` (inline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptSource {
    /// External script file path
    Script(Utf8PathBuf),
    /// Inline script content
    Content(String),
}

impl ScriptSource {
    /// Returns a human-readable name for this source.
    pub fn name(&self) -> &str {
        match self {
            Self::Script(path) => path.as_str(),
            Self::Content(_) => "<inline>",
        }
    }

    /// Returns the script path if this source is an external file.
    pub fn script_path(&self) -> Option<&Utf8Path> {
        match self {
            Self::Script(path) => Some(path),
            Self::Content(_) => None,
        }
    }

    /// Resolves relative script paths relative to the given base directory.
    ///
    /// If the source is an external script file with a relative path,
    /// it is resolved against `base_dir`. Content sources are unchanged.
    pub fn resolve_paths(&mut self, base_dir: &Utf8Path) {
        if let Self::Script(path) = self
            && path.is_relative()
        {
            *path = base_dir.join(&*path);
        }
    }

    /// Validates the script source.
    ///
    /// The `label` parameter is used in error messages to distinguish between
    /// different source types (e.g., "shell script", "mitamae recipe").
    pub fn validate(&self, label: &str) -> Result<(), RsdebstrapError> {
        match self {
            Self::Script(script) => {
                validate_no_parent_dirs(script, label)?;
                validate_host_file_exists(script, label)?;
                Ok(())
            }
            Self::Content(content) => {
                if content.trim().is_empty() {
                    return Err(RsdebstrapError::Validation(format!(
                        "inline {} content must not be empty",
                        label,
                    )));
                }
                Ok(())
            }
        }
    }
}

/// Internal trait for the pipeline to process phases uniformly.
///
/// This is not an extension point, but for internal convenience only.
pub(crate) trait PhaseItem: std::fmt::Debug {
    fn name(&self) -> Cow<'_, str>;
    fn validate(&self) -> Result<(), RsdebstrapError>;
    fn execute(&self, ctx: &dyn IsolationContext) -> Result<()>;
    fn resolved_isolation_config(&self) -> Option<&IsolationConfig>;
}

/// Validates that a path contains no `..` components.
///
/// Returns `RsdebstrapError::Validation` if any parent directory component is found.
/// The `label` parameter is used in error messages to describe the path's purpose
/// (e.g., "shell script", "mitamae binary").
pub(crate) fn validate_no_parent_dirs(path: &Utf8Path, label: &str) -> Result<(), RsdebstrapError> {
    if path
        .components()
        .any(|c| c == camino::Utf8Component::ParentDir)
    {
        return Err(RsdebstrapError::Validation(format!(
            "{} path '{}' contains '..' components, \
            which is not allowed for security reasons",
            label, path
        )));
    }
    Ok(())
}

/// Validates that a host-side file exists and is a regular file (not a symlink).
///
/// Uses `symlink_metadata` to avoid following symlinks. Returns
/// `RsdebstrapError::Io` if the file cannot be accessed, or
/// `RsdebstrapError::Validation` if the path is a symlink or not a regular file.
/// The `label` parameter is used in error messages (e.g., "shell script", "mitamae binary").
pub(crate) fn validate_host_file_exists(
    path: &Utf8Path,
    label: &str,
) -> Result<(), RsdebstrapError> {
    let metadata = fs::symlink_metadata(path).map_err(|e| {
        RsdebstrapError::io(format!("failed to read {} metadata: {}", label, path), e)
    })?;
    if metadata.is_symlink() {
        return Err(RsdebstrapError::Validation(format!(
            "{} path '{}' is a symlink, which is not allowed for security reasons",
            label, path
        )));
    }
    if !metadata.is_file() {
        return Err(RsdebstrapError::Validation(format!("{} is not a file: {}", label, path)));
    }
    Ok(())
}

/// Resolves `script`/`content` mutual exclusivity and builds a [`ScriptSource`].
///
/// Used by task `Deserialize` impls to share the common validation logic:
/// exactly one of `script` or `content` must be provided.
pub(crate) fn resolve_script_source<E: serde::de::Error>(
    script: Option<Utf8PathBuf>,
    content: Option<String>,
) -> std::result::Result<ScriptSource, E> {
    match (script, content) {
        (Some(_), Some(_)) => Err(E::custom("'script' and 'content' are mutually exclusive")),
        (None, None) => Err(E::custom("either 'script' or 'content' must be specified")),
        (Some(s), None) => Ok(ScriptSource::Script(s)),
        (None, Some(c)) => Ok(ScriptSource::Content(c)),
    }
}

/// RAII guard to ensure temporary file cleanup even on error.
pub(crate) struct TempFileGuard {
    path: Utf8PathBuf,
    dry_run: bool,
}

impl TempFileGuard {
    pub(crate) fn new(path: Utf8PathBuf, dry_run: bool) -> Self {
        Self { path, dry_run }
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if !self.dry_run {
            match fs::remove_file(&self.path) {
                Ok(()) => tracing::debug!("cleaned up temp file: {}", self.path),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    tracing::debug!("temp file already removed: {}", self.path);
                }
                Err(e) => {
                    tracing::error!(
                        path = %self.path,
                        error_kind = ?e.kind(),
                        "failed to cleanup temp file: {}",
                        e,
                    );
                }
            }
        }
    }
}

/// Sets Unix file permissions on the given path.
#[cfg(unix)]
pub(crate) fn set_file_mode(path: &Utf8Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path))?
        .permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)
        .with_context(|| format!("failed to set permissions on {}", path))?;
    Ok(())
}

/// Copies or writes a script source to the target path and sets permissions.
///
/// On Unix systems, sets the file mode to the specified `mode`.
/// On other platforms, the permission step is skipped.
pub(crate) fn prepare_source_file(
    source: &ScriptSource,
    target: &Utf8Path,
    mode: u32,
    label: &str,
) -> Result<()> {
    match source {
        ScriptSource::Script(src_path) => {
            info!("copying {} from {} to rootfs", label, src_path);
            fs::copy(src_path, target)
                .with_context(|| format!("failed to copy {} {} to {}", label, src_path, target))?;
        }
        ScriptSource::Content(content) => {
            info!("writing inline {} to rootfs", label);
            fs::write(target, content)
                .with_context(|| format!("failed to write inline {} to {}", label, target))?;
        }
    }
    #[cfg(unix)]
    set_file_mode(target, mode)?;
    Ok(())
}

/// Validates that /tmp exists as a real directory (not a symlink).
///
/// This is a security-critical check to prevent attackers from using symlinks
/// to write files outside the chroot.
pub(crate) fn validate_tmp_directory(rootfs: &Utf8Path) -> Result<()> {
    let tmp_dir = rootfs.join("tmp");
    let metadata = match std::fs::symlink_metadata(&tmp_dir) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(RsdebstrapError::Validation(format!(
                "/tmp directory not found in rootfs at {}. \
                The rootfs may not be properly bootstrapped.",
                tmp_dir
            ))
            .into());
        }
        Err(e) => {
            return Err(RsdebstrapError::io(
                format!("failed to read /tmp metadata at {}", tmp_dir),
                e,
            )
            .into());
        }
    };

    if metadata.file_type().is_symlink() {
        return Err(RsdebstrapError::Validation(
            "/tmp in rootfs is a symlink, which is not allowed for security reasons. \
            An attacker could use this to write files outside the chroot."
                .to_string(),
        )
        .into());
    }

    if !metadata.file_type().is_dir() {
        return Err(RsdebstrapError::Validation(format!(
            "/tmp in rootfs is not a directory: {}. \
            The rootfs may not be properly bootstrapped.",
            tmp_dir
        ))
        .into());
    }

    Ok(())
}

/// Executes a command within an isolation context, preserving `RsdebstrapError` variants.
///
/// If the context returns an `anyhow::Error` that wraps a `RsdebstrapError`, the typed
/// error is preserved. Otherwise, the error is wrapped with a descriptive context message.
///
/// # Arguments
///
/// * `context` - The isolation context to execute within
/// * `command` - The command and arguments to execute
/// * `task_label` - Human-readable label used in error messages
/// * `privilege` - Optional privilege escalation method (`sudo`/`doas`) to wrap the command
pub(crate) fn execute_in_context(
    context: &dyn IsolationContext,
    command: &[String],
    task_label: &str,
    privilege: Option<PrivilegeMethod>,
) -> Result<ExecutionResult> {
    context
        .execute(command, privilege)
        .map_err(|e| match e.downcast::<RsdebstrapError>() {
            Ok(typed) => typed.into(),
            Err(e) => e.context(format!("failed to execute {}", task_label)),
        })
}

/// Checks the execution result and returns an error if the command failed.
///
/// Handles three cases:
/// - Non-zero exit status: returns `Execution` error with the status code
/// - No exit status in non-dry-run mode: returns `Execution` error (e.g., killed by signal)
/// - Success or dry-run with no status: returns `Ok(())`
pub(crate) fn check_execution_result(
    result: &ExecutionResult,
    command: &[String],
    context_name: &str,
    dry_run: bool,
) -> Result<()> {
    match result.status {
        Some(status) if !status.success() => {
            Err(
                RsdebstrapError::execution_in_isolation(command, context_name, status.to_string())
                    .into(),
            )
        }
        None if !dry_run => Err(RsdebstrapError::execution_in_isolation(
            command,
            context_name,
            "process exited without status (possibly killed by signal)",
        )
        .into()),
        _ => Ok(()),
    }
}

/// Re-validates `/tmp` (TOCTOU mitigation) and runs the file preparation closure.
///
/// In dry-run mode, skips both validation and file preparation entirely.
pub(crate) fn prepare_files_with_toctou_check(
    rootfs: &Utf8Path,
    dry_run: bool,
    prepare_fn: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if !dry_run {
        validate_tmp_directory(rootfs)
            .context("TOCTOU check: /tmp validation failed before writing files")?;
        prepare_fn()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    mod check_execution_result_tests {
        use std::os::unix::process::ExitStatusExt;
        use std::process::ExitStatus;

        use super::*;
        use crate::executor::ExecutionResult;

        #[test]
        fn success_returns_ok() {
            let result = ExecutionResult {
                status: Some(ExitStatus::from_raw(0)),
            };
            let command: Vec<String> = vec!["/bin/sh".to_string(), "/tmp/test.sh".to_string()];
            assert!(check_execution_result(&result, &command, "chroot", false).is_ok());
        }

        #[test]
        fn nonzero_exit_returns_execution_error() {
            let result = ExecutionResult {
                status: Some(ExitStatus::from_raw(1 << 8)),
            };
            let command: Vec<String> = vec!["/bin/sh".to_string(), "/tmp/test.sh".to_string()];
            let err = check_execution_result(&result, &command, "chroot", false).unwrap_err();
            let typed = err.downcast_ref::<RsdebstrapError>().unwrap();
            assert!(
                matches!(typed, RsdebstrapError::Execution { .. }),
                "expected Execution error, got: {:?}",
                typed
            );
        }

        #[test]
        fn no_status_in_non_dry_run_returns_error() {
            let result = ExecutionResult { status: None };
            let command: Vec<String> = vec!["/bin/sh".to_string(), "/tmp/test.sh".to_string()];
            let err = check_execution_result(&result, &command, "chroot", false).unwrap_err();
            let typed = err.downcast_ref::<RsdebstrapError>().unwrap();
            assert!(
                matches!(typed, RsdebstrapError::Execution { .. }),
                "expected Execution error, got: {:?}",
                typed
            );
            assert!(err.to_string().contains("killed by signal"));
        }

        #[test]
        fn no_status_in_dry_run_returns_ok() {
            let result = ExecutionResult { status: None };
            let command: Vec<String> = vec!["/bin/sh".to_string(), "/tmp/test.sh".to_string()];
            assert!(check_execution_result(&result, &command, "chroot", true).is_ok());
        }
    }

    #[test]
    fn test_temp_file_guard_removes_file_on_drop() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = Utf8PathBuf::from_path_buf(temp_dir.path().join("test_file.tmp"))
            .expect("path should be valid UTF-8");

        fs::write(&file_path, "test content").expect("failed to write file");
        assert!(file_path.exists(), "file should exist before drop");

        {
            let _guard = TempFileGuard::new(file_path.clone(), false);
        }

        assert!(!file_path.exists(), "file should be removed after drop");
    }

    #[test]
    fn test_temp_file_guard_handles_already_removed_file() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = Utf8PathBuf::from_path_buf(temp_dir.path().join("nonexistent.tmp"))
            .expect("path should be valid UTF-8");

        {
            let _guard = TempFileGuard::new(file_path.clone(), false);
        }
        // If we get here, no panic occurred
    }

    #[test]
    fn test_temp_file_guard_skips_removal_in_dry_run() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = Utf8PathBuf::from_path_buf(temp_dir.path().join("dry_run_file.tmp"))
            .expect("path should be valid UTF-8");

        fs::write(&file_path, "test content").expect("failed to write file");
        assert!(file_path.exists(), "file should exist before drop");

        {
            let _guard = TempFileGuard::new(file_path.clone(), true);
        }

        assert!(file_path.exists(), "file should still exist after dry_run drop");
    }
}
