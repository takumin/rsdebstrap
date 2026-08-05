//! Phase module for pipeline task definitions.
//!
//! This module provides phase-specific task types and the internal `PhaseItem`
//! trait used by the pipeline to name and validate tasks generically across
//! phases, plus the per-phase item traits that say what each phase may do.
//!
//! ## Phase structure
//!
//! - [`prepare`] — Preparation tasks before main provisioning (named-field
//!   [`PrepareConfig`]: `mount`, `resolv_conf`)
//! - [`provision`] — Main provisioning tasks (Shell, Mitamae), an ordered `Vec`
//! - [`assemble`] — Finalization tasks after provisioning (named-field
//!   [`AssembleConfig`]: `resolv_conf`)
//!
//! Adding a new task to a named-field phase requires:
//! 1. Adding an `Option<...>` field to the phase config struct
//! 2. Implementing `PhaseItem` plus that phase's item trait (`PrepareItem` or
//!    `AssembleItem`) for the task struct
//! 3. Emitting it from the config's `items()` in the desired execution order

pub mod assemble;
pub mod prepare;
pub mod provision;

use std::borrow::Cow;
use std::fs;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use tracing::info;

pub use assemble::AssembleConfig;
pub use assemble::AssembleResolvConfTask;
pub use prepare::MountTask;
pub use prepare::PrepareConfig;
pub use prepare::ResolvConfTask;
pub use provision::MitamaeTask;
pub use provision::ProvisionTask;
pub use provision::ResolvedProvisionTask;
pub use provision::ShellTask;

use crate::config::IsolationConfig;
use crate::error::RsdebstrapError;
use crate::executor::ExecutionResult;
use crate::isolation::{IsolationContext, RootfsContext};
use crate::privilege::PrivilegeMethod;
use crate::rootfs::{RelPath, RootfsOps};

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

/// What every phase item shares: a name to log and a configuration to validate.
///
/// This is not an extension point, but for internal convenience only. What an
/// item can *do* is not here — it differs per phase, and the three traits below
/// say so:
///
/// - [`PrepareItem`] adds nothing. Prepare tasks are declarations; the mount and
///   resolv.conf lifecycles are driven by the pipeline's RAII guards, which
///   bracket the whole run rather than a single task.
/// - [`ProvisionItem`] runs programs, and is the only phase whose items carry an
///   isolation setting.
/// - [`AssembleItem`] writes the rootfs's final state through
///   [`RootfsContext`] and cannot run a program at all.
pub(crate) trait PhaseItem: std::fmt::Debug {
    fn name(&self) -> Cow<'_, str>;
    fn validate(&self) -> Result<(), RsdebstrapError>;
}

pub(crate) trait PrepareItem: PhaseItem {}

pub(crate) trait ProvisionItem: PhaseItem {
    fn resolved_isolation_config(&self) -> Option<&IsolationConfig>;
    fn execute(&self, ctx: &dyn IsolationContext) -> Result<()>;
}

pub(crate) trait AssembleItem: PhaseItem {
    fn execute(&self, ctx: &dyn RootfsContext) -> Result<()>;
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

/// RAII guard removing a staged file from the rootfs, on every path out.
///
/// Removal goes through [`RootfsOps`], so the entry it deletes is resolved the same
/// descriptor-anchored way it was written. A host path plus `fs::remove_file` would resolve
/// the name a second time, and a symlink planted at `/tmp` in between would send the removal
/// somewhere else.
pub(crate) struct StagedFileGuard<'a> {
    ops: &'a dyn RootfsOps,
    path: RelPath,
    dry_run: bool,
}

impl<'a> StagedFileGuard<'a> {
    pub(crate) fn new(ops: &'a dyn RootfsOps, path: RelPath, dry_run: bool) -> Self {
        Self { ops, path, dry_run }
    }
}

impl Drop for StagedFileGuard<'_> {
    fn drop(&mut self) {
        if self.dry_run {
            return;
        }
        match self.ops.remove(&self.path) {
            Ok(()) => tracing::debug!("cleaned up staged file: {}", self.path),
            Err(e) => tracing::error!(path = %self.path, "failed to clean up staged file: {}", e),
        }
    }
}

/// Stages a script source inside the rootfs at `path` with `mode`.
///
/// The host side of the copy happens here, unprivileged; what reaches [`RootfsOps`] is the
/// bytes and a [`RelPath`]. The write is atomic and carries its mode from creation, so the
/// file never exists in the rootfs with permissions other than the ones asked for.
pub(crate) fn stage_source_file(
    ops: &dyn RootfsOps,
    source: &ScriptSource,
    path: &RelPath,
    mode: u32,
    label: &str,
) -> Result<()> {
    let content = match source {
        ScriptSource::Script(src_path) => {
            info!("copying {} from {} to rootfs", label, src_path);
            fs::read(src_path).with_context(|| format!("failed to read {} {}", label, src_path))?
        }
        ScriptSource::Content(content) => {
            info!("writing inline {} to rootfs", label);
            content.clone().into_bytes()
        }
    };
    ops.write_file(path, &content, mode)
        .with_context(|| format!("failed to stage {} at {}", label, path))?;
    Ok(())
}

/// Validates that /tmp exists as a real directory (not a symlink).
///
/// A pre-flight check for a readable error, not a security control: staging resolves `/tmp`
/// itself with `O_NOFOLLOW` against the rootfs descriptor, so a symlink there fails the
/// write no matter what this reported earlier.
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

    fn staged_rootfs() -> (tempfile::TempDir, crate::rootfs::LocalRootfsOps) {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let root = Utf8Path::from_path(temp_dir.path()).expect("path should be valid UTF-8");
        fs::create_dir(root.join("tmp")).expect("failed to create tmp");
        let ops = crate::rootfs::LocalRootfsOps::open(root).expect("failed to open rootfs");
        (temp_dir, ops)
    }

    #[test]
    fn staged_file_guard_removes_the_entry_on_drop() {
        let (temp_dir, ops) = staged_rootfs();
        let path = RelPath::parse("/tmp/staged").unwrap();
        ops.write_file(&path, b"content", 0o600).unwrap();
        let host = temp_dir.path().join("tmp/staged");
        assert!(host.exists(), "entry should exist before drop");

        drop(StagedFileGuard::new(&ops, path, false));

        assert!(!host.exists(), "entry should be removed after drop");
    }

    #[test]
    fn staged_file_guard_tolerates_an_already_removed_entry() {
        let (_temp_dir, ops) = staged_rootfs();
        // Drop must not panic when the entry is already gone — a task that removed its
        // own script would otherwise abort the process while unwinding.
        drop(StagedFileGuard::new(&ops, RelPath::parse("/tmp/absent").unwrap(), false));
    }

    #[test]
    fn staged_file_guard_skips_removal_in_dry_run() {
        let (temp_dir, ops) = staged_rootfs();
        let path = RelPath::parse("/tmp/staged").unwrap();
        ops.write_file(&path, b"content", 0o600).unwrap();

        drop(StagedFileGuard::new(&ops, path, true));

        assert!(temp_dir.path().join("tmp/staged").exists(), "dry run must not remove it");
    }
}
