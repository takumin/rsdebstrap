//! Task module for declarative pipeline steps.
//!
//! This module provides the `TaskDefinition` enum — a data-driven abstraction
//! where each variant describes *what* to execute, and methods on the enum
//! provide *how* to execute via Rust's exhaustive pattern matching.
//!
//! Adding a new task type requires:
//! 1. Adding a new variant to `TaskDefinition`
//! 2. Creating a corresponding data struct (e.g., `MitamaeTask`)
//! 3. Implementing the match arms in all methods on `TaskDefinition`
//!    (`name`, `validate`, `execute`, `script_path`, `resolve_paths`, `binary_path`)
//!
//! The compiler enforces exhaustiveness, ensuring all task types are handled.

pub mod mitamae;
pub mod shell;

use std::borrow::Cow;
use std::fs;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use serde::Deserialize;
use tracing::info;

pub use mitamae::MitamaeTask;
pub use shell::ShellTask;

use crate::error::RsdebstrapError;
use crate::isolation::IsolationContext;

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

    /// Validates the script source.
    ///
    /// The `label` parameter is used in error messages to distinguish between
    /// different source types (e.g., "shell script", "mitamae recipe").
    pub fn validate(&self, label: &str) -> Result<(), RsdebstrapError> {
        match self {
            Self::Script(script) => {
                if script
                    .components()
                    .any(|c| c == camino::Utf8Component::ParentDir)
                {
                    return Err(RsdebstrapError::Validation(format!(
                        "{} path '{}' contains '..' components, \
                        which is not allowed for security reasons",
                        label, script
                    )));
                }
                let metadata = fs::metadata(script).map_err(|e| {
                    RsdebstrapError::io(format!("failed to read {} metadata: {}", label, script), e)
                })?;
                if !metadata.is_file() {
                    return Err(RsdebstrapError::Validation(format!(
                        "{} is not a file: {}",
                        label, script
                    )));
                }
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

/// Declarative task definition for pipeline steps.
///
/// Each variant holds the data needed to configure and execute a specific
/// type of task. The enum dispatch pattern provides compile-time exhaustive
/// matching — adding a new variant causes compilation errors at every
/// unhandled match site, preventing missed implementations.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TaskDefinition {
    /// Shell script execution task
    Shell(ShellTask),
    /// Mitamae recipe execution task
    Mitamae(MitamaeTask),
}

impl TaskDefinition {
    /// Returns a human-readable name for this task with type prefix.
    pub fn name(&self) -> Cow<'_, str> {
        match self {
            Self::Shell(task) => Cow::Owned(format!("shell:{}", task.name())),
            Self::Mitamae(task) => Cow::Owned(format!("mitamae:{}", task.name())),
        }
    }

    /// Validates the task configuration.
    pub fn validate(&self) -> Result<(), RsdebstrapError> {
        match self {
            Self::Shell(task) => task.validate(),
            Self::Mitamae(task) => task.validate(),
        }
    }

    /// Executes the task within the given isolation context.
    pub fn execute(&self, ctx: &dyn IsolationContext) -> Result<()> {
        match self {
            Self::Shell(task) => task.execute(ctx),
            Self::Mitamae(task) => task.execute(ctx),
        }
    }

    /// Returns the script path if this task uses an external script file.
    pub fn script_path(&self) -> Option<&Utf8Path> {
        match self {
            Self::Shell(task) => task.script_path(),
            Self::Mitamae(task) => task.script_path(),
        }
    }

    /// Resolves relative paths in this task relative to the given base directory.
    pub fn resolve_paths(&mut self, base_dir: &Utf8Path) {
        match self {
            Self::Shell(task) => task.resolve_paths(base_dir),
            Self::Mitamae(task) => task.resolve_paths(base_dir),
        }
    }

    /// Returns the binary path if this task uses an external binary.
    pub fn binary_path(&self) -> Option<&Utf8Path> {
        match self {
            Self::Shell(_) => None,
            Self::Mitamae(task) => task.binary(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
