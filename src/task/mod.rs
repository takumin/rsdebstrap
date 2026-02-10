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
//!    (`name`, `validate`, `execute`, `script_path`, `resolve_paths`, `binary_path`,
//!    `resolve_privilege`, `resolve_isolation`, `resolved_isolation_config`)
//!
//! The compiler enforces exhaustiveness, ensuring all task types are handled.

pub(crate) mod execution;
pub(crate) mod file_ops;
pub mod mitamae;
pub mod shell;
pub(crate) mod validation;

use std::borrow::Cow;

use camino::{Utf8Path, Utf8PathBuf};
use serde::Deserialize;

pub use mitamae::MitamaeTask;
pub use shell::ShellTask;

use crate::error::RsdebstrapError;
use crate::isolation::IsolationConfig;
use crate::isolation::IsolationContext;
use crate::privilege::PrivilegeDefaults;

// Re-export submodule items for convenient super:: access from shell.rs and mitamae.rs
pub(crate) use execution::execute_and_check;
#[cfg(unix)]
pub(crate) use file_ops::set_file_mode;
pub(crate) use file_ops::{TempFileGuard, prepare_files_with_toctou_check, prepare_source_file};
pub(crate) use validation::{
    validate_host_file_exists, validate_no_parent_dirs, validate_shell_in_rootfs,
    validate_tmp_directory,
};

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
    pub fn execute(&self, ctx: &dyn IsolationContext) -> anyhow::Result<()> {
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

    /// Resolves the privilege setting against profile defaults.
    pub fn resolve_privilege(
        &mut self,
        defaults: Option<&PrivilegeDefaults>,
    ) -> Result<(), RsdebstrapError> {
        match self {
            Self::Shell(task) => task.resolve_privilege(defaults),
            Self::Mitamae(task) => task.resolve_privilege(defaults),
        }
    }

    /// Resolves the isolation setting against profile defaults.
    pub fn resolve_isolation(&mut self, defaults: &IsolationConfig) {
        match self {
            Self::Shell(task) => task.resolve_isolation(defaults),
            Self::Mitamae(task) => task.resolve_isolation(defaults),
        }
    }

    /// Returns the resolved isolation config.
    ///
    /// Should only be called after [`resolve_isolation()`](Self::resolve_isolation).
    pub fn resolved_isolation_config(&self) -> Option<&IsolationConfig> {
        match self {
            Self::Shell(task) => task.resolved_isolation_config(),
            Self::Mitamae(task) => task.resolved_isolation_config(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use camino::Utf8PathBuf;

    use super::file_ops::TempFileGuard;

    #[cfg(unix)]
    mod check_execution_result_tests {
        use std::os::unix::process::ExitStatusExt;
        use std::process::ExitStatus;

        use crate::error::RsdebstrapError;
        use crate::executor::ExecutionResult;
        use crate::task::execution::check_execution_result;

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
