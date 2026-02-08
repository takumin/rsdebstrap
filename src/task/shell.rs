//! Shell task implementation.
//!
//! This module provides the `ShellTask` data structure and execution logic
//! for running shell scripts within an isolation context. It handles:
//! - Script source management (external files or inline content)
//! - Security validation (path traversal, symlink attacks, TOCTOU risk reduction)
//! - Script lifecycle (copy/write to rootfs, execute, cleanup via RAII guard)

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use serde::Deserialize;
use serde::de::{self, MapAccess, Visitor};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use tracing::{debug, info};

use super::{ScriptSource, TempFileGuard};
use crate::error::RsdebstrapError;
use crate::isolation::IsolationContext;

/// Shell task data and execution logic.
///
/// Represents a shell script to be executed within an isolation context.
/// Holds configuration data and provides methods for validation and execution.
/// Used as a variant in the `TaskDefinition` enum for compile-time dispatch.
///
/// ## Lifecycle
///
/// The typical lifecycle when loaded from a YAML profile is:
/// 1. **Deserialize** — construct from YAML via `serde`
///    (or [`new()`](Self::new) for programmatic use)
/// 2. [`resolve_paths()`](Self::resolve_paths) — resolve relative script paths
/// 3. [`validate()`](Self::validate) — check script existence and configuration
/// 4. [`execute()`](Self::execute) — run within an isolation context
///
/// Deserialization validates that exactly one of `script` or `content` is
/// specified, rejecting YAML that provides both or neither.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellTask {
    /// Script source: either an external file path or inline content
    source: ScriptSource,

    /// Shell interpreter to use (default: /bin/sh)
    shell: String,
}

fn default_shell() -> String {
    "/bin/sh".to_string()
}

impl<'de> Deserialize<'de> for ShellTask {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Script,
            Content,
            Shell,
        }

        struct ShellTaskVisitor;

        impl<'de> Visitor<'de> for ShellTaskVisitor {
            type Value = ShellTask;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a shell task with either 'script' or 'content'")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<ShellTask, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut script: Option<Utf8PathBuf> = None;
                let mut content: Option<String> = None;
                let mut shell: Option<String> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Script => {
                            if script.is_some() {
                                return Err(de::Error::duplicate_field("script"));
                            }
                            script = Some(map.next_value()?);
                        }
                        Field::Content => {
                            if content.is_some() {
                                return Err(de::Error::duplicate_field("content"));
                            }
                            content = Some(map.next_value()?);
                        }
                        Field::Shell => {
                            if shell.is_some() {
                                return Err(de::Error::duplicate_field("shell"));
                            }
                            shell = Some(map.next_value()?);
                        }
                    }
                }

                let source = match (script, content) {
                    (Some(_), Some(_)) => {
                        return Err(de::Error::custom(
                            "'script' and 'content' are mutually exclusive",
                        ));
                    }
                    (None, None) => {
                        return Err(de::Error::custom(
                            "either 'script' or 'content' must be specified",
                        ));
                    }
                    (Some(s), None) => ScriptSource::Script(s),
                    (None, Some(c)) => ScriptSource::Content(c),
                };

                Ok(ShellTask {
                    source,
                    shell: shell.unwrap_or_else(default_shell),
                })
            }
        }

        const FIELDS: &[&str] = &["script", "content", "shell"];
        deserializer.deserialize_struct("ShellTask", FIELDS, ShellTaskVisitor)
    }
}

impl ShellTask {
    /// Creates a new ShellTask with the given script source and default shell (/bin/sh).
    ///
    /// Note: Call [`validate()`](Self::validate) after construction to check
    /// that the source is valid (e.g., non-empty content).
    pub fn new(source: ScriptSource) -> Self {
        Self {
            source,
            shell: default_shell(),
        }
    }

    /// Creates a new ShellTask with the given script source and custom shell.
    ///
    /// Note: Call [`validate()`](Self::validate) after construction to check
    /// that the shell path and source are valid.
    pub fn with_shell(source: ScriptSource, shell: impl Into<String>) -> Self {
        Self {
            source,
            shell: shell.into(),
        }
    }

    /// Returns a reference to the script source.
    pub fn source(&self) -> &ScriptSource {
        &self.source
    }

    /// Returns the shell interpreter path.
    pub fn shell(&self) -> &str {
        &self.shell
    }

    /// Returns a human-readable name for this task (without type prefix).
    pub fn name(&self) -> &str {
        self.source.name()
    }

    /// Returns the script path if this task uses an external script file.
    pub fn script_path(&self) -> Option<&Utf8Path> {
        self.source.script_path()
    }

    /// Resolves relative paths in this task relative to the given base directory.
    pub fn resolve_paths(&mut self, base_dir: &Utf8Path) {
        if let ScriptSource::Script(path) = &mut self.source
            && path.is_relative()
        {
            *path = base_dir.join(&*path);
        }
    }

    /// Validates the task configuration.
    ///
    /// Checks that the shell path is non-empty and absolute, then validates
    /// the script source:
    /// - For external script files: rejects path traversal (`..` components),
    ///   validates that the file exists and is a regular file.
    /// - For inline content: validates that the content is not empty or whitespace-only.
    ///
    /// # Errors
    ///
    /// Returns `RsdebstrapError::Validation` for constraint violations (empty shell,
    /// relative shell path, path traversal, non-file script, empty or whitespace-only
    /// content) or `RsdebstrapError::Io` if the script file cannot be accessed.
    pub fn validate(&self) -> Result<(), RsdebstrapError> {
        if self.shell.is_empty() {
            return Err(RsdebstrapError::Validation("shell path must not be empty".to_string()));
        }
        if !self.shell.starts_with('/') {
            return Err(RsdebstrapError::Validation(format!(
                "shell path must be absolute (start with '/'): {}",
                self.shell
            )));
        }

        self.source.validate("shell script")
    }

    /// Executes the shell script using the provided isolation context.
    ///
    /// Callers should invoke [`validate()`](Self::validate) before this method
    /// to ensure the task configuration is valid (e.g., script file exists).
    ///
    /// This method:
    /// 1. Validates the rootfs (unless dry_run)
    /// 2. Sets up an RAII guard for cleanup of the temp script file
    /// 3. Re-validates /tmp to mitigate TOCTOU race conditions (unless dry_run)
    /// 4. Copies or writes the script to rootfs /tmp
    /// 5. Executes the script via the isolation context
    /// 6. Returns an error if the process fails or exits without status
    ///
    /// In dry-run mode, skips file I/O (rootfs validation, script copy/write,
    /// permission changes, cleanup) while still constructing and delegating
    /// commands to the executor.
    pub fn execute(&self, context: &dyn IsolationContext) -> Result<()> {
        let rootfs = context.rootfs();
        let dry_run = context.dry_run();

        if !dry_run {
            self.validate_rootfs(rootfs)
                .context("rootfs validation failed")?;
        }

        info!("running shell script: {} (isolation: {})", self.name(), context.name());
        debug!("rootfs: {}, shell: {}, dry_run: {}", rootfs, self.shell, dry_run);

        // Generate unique script name in rootfs
        let script_name = format!("task-{}.sh", uuid::Uuid::new_v4());
        let target_script = rootfs.join("tmp").join(&script_name);

        // RAII guard ensures cleanup even on error
        let _guard = TempFileGuard::new(target_script.clone(), dry_run);

        if !dry_run {
            // Re-validate /tmp immediately before use to mitigate TOCTOU race conditions
            super::validate_tmp_directory(rootfs)
                .context("TOCTOU check: /tmp validation failed before writing script")?;

            super::prepare_source_file(&self.source, &target_script, 0o700, "script")?;
        }

        // Execute script using the configured isolation backend
        let script_path_in_isolation = format!("/tmp/{}", script_name);
        let command: Vec<OsString> =
            vec![self.shell.as_str().into(), script_path_in_isolation.into()];

        let result =
            context
                .execute(&command)
                .map_err(|e| match e.downcast::<RsdebstrapError>() {
                    Ok(typed) => typed.into(),
                    Err(e) => e.context("failed to execute script"),
                })?;

        if !result.success() {
            let status_display = result
                .status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown (no status available)".to_string());
            return Err(RsdebstrapError::execution_in_isolation(
                &command,
                context.name(),
                status_display,
            )
            .into());
        } else if !dry_run && result.status.is_none() {
            return Err(RsdebstrapError::execution_in_isolation(
                &command,
                context.name(),
                "process exited without status (possibly killed by signal)",
            )
            .into());
        }

        info!("shell script completed successfully");
        Ok(())
    }

    /// Validates that the rootfs is ready for isolated command execution.
    fn validate_rootfs(&self, rootfs: &Utf8Path) -> Result<()> {
        super::validate_tmp_directory(rootfs)?;

        // Validate shell path to prevent path traversal attacks
        let shell_path = self.shell.trim_start_matches('/');
        if camino::Utf8Path::new(shell_path)
            .components()
            .any(|c| c == camino::Utf8Component::ParentDir)
        {
            return Err(RsdebstrapError::Validation(format!(
                "shell path '{}' contains '..' components, \
                which is not allowed for security reasons",
                self.shell
            ))
            .into());
        }

        // Check if the specified shell exists and is a file in rootfs
        let shell_in_rootfs = rootfs.join(shell_path);
        let metadata = match fs::metadata(&shell_in_rootfs) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(RsdebstrapError::Validation(format!(
                    "shell '{}' does not exist in rootfs at {}",
                    self.shell, shell_in_rootfs
                ))
                .into());
            }
            Err(e) => {
                return Err(RsdebstrapError::io(
                    format!(
                        "failed to read shell metadata for '{}' at {}",
                        self.shell, shell_in_rootfs
                    ),
                    e,
                )
                .into());
            }
        };

        if metadata.is_dir() {
            return Err(RsdebstrapError::Validation(format!(
                "shell path '{}' points to a directory, not a file: {}",
                self.shell, shell_in_rootfs
            ))
            .into());
        }

        if !metadata.is_file() {
            return Err(RsdebstrapError::Validation(format!(
                "shell '{}' is not a regular file in rootfs at {}",
                self.shell, shell_in_rootfs
            ))
            .into());
        }

        Ok(())
    }
}
