//! Shell task implementation.
//!
//! This module provides the `ShellTask` data structure and execution logic
//! for running shell scripts within an isolation context. It handles:
//! - Script source management (external files or inline content)
//! - Security validation (path traversal, symlink attacks, TOCTOU risk reduction)
//! - Script lifecycle (copy/write to rootfs, execute, cleanup via RAII guard)

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::Deserialize;
use std::borrow::Cow;
use std::fs;
use tracing::{debug, info};

use crate::error::RsdebstrapError;
use crate::isolation::{IsolationContext, TaskIsolation};
use crate::phase::{ScriptSource, StagedFileGuard};
use crate::privilege::{Privilege, PrivilegeMethod};

/// Shell task data and execution logic.
///
/// Represents a shell script to be executed within an isolation context.
/// Holds configuration data and provides methods for validation and execution.
/// Used as a variant in the `ProvisionTask` enum for compile-time dispatch.
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

    /// Privilege escalation setting as declared in the profile
    privilege: Privilege,

    /// Isolation setting as declared in the profile
    isolation: TaskIsolation,
}

fn default_shell() -> String {
    "/bin/sh".to_string()
}

// Wire shape of a shell task: one type drives both deserialization and schema
// generation, so the two cannot describe different shapes.
//
// Plain `//` (not `///`) so this note does not leak into the schema's `description`.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("oneOf" = crate::schema::script_or_content()))]
struct RawShellTask {
    #[schemars(with = "Option<crate::schema::Utf8PathSchema>")]
    script: Option<Utf8PathBuf>,
    content: Option<String>,
    #[serde(default = "default_shell")]
    shell: String,
    #[serde(default)]
    privilege: Privilege,
    #[serde(default)]
    isolation: TaskIsolation,
}

impl<'de> Deserialize<'de> for ShellTask {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawShellTask::deserialize(deserializer)?;
        let source = crate::phase::resolve_script_source::<D::Error>(raw.script, raw.content)?;
        Ok(ShellTask {
            source,
            shell: raw.shell,
            privilege: raw.privilege,
            isolation: raw.isolation,
        })
    }
}

impl JsonSchema for ShellTask {
    fn schema_name() -> Cow<'static, str> {
        "ShellTask".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        RawShellTask::json_schema(generator)
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
            privilege: Privilege::default(),
            isolation: TaskIsolation::default(),
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
            privilege: Privilege::default(),
            isolation: TaskIsolation::default(),
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
        self.source.resolve_paths(base_dir);
    }

    /// Returns the privilege setting as written in the profile.
    pub fn privilege(&self) -> &Privilege {
        &self.privilege
    }

    /// Returns the isolation setting as written in the profile.
    pub fn task_isolation(&self) -> &TaskIsolation {
        &self.isolation
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
    /// 3. Stages the script under rootfs /tmp through `RootfsOps`
    /// 4. Executes the script via the isolation context
    /// 5. Returns an error if the process fails or exits without status
    ///
    /// In dry-run mode, skips file I/O (rootfs validation, script copy/write,
    /// permission changes, cleanup) while still constructing and delegating
    /// commands to the executor.
    pub fn execute(
        &self,
        context: &dyn IsolationContext,
        privilege: Option<PrivilegeMethod>,
    ) -> Result<()> {
        let rootfs = context.rootfs();
        let dry_run = context.dry_run();

        if !dry_run {
            self.validate_rootfs(rootfs)
                .context("rootfs validation failed")?;
        }

        info!("running shell script: {} (isolation: {})", self.name(), context.name());
        debug!("rootfs: {}, shell: {}, dry_run: {}", rootfs, self.shell, dry_run);

        let script_name = format!("task-{}.sh", uuid::Uuid::new_v4());
        let script_path_in_isolation = format!("/tmp/{}", script_name);
        let staged = crate::rootfs::RelPath::parse(&script_path_in_isolation)?;
        let _guard = StagedFileGuard::new(context.rootfs_ops(), staged.clone(), dry_run);

        if !dry_run {
            crate::phase::stage_source_file(
                context.rootfs_ops(),
                &self.source,
                &staged,
                crate::rootfs::FileMode::new(0o700),
                "script",
            )?;
        }

        let command: Vec<String> = vec![self.shell.clone(), script_path_in_isolation];

        let result = crate::phase::execute_in_context(context, &command, "script", privilege)?;
        crate::phase::check_execution_result(&result, &command, context.name(), dry_run)?;

        info!("shell script completed successfully");
        Ok(())
    }

    /// Validates that the rootfs is ready for isolated command execution.
    fn validate_rootfs(&self, rootfs: &Utf8Path) -> Result<()> {
        crate::phase::validate_tmp_directory(rootfs)?;

        let shell_path = self.shell.trim_start_matches('/');
        crate::phase::validate_no_parent_dirs(camino::Utf8Path::new(shell_path), "shell")?;

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
