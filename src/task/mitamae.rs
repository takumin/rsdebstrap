//! Mitamae task implementation.
//!
//! This module provides the `MitamaeTask` data structure and execution logic
//! for running mitamae recipes within an isolation context. It handles:
//! - Recipe source management (external files or inline content)
//! - Binary copying to rootfs /tmp with 0o700 permissions
//! - Security validation (path traversal, file existence)
//! - RAII cleanup of both binary and recipe temp files

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use serde::Deserialize;
use std::fs;
use tracing::{debug, info};

use super::{ScriptSource, TempFileGuard};
use crate::error::RsdebstrapError;
use crate::isolation::IsolationConfig;
use crate::isolation::{IsolationContext, TaskIsolation};
use crate::privilege::{Privilege, PrivilegeDefaults};

/// Mitamae task data and execution logic.
///
/// Represents a mitamae recipe to be executed within an isolation context.
/// The mitamae binary is copied from the host into the rootfs /tmp directory
/// before execution, and cleaned up afterwards via RAII guards.
///
/// ## Lifecycle
///
/// The typical lifecycle when loaded from a YAML profile is:
/// 1. **Deserialize** — construct from YAML via `serde`
///    (or [`new()`](Self::new) for programmatic use)
/// 2. [`resolve_paths()`](Self::resolve_paths) — resolve relative paths
/// 3. [`validate()`](Self::validate) — check binary and recipe existence
/// 4. [`execute()`](Self::execute) — run within an isolation context
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitamaeTask {
    /// Recipe source: either an external file path or inline content
    source: ScriptSource,
    /// Host-side mitamae binary path (None when relying on defaults)
    binary: Option<Utf8PathBuf>,
    /// Privilege escalation setting (resolved during defaults application)
    privilege: Privilege,
    /// Isolation setting (resolved during defaults application)
    isolation: TaskIsolation,
}

impl<'de> Deserialize<'de> for MitamaeTask {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawMitamaeTask {
            script: Option<Utf8PathBuf>,
            content: Option<String>,
            binary: Option<Utf8PathBuf>,
            #[serde(default)]
            privilege: Privilege,
            #[serde(default)]
            isolation: TaskIsolation,
        }

        let raw = RawMitamaeTask::deserialize(deserializer)?;
        let source = super::resolve_script_source::<D::Error>(raw.script, raw.content)?;
        Ok(MitamaeTask {
            source,
            binary: raw.binary,
            privilege: raw.privilege,
            isolation: raw.isolation,
        })
    }
}

impl MitamaeTask {
    /// Creates a new MitamaeTask with the given recipe source and binary path.
    pub fn new(source: ScriptSource, binary: Utf8PathBuf) -> Self {
        Self {
            source,
            binary: Some(binary),
            privilege: Privilege::default(),
            isolation: TaskIsolation::default(),
        }
    }

    /// Creates a new MitamaeTask without a binary path (expects defaults to provide it).
    pub fn new_without_binary(source: ScriptSource) -> Self {
        Self {
            source,
            binary: None,
            privilege: Privilege::default(),
            isolation: TaskIsolation::default(),
        }
    }

    /// Returns a reference to the recipe source.
    pub fn source(&self) -> &ScriptSource {
        &self.source
    }

    /// Returns the mitamae binary path, if set.
    pub fn binary(&self) -> Option<&Utf8Path> {
        self.binary.as_deref()
    }

    /// Sets the mitamae binary path if not already set (used for applying defaults).
    /// Does nothing if binary is already set (task-level takes precedence).
    pub fn set_binary_if_absent(&mut self, binary: &Utf8Path) {
        if self.binary.is_none() {
            self.binary = Some(binary.to_path_buf());
        }
    }

    /// Returns a human-readable name for this task (without type prefix).
    pub fn name(&self) -> &str {
        self.source.name()
    }

    /// Returns the script path if this task uses an external recipe file.
    pub fn script_path(&self) -> Option<&Utf8Path> {
        self.source.script_path()
    }

    /// Resolves relative paths in this task relative to the given base directory.
    pub fn resolve_paths(&mut self, base_dir: &Utf8Path) {
        if let Some(ref mut binary) = self.binary
            && binary.is_relative()
        {
            *binary = base_dir.join(&*binary);
        }
        self.source.resolve_paths(base_dir);
    }

    /// Resolves the privilege setting against profile defaults.
    ///
    /// # Errors
    ///
    /// Returns `RsdebstrapError::Validation` if `privilege: true` is specified
    /// but no `defaults.privilege.method` is configured in the profile.
    pub fn resolve_privilege(
        &mut self,
        defaults: Option<&PrivilegeDefaults>,
    ) -> Result<(), RsdebstrapError> {
        self.privilege.resolve_in_place(defaults)
    }

    /// Resolves the isolation setting against profile defaults.
    pub fn resolve_isolation(&mut self, defaults: &IsolationConfig) {
        self.isolation.resolve_in_place(defaults);
    }

    /// Returns the resolved isolation config.
    ///
    /// Should only be called after [`resolve_isolation()`](Self::resolve_isolation).
    pub fn resolved_isolation_config(&self) -> Option<&IsolationConfig> {
        self.isolation.resolved_config()
    }

    /// Validates the task configuration.
    ///
    /// Checks:
    /// - Binary path is set and non-empty with no `..` components
    /// - Binary file exists and is a regular file
    /// - Recipe: Script → no path traversal, exists, is a regular file; Content → non-empty
    pub fn validate(&self) -> Result<(), RsdebstrapError> {
        let binary = match &self.binary {
            Some(b) => b,
            None => {
                return Err(RsdebstrapError::Validation(format!(
                    "mitamae binary path is not specified and no default is configured \
                    for architecture '{}'. Either add 'binary: /path/to/mitamae' to the \
                    task definition or configure 'defaults.mitamae.binary.{}' in the profile",
                    std::env::consts::ARCH,
                    std::env::consts::ARCH,
                )));
            }
        };

        if binary.as_str().is_empty() {
            return Err(RsdebstrapError::Validation(
                "mitamae binary path must not be empty".to_string(),
            ));
        }

        super::validate_no_parent_dirs(binary, "mitamae binary")?;
        super::validate_host_file_exists(binary, "mitamae binary")?;

        // Validate recipe source
        self.source.validate("mitamae recipe")
    }

    /// Executes the mitamae recipe using the provided isolation context.
    ///
    /// This method:
    /// 1. Validates /tmp in rootfs (unless dry_run)
    /// 2. Sets up RAII guards for cleanup of temp files
    /// 3. Re-validates /tmp to mitigate TOCTOU race conditions (unless dry_run)
    /// 4. Copies mitamae binary to rootfs /tmp with 0o700 permissions
    /// 5. Copies or writes the recipe to rootfs /tmp with 0o600 permissions
    /// 6. Executes `mitamae local <recipe>` via the isolation context
    /// 7. Returns an error if the process fails or exits without status
    pub fn execute(&self, context: &dyn IsolationContext) -> Result<()> {
        let rootfs = context.rootfs();
        let dry_run = context.dry_run();

        let binary = self.binary.as_ref().ok_or_else(|| {
            RsdebstrapError::Validation("mitamae binary path not set".to_string())
        })?;

        // Unlike ShellTask, no validate_rootfs() is needed here because the mitamae
        // binary is copied from the host side — there is no rootfs-resident binary
        // to verify. Only /tmp validation is required for the copy destination.
        if !dry_run {
            super::validate_tmp_directory(rootfs).context("rootfs validation failed")?;
        }

        info!("running mitamae recipe: {} (isolation: {})", self.name(), context.name());
        debug!("rootfs: {}, binary: {}, dry_run: {}", rootfs, binary, dry_run);

        let uuid = uuid::Uuid::new_v4();
        let binary_name = format!("mitamae-{}", uuid);
        let recipe_name = format!("recipe-{}.rb", uuid);
        let target_binary = rootfs.join("tmp").join(&binary_name);
        let target_recipe = rootfs.join("tmp").join(&recipe_name);

        let _binary_guard = TempFileGuard::new(target_binary.clone(), dry_run);
        let _recipe_guard = TempFileGuard::new(target_recipe.clone(), dry_run);

        super::prepare_files_with_toctou_check(rootfs, dry_run, || {
            info!("copying mitamae binary from {} to rootfs", binary);
            fs::copy(binary, &target_binary).with_context(|| {
                format!("failed to copy mitamae binary {} to {}", binary, target_binary)
            })?;
            #[cfg(unix)]
            super::set_file_mode(&target_binary, 0o700)?;
            super::prepare_source_file(&self.source, &target_recipe, 0o600, "recipe")
        })?;

        let binary_path_in_isolation = format!("/tmp/{}", binary_name);
        let recipe_path_in_isolation = format!("/tmp/{}", recipe_name);
        let command: Vec<String> = vec![
            binary_path_in_isolation,
            "local".to_string(),
            recipe_path_in_isolation,
        ];

        super::execute_and_check(context, &command, "mitamae", self.privilege.resolved_method())?;

        info!("mitamae recipe completed successfully");
        Ok(())
    }
}
