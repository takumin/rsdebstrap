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
use serde::de::{self, MapAccess, Visitor};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use tracing::{debug, info};

use super::{ScriptSource, TempFileGuard};
use crate::error::RsdebstrapError;
use crate::isolation::IsolationContext;

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
    /// Host-side mitamae binary path
    binary: Utf8PathBuf,
}

impl<'de> Deserialize<'de> for MitamaeTask {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Script,
            Content,
            Binary,
        }

        struct MitamaeTaskVisitor;

        impl<'de> Visitor<'de> for MitamaeTaskVisitor {
            type Value = MitamaeTask;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a mitamae task with 'binary' and either 'script' or 'content'")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<MitamaeTask, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut script: Option<Utf8PathBuf> = None;
                let mut content: Option<String> = None;
                let mut binary: Option<Utf8PathBuf> = None;

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
                        Field::Binary => {
                            if binary.is_some() {
                                return Err(de::Error::duplicate_field("binary"));
                            }
                            binary = Some(map.next_value()?);
                        }
                    }
                }

                let binary = binary.ok_or_else(|| de::Error::missing_field("binary"))?;

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

                Ok(MitamaeTask { source, binary })
            }
        }

        const FIELDS: &[&str] = &["script", "content", "binary"];
        deserializer.deserialize_struct("MitamaeTask", FIELDS, MitamaeTaskVisitor)
    }
}

impl MitamaeTask {
    /// Creates a new MitamaeTask with the given recipe source and binary path.
    pub fn new(source: ScriptSource, binary: Utf8PathBuf) -> Self {
        Self { source, binary }
    }

    /// Returns a reference to the recipe source.
    pub fn source(&self) -> &ScriptSource {
        &self.source
    }

    /// Returns the mitamae binary path.
    pub fn binary(&self) -> &Utf8Path {
        &self.binary
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
        if self.binary.is_relative() {
            self.binary = base_dir.join(&self.binary);
        }
        if let ScriptSource::Script(path) = &mut self.source
            && path.is_relative()
        {
            *path = base_dir.join(&*path);
        }
    }

    /// Validates the task configuration.
    ///
    /// Checks:
    /// - Binary path is non-empty and has no `..` components
    /// - Binary file exists and is a regular file
    /// - Recipe: Script → no path traversal, exists, is a regular file; Content → non-empty
    pub fn validate(&self) -> Result<(), RsdebstrapError> {
        // Validate binary path
        if self.binary.as_str().is_empty() {
            return Err(RsdebstrapError::Validation(
                "mitamae binary path must not be empty".to_string(),
            ));
        }

        if self
            .binary
            .components()
            .any(|c| c == camino::Utf8Component::ParentDir)
        {
            return Err(RsdebstrapError::Validation(format!(
                "mitamae binary path '{}' contains '..' components, \
                which is not allowed for security reasons",
                self.binary
            )));
        }

        let metadata = fs::metadata(&self.binary).map_err(|e| {
            RsdebstrapError::io(
                format!("failed to read mitamae binary metadata: {}", self.binary),
                e,
            )
        })?;
        if !metadata.is_file() {
            return Err(RsdebstrapError::Validation(format!(
                "mitamae binary is not a file: {}",
                self.binary
            )));
        }

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

        // Unlike ShellTask, no validate_rootfs() is needed here because the mitamae
        // binary is copied from the host side — there is no rootfs-resident binary
        // to verify. Only /tmp validation is required for the copy destination.
        if !dry_run {
            super::validate_tmp_directory(rootfs).context("rootfs validation failed")?;
        }

        info!("running mitamae recipe: {} (isolation: {})", self.name(), context.name());
        debug!("rootfs: {}, binary: {}, dry_run: {}", rootfs, self.binary, dry_run);

        // Generate unique names for binary and recipe in rootfs
        let uuid = uuid::Uuid::new_v4();
        let binary_name = format!("mitamae-{}", uuid);
        let recipe_name = format!("recipe-{}.rb", uuid);
        let target_binary = rootfs.join("tmp").join(&binary_name);
        let target_recipe = rootfs.join("tmp").join(&recipe_name);

        // RAII guards ensure cleanup even on error
        let _binary_guard = TempFileGuard::new(target_binary.clone(), dry_run);
        let _recipe_guard = TempFileGuard::new(target_recipe.clone(), dry_run);

        if !dry_run {
            // Re-validate /tmp immediately before use to mitigate TOCTOU race conditions
            super::validate_tmp_directory(rootfs)
                .context("TOCTOU check: /tmp validation failed before writing files")?;

            // Copy mitamae binary to rootfs
            info!("copying mitamae binary from {} to rootfs", self.binary);
            fs::copy(&self.binary, &target_binary).with_context(|| {
                format!("failed to copy mitamae binary {} to {}", self.binary, target_binary)
            })?;

            #[cfg(unix)]
            super::set_file_mode(&target_binary, 0o700)?;

            // Copy or write recipe to rootfs (0o600: recipe is a data file, not executable)
            super::prepare_source_file(&self.source, &target_recipe, 0o600, "recipe")?;
        }

        // Execute mitamae using the configured isolation backend
        let binary_path_in_isolation = format!("/tmp/{}", binary_name);
        let recipe_path_in_isolation = format!("/tmp/{}", recipe_name);
        let command: Vec<OsString> = vec![
            binary_path_in_isolation.into(),
            "local".into(),
            recipe_path_in_isolation.into(),
        ];

        let result =
            context
                .execute(&command)
                .map_err(|e| match e.downcast::<RsdebstrapError>() {
                    Ok(typed) => typed.into(),
                    Err(e) => e.context("failed to execute mitamae"),
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

        info!("mitamae recipe completed successfully");
        Ok(())
    }
}
