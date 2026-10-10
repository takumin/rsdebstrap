//! Mitamae task implementation.
//!
//! This module provides the `MitamaeTask` data structure and execution logic
//! for running mitamae recipes within an isolation context. It handles:
//! - Recipe source management (external files or inline content)
//! - Binary copying to rootfs /tmp with 0o700 permissions
//! - Plugin staging: each plugin's `mrblib` tree, passed to mitamae as `--plugins`
//!   (see [`plugin`])
//! - Security validation (path traversal, file existence)
//! - RAII cleanup of the binary, the recipe and the plugin tree

pub mod plugin;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::Deserialize;
use std::borrow::Cow;
use tracing::{debug, info};

use crate::condition::Condition;
use crate::error::RsdebstrapError;
use crate::isolation::{IsolationContext, TaskIsolation};
use crate::phase::{ScriptSource, StagedDirGuard, StagedFileGuard};
use crate::privilege::{Privilege, PrivilegeMethod};
pub use plugin::{MitamaePlugin, MitamaePluginSource};

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
    /// Plugins as declared on the task (None when relying on defaults)
    plugins: Option<Vec<MitamaePlugin>>,
    /// Privilege escalation setting as declared in the profile
    privilege: Privilege,
    /// Isolation setting as declared in the profile
    isolation: TaskIsolation,
    /// Condition under which the task runs, as declared in the profile
    when: Option<Condition>,
}

// Wire shape of a mitamae task: one type drives both deserialization and schema
// generation, so the two cannot describe different shapes.
//
// Plain `//` (not `///`) so this note does not leak into the schema's `description`.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("oneOf" = crate::schema::script_or_content()))]
struct RawMitamaeTask {
    #[schemars(with = "Option<crate::schema::Utf8PathSchema>")]
    script: Option<Utf8PathBuf>,
    content: Option<String>,
    #[schemars(with = "Option<crate::schema::Utf8PathSchema>")]
    binary: Option<Utf8PathBuf>,
    /// mitamae plugins for this task, replacing `defaults.mitamae.plugins`; `[]` runs the
    /// task with none.
    plugins: Option<Vec<MitamaePlugin>>,
    #[serde(default)]
    privilege: Privilege,
    #[serde(default)]
    isolation: TaskIsolation,
    /// CEL expression over the profile's variables (`vars.<name>`); the task runs only
    /// when it evaluates to `true`, e.g. `vars.suite == 'trixie'`.
    when: Option<Condition>,
}

impl<'de> Deserialize<'de> for MitamaeTask {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawMitamaeTask::deserialize(deserializer)?;
        let source = crate::phase::resolve_script_source::<D::Error>(raw.script, raw.content)?;
        Ok(MitamaeTask {
            source,
            binary: raw.binary,
            plugins: raw.plugins,
            privilege: raw.privilege,
            isolation: raw.isolation,
            when: raw.when,
        })
    }
}

impl JsonSchema for MitamaeTask {
    fn schema_name() -> Cow<'static, str> {
        "MitamaeTask".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        RawMitamaeTask::json_schema(generator)
    }
}

impl MitamaeTask {
    /// Creates a new MitamaeTask with the given recipe source and binary path.
    pub fn new(source: ScriptSource, binary: Utf8PathBuf) -> Self {
        Self {
            source,
            binary: Some(binary),
            plugins: None,
            privilege: Privilege::default(),
            isolation: TaskIsolation::default(),
            when: None,
        }
    }

    /// Creates a new MitamaeTask without a binary path (expects defaults to provide it).
    pub fn new_without_binary(source: ScriptSource) -> Self {
        Self {
            source,
            binary: None,
            plugins: None,
            privilege: Privilege::default(),
            isolation: TaskIsolation::default(),
            when: None,
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

    /// Sets the mitamae plugins.
    pub fn with_plugins(mut self, plugins: Vec<MitamaePlugin>) -> Self {
        self.plugins = Some(plugins);
        self
    }

    /// Returns the mitamae plugins, if set.
    pub fn plugins(&self) -> Option<&[MitamaePlugin]> {
        self.plugins.as_deref()
    }

    /// Sets the plugins if not already set (used for applying defaults).
    /// Does nothing if they are already set, even to none (task-level takes precedence).
    pub fn set_plugins_if_absent(&mut self, plugins: &[MitamaePlugin]) {
        if self.plugins.is_none() {
            self.plugins = Some(plugins.to_vec());
        }
    }

    fn active_plugins(&self) -> &[MitamaePlugin] {
        self.plugins.as_deref().unwrap_or_default()
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
        for plugin in self.plugins.iter_mut().flatten() {
            plugin.resolve_paths(base_dir);
        }
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

    /// Returns the `when:` condition as written in the profile.
    pub fn when(&self) -> Option<&Condition> {
        self.when.as_ref()
    }

    /// Validates the task configuration.
    ///
    /// Checks:
    /// - Binary path is set and non-empty with no `..` components
    /// - Binary file exists and is a regular file
    /// - Plugins: each declaration, unique names, and that each reads or fetches
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

        crate::phase::validate_no_parent_dirs(binary, "mitamae binary")?;
        crate::phase::validate_host_file_exists(binary, "mitamae binary")?;

        plugin::validate_plugins(self.active_plugins())?;

        self.source.validate("mitamae recipe")
    }

    /// Executes the mitamae recipe using the provided isolation context.
    ///
    /// This method:
    /// 1. Validates /tmp in rootfs (unless dry_run)
    /// 2. Sets up RAII guards for cleanup of temp files
    /// 3. Stages the mitamae binary (0o700), recipe (0o600) and plugins (directories
    ///    0o700, files 0o600) through `RootfsOps`
    /// 4. Executes `mitamae local [--plugins=<dir>] <recipe>` via the isolation context
    /// 5. Returns an error if the process fails or exits without status
    pub fn execute(
        &self,
        context: &dyn IsolationContext,
        privilege: Option<PrivilegeMethod>,
    ) -> Result<()> {
        let rootfs = context.rootfs();
        let dry_run = context.dry_run();

        // `validate` has a written-out error for this and is the only thing that fills the
        // field in from `defaults.mitamae.binary`. Reached without it -- `execute` is `pub`
        // -- an unwrap would abort the process over a value that is `Option` precisely
        // because a profile may not have named one.
        let binary = self.binary.as_ref().ok_or_else(|| {
            self.validate()
                .expect_err("binary is None, which validate refuses")
        })?;

        // Unlike ShellTask, no validate_rootfs() is needed here because the mitamae
        // binary is copied from the host side — there is no rootfs-resident binary
        // to verify. Only /tmp validation is required for the copy destination.
        if !dry_run {
            crate::phase::validate_tmp_directory(rootfs).context("rootfs validation failed")?;
        }

        info!("running mitamae recipe: {} (isolation: {})", self.name(), context.name());
        debug!("rootfs: {}, binary: {}, dry_run: {}", rootfs, binary, dry_run);

        let uuid = uuid::Uuid::new_v4();
        let binary_name = format!("mitamae-{}", uuid);
        let recipe_name = format!("recipe-{}.rb", uuid);
        let binary_path_in_isolation = format!("/tmp/{}", binary_name);
        let recipe_path_in_isolation = format!("/tmp/{}", recipe_name);
        let staged_binary = crate::rootfs::RelPath::parse(&binary_path_in_isolation)?;
        let staged_recipe = crate::rootfs::RelPath::parse(&recipe_path_in_isolation)?;

        let plugins_path_in_isolation = format!("/tmp/mitamae-plugins-{}", uuid);
        let staged_plugins = crate::rootfs::RelPath::parse(&plugins_path_in_isolation)?;

        let ops = context.rootfs_ops();
        let _binary_guard = StagedFileGuard::new(ops, staged_binary.clone(), dry_run);
        let _recipe_guard = StagedFileGuard::new(ops, staged_recipe.clone(), dry_run);
        let plugins = self.active_plugins();
        let _plugins_guard = (!plugins.is_empty())
            .then(|| StagedDirGuard::new(ops, staged_plugins.clone(), dry_run));

        if !dry_run {
            crate::phase::stage_host_file(
                ops,
                binary,
                &staged_binary,
                crate::rootfs::FileMode::new(0o700),
                "mitamae binary",
            )?;
            crate::phase::stage_source_file(
                ops,
                &self.source,
                &staged_recipe,
                crate::rootfs::FileMode::new(0o600),
                "recipe",
            )?;
            if !plugins.is_empty() {
                plugin::stage_plugins(ops, plugins, &staged_plugins)?;
            }
        }
        let mut command: Vec<String> = vec![binary_path_in_isolation, "local".to_string()];
        if !plugins.is_empty() {
            command.push(format!("--plugins={}", plugins_path_in_isolation));
        }
        command.push(recipe_path_in_isolation);

        let result = crate::phase::execute_in_context(context, &command, "mitamae", privilege)?;
        crate::phase::check_execution_result(&result, &command, context.name(), dry_run)?;

        info!("mitamae recipe completed successfully");
        Ok(())
    }
}
