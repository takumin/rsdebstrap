//! Provision phase module for main provisioning tasks.
//!
//! This module provides the `ProvisionTask` enum — a data-driven abstraction
//! where each variant describes *what* to execute, and methods on the enum
//! provide *how* to execute via Rust's exhaustive pattern matching.
//!
//! Adding a new task type requires:
//! 1. Adding a new variant to `ProvisionTask`
//! 2. Creating a corresponding data struct (e.g., `MitamaeTask`)
//! 3. Implementing the match arms in all methods on `ProvisionTask`
//!    (`name`, `validate`, `execute`, `script_path`, `resolve_paths`, `binary_path`,
//!    `resolve_privilege`, `resolve_isolation`, `resolved_isolation_config`)
//!
//! The compiler enforces exhaustiveness, ensuring all task types are handled.

pub mod mitamae;
pub mod shell;

use std::borrow::Cow;

use camino::Utf8Path;
use serde::Deserialize;

pub use mitamae::MitamaeTask;
pub use shell::ShellTask;

use crate::config::IsolationConfig;
use crate::error::RsdebstrapError;
use crate::isolation::TaskIsolation;
use crate::phase::PhaseItem;
use crate::privilege::PrivilegeDefaults;

/// Declarative task definition for provision pipeline steps.
///
/// Each variant holds the data needed to configure and execute a specific
/// type of task. The enum dispatch pattern provides compile-time exhaustive
/// matching — adding a new variant causes compilation errors at every
/// unhandled match site, preventing missed implementations.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ProvisionTask {
    /// Shell script execution task
    Shell(ShellTask),
    /// Mitamae recipe execution task
    Mitamae(MitamaeTask),
}

impl PhaseItem for ProvisionTask {
    fn name(&self) -> Cow<'_, str> {
        ProvisionTask::name(self)
    }

    fn validate(&self) -> Result<(), RsdebstrapError> {
        match self {
            Self::Shell(task) => task.validate(),
            Self::Mitamae(task) => task.validate(),
        }
    }

    fn execute(&self, ctx: &dyn crate::isolation::IsolationContext) -> anyhow::Result<()> {
        match self {
            Self::Shell(task) => task.execute(ctx),
            Self::Mitamae(task) => task.execute(ctx),
        }
    }

    fn resolved_isolation_config(&self) -> Option<&IsolationConfig> {
        ProvisionTask::resolved_isolation_config(self)
    }
}

impl ProvisionTask {
    /// Returns the display name of this task (e.g., "shell:<inline>", "mitamae:recipe.rb").
    pub fn name(&self) -> Cow<'_, str> {
        match self {
            Self::Shell(task) => Cow::Owned(format!("shell:{}", task.name())),
            Self::Mitamae(task) => Cow::Owned(format!("mitamae:{}", task.name())),
        }
    }

    /// Returns the resolved isolation config after `resolve_isolation()` has been called.
    pub fn resolved_isolation_config(&self) -> Option<&IsolationConfig> {
        match self {
            Self::Shell(task) => task.resolved_isolation_config(),
            Self::Mitamae(task) => task.resolved_isolation_config(),
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

    /// Returns a reference to the task's isolation setting (possibly unresolved).
    pub fn task_isolation(&self) -> &TaskIsolation {
        match self {
            Self::Shell(task) => task.task_isolation(),
            Self::Mitamae(task) => task.task_isolation(),
        }
    }

    /// Resolves the isolation setting against profile defaults.
    pub fn resolve_isolation(&mut self, defaults: &IsolationConfig) {
        match self {
            Self::Shell(task) => task.resolve_isolation(defaults),
            Self::Mitamae(task) => task.resolve_isolation(defaults),
        }
    }
}
