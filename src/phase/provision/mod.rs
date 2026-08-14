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
//!    `privilege`, `task_isolation`)
//!
//! The compiler enforces exhaustiveness, ensuring all task types are handled.

pub mod mitamae;
pub mod shell;

use std::borrow::Cow;

use camino::Utf8Path;
use schemars::JsonSchema;
use serde::Deserialize;

pub use mitamae::MitamaeTask;
pub use shell::ShellTask;

use crate::config::IsolationConfig;
use crate::error::RsdebstrapError;
use crate::isolation::TaskIsolation;
use crate::phase::{PhaseItem, ProvisionItem};
use crate::privilege::{Privilege, PrivilegeDefaults, PrivilegeMethod};

/// Declarative task definition for provision pipeline steps.
///
/// Each variant holds the data needed to configure and execute a specific
/// type of task. The enum dispatch pattern provides compile-time exhaustive
/// matching — adding a new variant causes compilation errors at every
/// unhandled match site, preventing missed implementations.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
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
}

/// A provision task paired with the settings it resolves to under the profile defaults.
///
/// [`ProvisionTask`] carries what the profile *declared*; the pipeline needs what that
/// declaration means once defaults are known. They are separate types so that an
/// unresolved setting cannot be read as if it were resolved: resolution produces a new
/// value rather than putting the task into a second state.
#[derive(Debug)]
pub struct ResolvedProvisionTask<'a> {
    task: &'a ProvisionTask,
    privilege: Option<PrivilegeMethod>,
    isolation: Option<IsolationConfig>,
}

impl PhaseItem for ResolvedProvisionTask<'_> {
    fn name(&self) -> Cow<'_, str> {
        self.task.name()
    }

    fn validate(&self) -> Result<(), RsdebstrapError> {
        PhaseItem::validate(self.task)
    }
}

impl ProvisionItem for ResolvedProvisionTask<'_> {
    fn execute(&self, ctx: &dyn crate::isolation::IsolationContext) -> anyhow::Result<()> {
        self.task.execute(ctx, self.privilege)
    }

    fn resolved_isolation_config(&self) -> Option<&IsolationConfig> {
        self.isolation.as_ref()
    }
}

impl ProvisionTask {
    /// Returns the display name of this task (e.g., `shell:<inline>`, `mitamae:recipe.rb`).
    pub fn name(&self) -> Cow<'_, str> {
        match self {
            Self::Shell(task) => Cow::Owned(format!("shell:{}", task.name())),
            Self::Mitamae(task) => Cow::Owned(format!("mitamae:{}", task.name())),
        }
    }

    /// Resolves this task's privilege and isolation settings against the profile defaults.
    ///
    /// # Errors
    ///
    /// Returns `RsdebstrapError::Validation` if `privilege: true` is declared but no
    /// `defaults.privilege.method` is configured, or if the task resolves to escalated
    /// execution without isolation.
    pub fn resolve(
        &self,
        privilege_defaults: Option<&PrivilegeDefaults>,
        isolation_defaults: &IsolationConfig,
    ) -> Result<ResolvedProvisionTask<'_>, RsdebstrapError> {
        let privilege = self.privilege().resolve(privilege_defaults)?;
        let isolation = self.task_isolation().resolve(isolation_defaults);

        // `isolation: false` runs the program the task names *from inside the rootfs*
        // directly on the host. Escalating that hands root to whatever the rootfs happens
        // to contain — a rootfs this run has not finished building and whose packages ran
        // their own maintainer scripts. The two settings are individually reasonable and
        // only their combination is not, so it is rejected here rather than by either.
        if isolation.is_none()
            && let Some(method) = privilege
        {
            return Err(RsdebstrapError::Validation(format!(
                "task '{}' declares `isolation: false` but resolves to `privilege: {}`; \
                running a program from inside the rootfs on the host as root is not \
                allowed. Set `privilege: false` on the task, or drop `isolation: false`.",
                self.name(),
                method,
            )));
        }

        Ok(ResolvedProvisionTask {
            task: self,
            privilege,
            isolation,
        })
    }

    /// Executes this task with an already-resolved privilege setting.
    fn execute(
        &self,
        ctx: &dyn crate::isolation::IsolationContext,
        privilege: Option<PrivilegeMethod>,
    ) -> anyhow::Result<()> {
        match self {
            Self::Shell(task) => task.execute(ctx, privilege),
            Self::Mitamae(task) => task.execute(ctx, privilege),
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

    /// Returns the privilege setting as written in the profile.
    pub fn privilege(&self) -> &Privilege {
        match self {
            Self::Shell(task) => task.privilege(),
            Self::Mitamae(task) => task.privilege(),
        }
    }

    /// Returns the isolation setting as written in the profile.
    pub fn task_isolation(&self) -> &TaskIsolation {
        match self {
            Self::Shell(task) => task.task_isolation(),
            Self::Mitamae(task) => task.task_isolation(),
        }
    }
}
