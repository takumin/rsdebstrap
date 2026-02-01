//! Shell provisioner implementation.
//!
//! This module provides a provisioner that executes shell scripts inside the
//! bootstrapped rootfs. It wraps the `ShellRunner` from the runner module.

use super::Provisioner;
use anyhow::Result;
use camino::Utf8PathBuf;
use serde::Deserialize;

use crate::isolation::IsolationContext;
use crate::runner::ShellRunner;

// Re-export ScriptSource for backward compatibility
pub use crate::runner::ScriptSource;

/// Shell provisioner configuration.
///
/// Executes shell scripts inside the bootstrapped rootfs using the
/// configured isolation backend.
/// This is a newtype wrapper around `ShellRunner` that implements the
/// `Provisioner` trait.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(transparent)]
pub struct ShellProvisioner(ShellRunner);

impl From<ShellRunner> for ShellProvisioner {
    fn from(runner: ShellRunner) -> Self {
        Self(runner)
    }
}

impl ShellProvisioner {
    /// Validates the shell provisioner configuration.
    ///
    /// For external script files, validates that the file exists and is a regular file.
    /// For inline content, no additional validation is needed (type system ensures it's present).
    pub fn validate(&self) -> Result<()> {
        self.0.validate()
    }

    /// Returns the script source for logging purposes.
    pub fn script_source(&self) -> &str {
        self.0.script_source()
    }

    /// Returns the script path if this provisioner uses an external script file.
    pub fn script_path(&self) -> Option<&Utf8PathBuf> {
        self.0.script_path()
    }

    /// Returns a mutable reference to the script path if this provisioner uses an
    /// external script file.
    pub(crate) fn script_path_mut(&mut self) -> Option<&mut Utf8PathBuf> {
        self.0.script_path_mut()
    }
}

impl Provisioner for ShellProvisioner {
    fn provision(&self, context: &dyn IsolationContext, dry_run: bool) -> Result<()> {
        self.0.run(context, dry_run)
    }
}
