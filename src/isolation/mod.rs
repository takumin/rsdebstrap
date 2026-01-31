//! Isolation strategy module for provisioners.
//!
//! This module provides the trait and implementations for different
//! isolation strategies (chroot, systemd-nspawn, bwrap) that can be
//! used to execute provisioning scripts in isolated environments.

pub mod bwrap;
pub mod chroot;
pub mod nspawn;

use anyhow::Result;
use camino::Utf8Path;
use serde::Deserialize;
use std::fmt::Debug;

use crate::executor::CommandSpec;

pub use bwrap::BwrapIsolation;
pub use chroot::ChrootIsolation;
pub use nspawn::NspawnIsolation;

/// Privilege escalation method.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Privilege {
    /// No privilege escalation
    #[default]
    None,
    /// Use sudo for privilege escalation
    Sudo,
}

/// Trait for isolation strategy implementations.
///
/// Each isolation type (chroot, systemd-nspawn, bwrap) implements this trait
/// to provide command building logic for executing scripts in isolated environments.
pub trait IsolationStrategy: Debug + Send + Sync {
    /// Returns the name of the isolation command (e.g., "chroot", "systemd-nspawn", "bwrap").
    fn command_name(&self) -> &str;

    /// Builds a command specification for executing a script in the isolated environment.
    ///
    /// # Arguments
    /// * `rootfs` - The path to the rootfs directory
    /// * `shell` - The shell interpreter to use (e.g., "/bin/sh")
    /// * `script_path` - The path to the script inside the rootfs (e.g., "/tmp/provision.sh")
    ///
    /// # Returns
    /// A `CommandSpec` ready to be executed by a `CommandExecutor`.
    fn build_command(
        &self,
        rootfs: &Utf8Path,
        shell: &str,
        script_path: &str,
    ) -> Result<CommandSpec>;

    /// Validates the environment before execution.
    ///
    /// This can be used to check for required binaries, permissions, etc.
    /// The default implementation does nothing.
    ///
    /// # Arguments
    /// * `rootfs` - The path to the rootfs directory
    fn validate_environment(&self, _rootfs: &Utf8Path) -> Result<()> {
        Ok(())
    }
}

/// Isolation configuration.
///
/// This enum represents the different isolation strategies that can be used.
/// The `type` field in YAML determines which variant is used.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum IsolationConfig {
    /// chroot isolation (default)
    Chroot(ChrootIsolation),
    /// systemd-nspawn isolation
    Nspawn(NspawnIsolation),
    /// bubblewrap isolation
    Bwrap(BwrapIsolation),
}

impl Default for IsolationConfig {
    fn default() -> Self {
        IsolationConfig::Chroot(ChrootIsolation::default())
    }
}

impl IsolationConfig {
    /// Returns a reference to the underlying isolation strategy as a trait object.
    pub fn as_strategy(&self) -> &dyn IsolationStrategy {
        match self {
            IsolationConfig::Chroot(cfg) => cfg,
            IsolationConfig::Nspawn(cfg) => cfg,
            IsolationConfig::Bwrap(cfg) => cfg,
        }
    }
}
