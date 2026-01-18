//! Provisioners module for post-bootstrap configuration.
//!
//! This module provides the trait and implementations for different
//! provisioner types (shell, file, ansible, etc.) that run after
//! the bootstrap process completes.

use anyhow::Result;
use camino::Utf8Path;

use crate::executor::CommandExecutor;

pub mod shell;

/// Trait for provisioner implementations.
///
/// Each provisioner type (shell, file, ansible, etc.) implements this trait
/// to provide provisioning logic that runs after bootstrap.
pub trait Provisioner {
    /// Executes the provisioner against the target rootfs.
    ///
    /// # Arguments
    /// * `rootfs` - The path to the bootstrapped rootfs directory
    /// * `executor` - The command executor for running commands
    ///
    /// # Returns
    /// Result indicating success or failure of the provisioning step.
    fn provision(&self, rootfs: &Utf8Path, executor: &dyn CommandExecutor) -> Result<()>;
}
