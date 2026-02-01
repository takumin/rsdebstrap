//! Provisioners module for post-bootstrap configuration.
//!
//! This module provides the trait and implementations for different
//! provisioner types (shell, file, ansible, etc.) that run after
//! the bootstrap process completes.

use anyhow::Result;

use crate::isolation::IsolationContext;

pub mod shell;

/// Trait for provisioner implementations.
///
/// Each provisioner type (shell, file, ansible, etc.) implements this trait
/// to provide provisioning logic that runs after bootstrap.
pub trait Provisioner {
    /// Executes the provisioner against the target rootfs.
    ///
    /// # Arguments
    /// * `context` - The active isolation context for executing commands in rootfs.
    ///   The rootfs path can be obtained via `context.rootfs()`.
    /// * `dry_run` - If true, skip actual file operations and only log what would be done
    ///
    /// # Returns
    /// Result indicating success or failure of the provisioning step.
    fn provision(&self, context: &dyn IsolationContext, dry_run: bool) -> Result<()>;
}
