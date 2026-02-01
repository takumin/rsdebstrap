//! Isolation module for executing commands in isolated environments.
//!
//! This module provides the trait and implementations for different
//! isolation backends (chroot, bwrap, systemd-nspawn, etc.) that can be used
//! to execute commands within a rootfs.

use anyhow::Result;
use camino::Utf8Path;
use std::ffi::OsString;

use crate::executor::{CommandExecutor, ExecutionResult};

pub mod chroot;

pub use chroot::ChrootIsolation;

/// Trait for isolation backend implementations.
///
/// Each isolation type (chroot, bwrap, systemd-nspawn, etc.) implements this trait
/// to provide the mechanism for executing commands within an isolated rootfs environment.
pub trait Isolation: Send + Sync {
    /// Returns the name of this isolation backend.
    fn name(&self) -> &'static str;

    /// Executes a command within the isolated rootfs environment.
    ///
    /// # Arguments
    /// * `rootfs` - The path to the rootfs directory
    /// * `command` - The command and arguments to execute within the isolation
    /// * `executor` - The command executor for running the isolation command
    ///
    /// # Returns
    /// Result containing the execution result or an error.
    fn execute(
        &self,
        rootfs: &Utf8Path,
        command: &[OsString],
        executor: &dyn CommandExecutor,
    ) -> Result<ExecutionResult>;
}
