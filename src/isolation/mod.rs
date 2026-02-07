//! Isolation module for executing commands in isolated environments.
//!
//! This module provides the trait and implementations for different
//! isolation backends (chroot, bwrap, systemd-nspawn, etc.) that can be used
//! to execute commands within a rootfs.
//!
//! ## Architecture
//!
//! The module uses a Provider/Context pattern:
//!
//! - [`IsolationProvider`]: Factory for creating isolation contexts. Stateless and shareable.
//! - [`IsolationContext`]: Represents an active isolation session with setup/teardown lifecycle.
//!
//! This pattern enables proper resource management for backends like bwrap or systemd-nspawn
//! that require mounting/unmounting operations.

use anyhow::Result;
use camino::Utf8Path;
use std::ffi::OsString;
use std::sync::Arc;

use crate::executor::{CommandExecutor, ExecutionResult};

pub mod chroot;

pub use chroot::{ChrootContext, ChrootProvider};

/// Provider trait for creating isolation contexts.
///
/// Each isolation type (chroot, bwrap, systemd-nspawn, etc.) implements this trait
/// to provide the factory method for creating isolation contexts.
///
/// Providers are stateless and can be shared across threads.
pub trait IsolationProvider: Send + Sync {
    /// Returns the name of this isolation backend.
    fn name(&self) -> &'static str;

    /// Sets up the isolation environment and returns an active context.
    ///
    /// # Arguments
    /// * `rootfs` - The path to the rootfs directory
    /// * `executor` - The command executor for running commands
    /// * `dry_run` - If true, skip actual setup operations
    ///
    /// # Returns
    /// Result containing the active isolation context or an error.
    fn setup(
        &self,
        rootfs: &Utf8Path,
        executor: Arc<dyn CommandExecutor>,
        dry_run: bool,
    ) -> Result<Box<dyn IsolationContext>>;
}

/// Active isolation context with command execution capability.
///
/// Represents an active isolation session. Commands can be executed within
/// this context, and resources are cleaned up when [`teardown`](Self::teardown)
/// is called or the context is dropped.
///
/// Contexts are not thread-safe by design - they represent a single
/// isolation session that should be used sequentially.
pub trait IsolationContext: Send {
    /// Returns the name of this isolation backend.
    fn name(&self) -> &'static str;

    /// Returns the path to the rootfs directory.
    fn rootfs(&self) -> &Utf8Path;

    /// Returns whether this context is in dry-run mode.
    ///
    /// When true, tasks should skip file I/O operations (script copy,
    /// permission changes, rootfs validation) while still logging and
    /// executing commands through the context.
    fn dry_run(&self) -> bool;

    /// Executes a command within the isolated environment.
    ///
    /// # Arguments
    /// * `command` - The command and arguments to execute
    ///
    /// # Returns
    /// Result containing the execution result or an error.
    fn execute(&self, command: &[OsString]) -> Result<ExecutionResult>;

    /// Tears down the isolation environment and releases resources.
    ///
    /// This method is idempotent - calling it multiple times has no effect
    /// after the first successful teardown.
    ///
    /// Note: This is also called automatically when the context is dropped,
    /// but calling it explicitly allows for error handling.
    fn teardown(&mut self) -> Result<()>;
}
