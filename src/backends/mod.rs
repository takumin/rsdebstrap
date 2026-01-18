//! Bootstrap backend implementations.
//!
//! This module provides the trait and implementations for different
//! bootstrap tools (mmdebstrap, debootstrap, etc.).

use anyhow::Result;
use std::ffi::OsString;

pub mod debootstrap;
pub mod mmdebstrap;
mod args;

pub use args::{CommandArgsBuilder, FlagValueStyle};

/// Trait for bootstrap backend implementations.
///
/// Each bootstrap tool (mmdebstrap, debootstrap, etc.) implements this trait
/// to provide tool-specific command building logic.
pub trait BootstrapBackend {
    /// Returns the command name to execute (e.g., "mmdebstrap", "debootstrap").
    fn command_name(&self) -> &str;

    /// Builds the command-line arguments for the bootstrap command.
    ///
    /// # Arguments
    /// * `output_dir` - The base output directory path
    ///
    /// # Returns
    /// A vector of command-line arguments to pass to the bootstrap tool.
    fn build_args(&self, output_dir: &camino::Utf8Path) -> Result<Vec<OsString>>;
}
