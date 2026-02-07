//! Task module for declarative pipeline steps.
//!
//! This module provides the `TaskDefinition` enum — a data-driven abstraction
//! where each variant describes *what* to execute, and methods on the enum
//! provide *how* to execute via Rust's exhaustive pattern matching.
//!
//! Adding a new task type requires:
//! 1. Adding a new variant to `TaskDefinition`
//! 2. Creating a corresponding data struct (e.g., `FileTask`)
//! 3. Implementing the match arms in each method
//!
//! The compiler enforces exhaustiveness, ensuring all task types are handled.

pub mod shell;

use anyhow::Result;
use camino::Utf8Path;
use serde::Deserialize;

pub use shell::{ScriptSource, ShellTask};

use crate::isolation::IsolationContext;

/// Declarative task definition for pipeline steps.
///
/// Each variant holds the data needed to configure and execute a specific
/// type of task. The enum dispatch pattern provides compile-time exhaustive
/// matching — adding a new variant causes compilation errors at every
/// unhandled match site, preventing missed implementations.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TaskDefinition {
    /// Shell script execution task
    Shell(ShellTask),
}

impl TaskDefinition {
    /// Returns a human-readable name for this task.
    pub fn name(&self) -> &str {
        match self {
            Self::Shell(task) => task.name(),
        }
    }

    /// Validates the task configuration.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Shell(task) => task.validate(),
        }
    }

    /// Executes the task within the given isolation context.
    pub fn execute(&self, ctx: &dyn IsolationContext) -> Result<()> {
        match self {
            Self::Shell(task) => task.execute(ctx),
        }
    }

    /// Returns the script path if this task uses an external script file.
    pub fn script_path(&self) -> Option<&camino::Utf8PathBuf> {
        match self {
            Self::Shell(task) => task.script_path(),
        }
    }

    /// Resolves relative paths in this task relative to the given base directory.
    pub fn resolve_paths(&mut self, base_dir: &Utf8Path) {
        match self {
            Self::Shell(task) => task.resolve_paths(base_dir),
        }
    }
}
