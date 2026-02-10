//! Command execution abstraction for rsdebstrap.
//!
//! This module provides:
//! - [`CommandSpec`]: Specification for commands to execute
//! - [`ExecutionResult`]: Result of command execution
//! - [`CommandExecutor`]: Trait for command execution strategies
//! - [`RealCommandExecutor`]: Production implementation using `std::process::Command`

mod pipe;
mod real;

use std::process::ExitStatus;

use anyhow::Result;
use camino::Utf8PathBuf;

use crate::privilege::PrivilegeMethod;

pub use real::RealCommandExecutor;

/// Formats string arguments into a space-separated, debug-quoted string.
///
/// Used by error messages and dry-run output to consistently format
/// command arguments (e.g., `"--variant=debootstrap" "/tmp/rootfs"`).
pub(crate) fn format_command_args(args: &[String]) -> String {
    args.iter()
        .map(|a| format!("{:?}", a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Specification for a command to be executed
#[derive(Debug, Clone)]
pub struct CommandSpec {
    /// The command to execute (e.g., "mmdebstrap")
    pub command: String,
    /// Command arguments
    pub args: Vec<String>,
    /// Working directory (optional, defaults to current directory)
    pub cwd: Option<Utf8PathBuf>,
    /// Environment variables to set (in addition to inherited environment)
    pub env: Vec<(String, String)>,
    /// Privilege escalation method to wrap the command
    pub privilege: Option<PrivilegeMethod>,
}

impl CommandSpec {
    /// Creates a new CommandSpec with command and args
    #[must_use]
    pub fn new(command: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            command: command.into(),
            args,
            cwd: None,
            env: Vec::new(),
            privilege: None,
        }
    }

    /// Sets the privilege escalation method
    #[must_use]
    pub fn with_privilege(mut self, privilege: Option<PrivilegeMethod>) -> Self {
        self.privilege = privilege;
        self
    }

    /// Sets the working directory
    #[must_use]
    pub fn with_cwd(mut self, cwd: Utf8PathBuf) -> Self {
        self.cwd = Some(cwd);
        self
    }

    /// Adds an environment variable
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Adds multiple environment variables.
    ///
    /// Accepts any iterator of key-value pairs that can be converted into strings,
    /// such as `Vec<(String, String)>`, `&[(&str, &str)]`, or `HashMap<String, String>`.
    #[must_use]
    pub fn with_envs<I, K, V>(mut self, envs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.env
            .extend(envs.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }
}

/// Result of command execution
#[derive(Debug)]
pub struct ExecutionResult {
    /// Exit status of the command (None in dry-run mode)
    pub status: Option<ExitStatus>,
}

impl ExecutionResult {
    /// Returns true if the command executed successfully.
    ///
    /// In dry-run mode (status is None), this always returns true.
    pub fn success(&self) -> bool {
        self.status.is_none_or(|s| s.success())
    }

    /// Returns the exit code if available
    pub fn code(&self) -> Option<i32> {
        self.status.and_then(|s| s.code())
    }
}

/// Trait for command execution.
///
/// Implementations must be `Send + Sync` to allow the executor to be shared
/// across threads (e.g., when used with `Arc<dyn CommandExecutor>` for
/// concurrent output streaming during command execution).
pub trait CommandExecutor: Send + Sync {
    /// Executes a command with the given specification.
    fn execute(&self, spec: &CommandSpec) -> Result<ExecutionResult>;
}
