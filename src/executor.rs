use anyhow::Result;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use which::which;

/// Specification for a command to be executed
#[derive(Debug, Clone)]
pub struct CommandSpec {
    /// The command to execute (e.g., "mmdebstrap")
    pub command: String,
    /// Command arguments
    pub args: Vec<OsString>,
    /// Working directory (optional, defaults to current directory)
    pub cwd: Option<PathBuf>,
    /// Environment variables to set (in addition to inherited environment)
    pub env: Vec<(String, String)>,
}

impl CommandSpec {
    /// Creates a new CommandSpec with command and args
    pub fn new(command: impl Into<String>, args: Vec<OsString>) -> Self {
        Self {
            command: command.into(),
            args,
            cwd: None,
            env: Vec::new(),
        }
    }

    /// Sets the working directory
    pub fn with_cwd(mut self, cwd: PathBuf) -> Self {
        self.cwd = Some(cwd);
        self
    }

    /// Adds an environment variable
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Adds multiple environment variables
    pub fn with_envs(mut self, envs: Vec<(String, String)>) -> Self {
        self.env.extend(envs);
        self
    }
}

/// Result of command execution
#[derive(Debug)]
pub struct ExecutionResult {
    /// Exit status of the command (None in dry-run mode)
    pub status: Option<ExitStatus>,
    /// Standard output (currently empty, reserved for future use)
    pub stdout: Vec<u8>,
    /// Standard error (currently empty, reserved for future use)
    pub stderr: Vec<u8>,
}

impl ExecutionResult {
    /// Returns true if the command executed successfully
    /// In dry-run mode (status is None), this always returns true
    pub fn success(&self) -> bool {
        self.status.as_ref().is_none_or(|s| s.success())
    }

    /// Returns the exit code if available
    pub fn code(&self) -> Option<i32> {
        self.status.as_ref().and_then(|s| s.code())
    }
}

/// Trait for command execution
pub trait CommandExecutor {
    /// Execute a command with the given specification
    fn execute(&self, spec: &CommandSpec) -> Result<ExecutionResult>;
}

/// Real command executor that uses std::process::Command to execute actual commands
pub struct RealCommandExecutor {
    pub dry_run: bool,
}

impl CommandExecutor for RealCommandExecutor {
    fn execute(&self, spec: &CommandSpec) -> Result<ExecutionResult> {
        // Validate that the command exists
        let cmd = match which(&spec.command) {
            Ok(p) => p,
            Err(e) => {
                anyhow::bail!("command not found: {}: {}", spec.command, e);
            }
        };
        tracing::trace!("command found: {}: {}", spec.command, cmd.to_string_lossy());

        if self.dry_run {
            tracing::info!("dry run: {}: {:?}", spec.command, spec.args);
            return Ok(ExecutionResult {
                status: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
            });
        }

        let mut command = Command::new(cmd);
        command.args(&spec.args);

        // Set working directory if specified
        if let Some(ref cwd) = spec.cwd {
            command.current_dir(cwd);
        }

        // Set environment variables if specified
        for (key, value) in &spec.env {
            command.env(key, value);
        }

        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                anyhow::bail!(
                    "failed to spawn command `{}` with args {:?}: {}",
                    spec.command,
                    spec.args,
                    e
                );
            }
        };
        tracing::trace!("spawn command: {}: {}", spec.command, child.id());

        let status = match child.wait() {
            Ok(c) => c,
            Err(e) => {
                anyhow::bail!(
                    "failed to wait command `{}` with args {:?}: {}",
                    spec.command,
                    spec.args,
                    e
                );
            }
        };
        tracing::trace!("wait command: {}: {}", spec.command, status.success());

        Ok(ExecutionResult {
            status: Some(status),
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }
}
