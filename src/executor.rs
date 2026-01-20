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
    #[must_use]
    pub fn new(command: impl Into<String>, args: Vec<OsString>) -> Self {
        Self {
            command: command.into(),
            args,
            cwd: None,
            env: Vec::new(),
        }
    }

    /// Sets the working directory
    #[must_use]
    pub fn with_cwd(mut self, cwd: PathBuf) -> Self {
        self.cwd = Some(cwd);
        self
    }

    /// Adds an environment variable
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Adds multiple environment variables
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
    /// Standard output captured from the command
    pub stdout: Vec<u8>,
    /// Standard error captured from the command
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
        if self.dry_run {
            tracing::info!("dry run: {:?}", spec);
            return Ok(ExecutionResult {
                status: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
            });
        }

        // Validate that the command exists
        let cmd = match which(&spec.command) {
            Ok(p) => p,
            Err(e) => {
                anyhow::bail!("command not found: {}: {}", spec.command, e);
            }
        };
        tracing::trace!("command found: {}: {}", spec.command, cmd.to_string_lossy());

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

        // Execute command and capture output
        let output = match command.output() {
            Ok(o) => o,
            Err(e) => {
                anyhow::bail!(
                    "failed to execute command `{}` with args {:?}: {}",
                    spec.command,
                    spec.args,
                    e
                );
            }
        };
        tracing::trace!("executed command: {}: success={}", spec.command, output.status.success());

        // Log stderr if the command failed and produced output
        if !output.status.success() && !output.stderr.is_empty() {
            let stderr_text = String::from_utf8_lossy(&output.stderr);
            tracing::debug!("command `{}` failed with stderr:\n{}", spec.command, stderr_text);
        }

        Ok(ExecutionResult {
            status: Some(output.status),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}
