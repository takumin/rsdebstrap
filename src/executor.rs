use anyhow::Result;
use std::ffi::OsString;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
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

        // Configure stdout and stderr to be captured
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        // Spawn the command
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

        // Read stdout and stderr concurrently using threads to avoid deadlocks.
        // Note: This still buffers the entire output in memory for diagnostic purposes.
        // For commands producing very large outputs, consider streaming to a file instead.
        let (tx_stdout, rx_stdout) = mpsc::channel();
        let (tx_stderr, rx_stderr) = mpsc::channel();

        let stdout_handle = child.stdout.take().map(|mut pipe| {
            thread::spawn(move || {
                let mut buffer = Vec::new();
                if let Err(e) = pipe.read_to_end(&mut buffer) {
                    tracing::warn!("failed to read stdout: {}", e);
                }
                let _ = tx_stdout.send(buffer);
            })
        });

        let stderr_handle = child.stderr.take().map(|mut pipe| {
            thread::spawn(move || {
                let mut buffer = Vec::new();
                if let Err(e) = pipe.read_to_end(&mut buffer) {
                    tracing::warn!("failed to read stderr: {}", e);
                }
                let _ = tx_stderr.send(buffer);
            })
        });

        // Wait for threads to finish reading
        let stdout = if let Some(handle) = stdout_handle {
            let _ = handle.join();
            rx_stdout.recv().unwrap_or_default()
        } else {
            Vec::new()
        };

        let stderr = if let Some(handle) = stderr_handle {
            let _ = handle.join();
            rx_stderr.recv().unwrap_or_default()
        } else {
            Vec::new()
        };

        // Wait for the command to complete
        let status = match child.wait() {
            Ok(s) => s,
            Err(e) => {
                anyhow::bail!(
                    "failed to wait for command `{}` with args {:?}: {}",
                    spec.command,
                    spec.args,
                    e
                );
            }
        };
        tracing::trace!("wait command: {}: {}", spec.command, status.success());

        // Log stderr if the command failed and produced output
        if !status.success() && !stderr.is_empty() {
            let stderr_text = String::from_utf8_lossy(&stderr);
            tracing::debug!("command `{}` failed with stderr:\n{}", spec.command, stderr_text);
        }

        Ok(ExecutionResult {
            status: Some(status),
            stdout,
            stderr,
        })
    }
}
