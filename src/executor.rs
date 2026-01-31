use anyhow::Result;
use std::ffi::OsString;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use which::which;

/// Maximum size of captured output in bytes (64KB)
const MAX_OUTPUT_SIZE: usize = 64 * 1024;

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

        // Set up stdout/stderr to be piped for streaming
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        // Spawn the command
        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                anyhow::bail!(
                    "failed to execute command `{}` with args {:?}: {}",
                    spec.command,
                    spec.args,
                    e
                );
            }
        };

        // Take ownership of stdout and stderr
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();

        // Read stdout in a separate thread
        let stdout_handle = thread::spawn(move || {
            let mut stdout_buffer = Vec::new();
            if let Some(pipe) = stdout_pipe {
                let reader = BufReader::new(pipe);
                for line in reader.lines() {
                    match line {
                        Ok(text) => {
                            tracing::trace!("stdout: {}", text);
                            // Append to buffer with size limit
                            if stdout_buffer.len() < MAX_OUTPUT_SIZE {
                                let remaining = MAX_OUTPUT_SIZE - stdout_buffer.len();
                                let line_bytes = text.as_bytes();
                                let to_append = line_bytes.len().min(remaining);
                                stdout_buffer.extend_from_slice(&line_bytes[..to_append]);
                                if stdout_buffer.len() < MAX_OUTPUT_SIZE {
                                    stdout_buffer.push(b'\n');
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("error reading stdout: {}", e);
                            break;
                        }
                    }
                }
            }
            stdout_buffer
        });

        // Read stderr in a separate thread
        let stderr_handle = thread::spawn(move || {
            let mut stderr_buffer = Vec::new();
            if let Some(pipe) = stderr_pipe {
                let reader = BufReader::new(pipe);
                for line in reader.lines() {
                    match line {
                        Ok(text) => {
                            tracing::trace!("stderr: {}", text);
                            // Append to buffer with size limit
                            if stderr_buffer.len() < MAX_OUTPUT_SIZE {
                                let remaining = MAX_OUTPUT_SIZE - stderr_buffer.len();
                                let line_bytes = text.as_bytes();
                                let to_append = line_bytes.len().min(remaining);
                                stderr_buffer.extend_from_slice(&line_bytes[..to_append]);
                                if stderr_buffer.len() < MAX_OUTPUT_SIZE {
                                    stderr_buffer.push(b'\n');
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("error reading stderr: {}", e);
                            break;
                        }
                    }
                }
            }
            stderr_buffer
        });

        // Wait for the child process to complete
        let status = match child.wait() {
            Ok(s) => s,
            Err(e) => {
                anyhow::bail!("failed to wait for command `{}`: {}", spec.command, e);
            }
        };

        // Collect output from threads
        let stdout = stdout_handle.join().unwrap_or_default();
        let stderr = stderr_handle.join().unwrap_or_default();

        tracing::trace!("executed command: {}: success={}", spec.command, status.success());

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
