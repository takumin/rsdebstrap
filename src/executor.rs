use anyhow::Result;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use which::which;

/// Maximum size of captured output in bytes (64KB)
pub const MAX_OUTPUT_SIZE: usize = 64 * 1024;

/// Buffer size for reading from pipes (4KB)
const READ_BUFFER_SIZE: usize = 4 * 1024;

/// Reads from a pipe into a buffer, streaming output to the trace log.
///
/// This function starts in text mode using line-based reading for clean log output.
/// If a UTF-8 decoding error occurs, it falls back to binary mode using raw byte reads.
/// In binary mode, log output uses lossy UTF-8 conversion.
fn read_pipe_to_buffer<R: Read>(pipe: Option<R>, stream_name: &'static str) -> Vec<u8> {
    let mut buffer = Vec::new();
    let Some(pipe) = pipe else {
        return buffer;
    };

    let mut reader = BufReader::new(pipe);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                // Log the line (without trailing newline for cleaner output)
                let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
                tracing::trace!("{}: {}", stream_name, trimmed);

                // Append to buffer with size limit
                if buffer.len() < MAX_OUTPUT_SIZE {
                    let remaining = MAX_OUTPUT_SIZE - buffer.len();
                    let line_bytes = line.as_bytes();
                    let to_append = line_bytes.len().min(remaining);
                    buffer.extend_from_slice(&line_bytes[..to_append]);
                }
            }
            Err(e) => {
                // For invalid UTF-8, fall back to raw byte reading
                tracing::trace!("{}: switching to binary mode due to: {}", stream_name, e);

                // Save any data that was read into BufReader's internal buffer before the error
                let buffered = reader.buffer();
                if !buffered.is_empty() && buffer.len() < MAX_OUTPUT_SIZE {
                    let remaining = MAX_OUTPUT_SIZE - buffer.len();
                    let to_append = buffered.len().min(remaining);
                    buffer.extend_from_slice(&buffered[..to_append]);
                }

                read_binary_remainder(&mut reader, stream_name, &mut buffer);
                break;
            }
        }
    }

    buffer
}

/// Reads remaining binary data from a reader when UTF-8 decoding fails.
fn read_binary_remainder<R: Read>(
    reader: &mut BufReader<R>,
    stream_name: &'static str,
    buffer: &mut Vec<u8>,
) {
    // Consume the internal buffer first (already saved by caller)
    reader.consume(reader.buffer().len());

    let mut read_buf = [0u8; READ_BUFFER_SIZE];
    let mut total_binary_bytes = 0usize;

    loop {
        match reader.read(&mut read_buf) {
            Ok(0) => break, // EOF
            Ok(n) => {
                total_binary_bytes += n;

                // Append to buffer with size limit
                if buffer.len() < MAX_OUTPUT_SIZE {
                    let remaining = MAX_OUTPUT_SIZE - buffer.len();
                    let to_append = n.min(remaining);
                    buffer.extend_from_slice(&read_buf[..to_append]);
                }
            }
            Err(e) => {
                tracing::warn!("error reading {}: {}", stream_name, e);
                break;
            }
        }
    }

    if total_binary_bytes > 0 {
        tracing::trace!(
            "{}: read {} bytes of binary data",
            stream_name,
            total_binary_bytes
        );
    }
}

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
        let stdout_handle = thread::spawn(move || read_pipe_to_buffer(stdout_pipe, "stdout"));

        // Read stderr in a separate thread
        let stderr_handle = thread::spawn(move || read_pipe_to_buffer(stderr_pipe, "stderr"));

        // Wait for the child process to complete
        let status = match child.wait() {
            Ok(s) => s,
            Err(e) => {
                anyhow::bail!("failed to wait for command `{}`: {}", spec.command, e);
            }
        };

        // Collect output from threads (with error logging on panic)
        let stdout = stdout_handle.join().unwrap_or_else(|e| {
            tracing::error!("stdout reader thread panicked: {:?}", e);
            Vec::new()
        });
        let stderr = stderr_handle.join().unwrap_or_else(|e| {
            tracing::error!("stderr reader thread panicked: {:?}", e);
            Vec::new()
        });

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
