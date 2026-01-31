use anyhow::Result;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use which::which;

/// Maximum size of captured output in bytes (64KB)
///
/// This constant is public for testing purposes only and should not be
/// considered part of the stable public API.
#[doc(hidden)]
pub const MAX_OUTPUT_SIZE: usize = 64 * 1024;

/// Buffer size for reading from pipes (4KB)
const READ_BUFFER_SIZE: usize = 4 * 1024;

/// Appends data to a buffer with a size limit.
///
/// Returns `true` if data was truncated due to the size limit.
fn append_with_limit(buffer: &mut Vec<u8>, data: &[u8], max_size: usize) -> bool {
    if buffer.len() >= max_size {
        return true;
    }
    let remaining = max_size - buffer.len();
    let to_append = data.len().min(remaining);
    buffer.extend_from_slice(&data[..to_append]);
    to_append < data.len()
}

/// Extracts a human-readable message from a thread panic.
///
/// The returned `&str` borrows from the panic payload, so it is valid
/// as long as the `err` reference is valid.
fn panic_message(err: &(dyn std::any::Any + Send)) -> &str {
    err.downcast_ref::<&str>()
        .copied()
        .or_else(|| err.downcast_ref::<String>().map(|s| s.as_str()))
        .unwrap_or("unknown panic")
}

/// Reads from a pipe into a buffer, streaming output to the trace log.
///
/// This function starts in text mode using line-based reading for clean log output.
/// If a UTF-8 decoding error occurs, it falls back to binary mode using raw byte reads.
/// In binary mode, log output uses lossy UTF-8 conversion.
fn read_pipe_to_buffer<R: Read>(pipe: Option<R>, stream_name: &'static str) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut truncated = false;
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
                truncated |= append_with_limit(&mut buffer, line.as_bytes(), MAX_OUTPUT_SIZE);
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::InvalidData {
                    // UTF-8 error: fall back to raw byte reading
                    tracing::trace!(stream = stream_name, error = %e, "switching to binary mode");
                    truncated |= read_binary_remainder(&mut reader, stream_name, &mut buffer);
                } else {
                    // Other I/O errors (e.g., pipe broken): warn and stop reading
                    tracing::warn!(stream = stream_name, error = %e, "I/O error, stopping read");
                }
                break;
            }
        }
    }

    // Warn if output was truncated
    if truncated {
        tracing::warn!(stream = stream_name, max_bytes = MAX_OUTPUT_SIZE, "output truncated");
    }

    buffer
}

/// Reads remaining binary data from a reader when UTF-8 decoding fails.
///
/// This function saves any data already buffered by the BufReader before
/// continuing to read remaining data in binary mode.
///
/// Returns `true` if data was truncated due to the size limit.
fn read_binary_remainder<R: Read>(
    reader: &mut BufReader<R>,
    stream_name: &'static str,
    buffer: &mut Vec<u8>,
) -> bool {
    let mut truncated = false;

    // Save any data that was read into BufReader's internal buffer before the UTF-8 error
    let buffered = reader.buffer();
    let buffered_len = buffered.len();
    if !buffered.is_empty() {
        truncated |= append_with_limit(buffer, buffered, MAX_OUTPUT_SIZE);
    }

    // Consume the internal buffer to advance past it before continuing with raw reads
    reader.consume(buffered_len);

    let mut read_buf = [0u8; READ_BUFFER_SIZE];
    let mut total_binary_bytes = 0usize;

    loop {
        match reader.read(&mut read_buf) {
            Ok(0) => break, // EOF
            Ok(n) => {
                total_binary_bytes += n;

                // Log binary data with truncated preview to avoid flooding logs
                if tracing::enabled!(tracing::Level::TRACE) {
                    const PREVIEW_LIMIT: usize = 64;
                    if n > PREVIEW_LIMIT {
                        let preview = String::from_utf8_lossy(&read_buf[..PREVIEW_LIMIT]);
                        tracing::trace!("{}: (binary) {}... ({} bytes)", stream_name, preview, n);
                    } else {
                        let chunk = String::from_utf8_lossy(&read_buf[..n]);
                        tracing::trace!("{}: (binary) {}", stream_name, chunk);
                    }
                }

                // Append to buffer with size limit
                truncated |= append_with_limit(buffer, &read_buf[..n], MAX_OUTPUT_SIZE);
            }
            Err(e) => {
                tracing::warn!(stream = stream_name, error = %e, "error reading binary data");
                break;
            }
        }
    }

    if total_binary_bytes > 0 {
        tracing::trace!(stream = stream_name, bytes = total_binary_bytes, "read binary data");
    }

    truncated
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

        tracing::trace!("spawned command: {}: pid={}", spec.command, child.id());

        // Take ownership of stdout and stderr
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();

        // Read stderr in a separate thread (only one thread needed)
        let stderr_handle = thread::spawn(move || read_pipe_to_buffer(stderr_pipe, "stderr"));

        // Read stdout in the main thread
        let stdout = read_pipe_to_buffer(stdout_pipe, "stdout");

        // Wait for the child process to complete
        let status = match child.wait() {
            Ok(s) => s,
            Err(e) => {
                // Join the stderr thread to prevent thread leak
                let _ = stderr_handle.join();
                anyhow::bail!(
                    "failed to wait for command `{}` with args {:?}: {}",
                    spec.command,
                    spec.args,
                    e
                );
            }
        };

        // Collect stderr from the thread (with error logging on panic)
        let stderr = stderr_handle.join().unwrap_or_else(|e| {
            tracing::error!(
                stream = "stderr",
                panic = panic_message(&*e),
                "reader thread panicked"
            );
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
