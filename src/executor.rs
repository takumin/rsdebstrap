use anyhow::Result;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use which::which;

/// Maximum size of captured output in bytes (64KB)
pub(crate) const MAX_OUTPUT_SIZE: usize = 64 * 1024;

/// Maximum line size before truncation (4KB)
///
/// Lines longer than this limit are truncated to prevent OOM issues.
const MAX_LINE_SIZE: usize = 4 * 1024;

/// Type of output stream for logging purposes.
#[derive(Clone, Copy)]
enum StreamType {
    Stdout,
    Stderr,
}

impl std::fmt::Display for StreamType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdout => write!(f, "stdout"),
            Self::Stderr => write!(f, "stderr"),
        }
    }
}

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

/// Reads from a pipe into a buffer, streaming output to logs in real-time.
///
/// This function uses chunk-based reading with line splitting to handle output
/// efficiently while preventing OOM issues from extremely long lines.
///
/// ## Line Length Handling
///
/// Lines longer than [`MAX_LINE_SIZE`] (4KB) are truncated. When truncation occurs:
/// - The truncated portion is logged with a `[truncated]` marker
/// - A debug-level log records the truncation event
/// - Remaining bytes until the next newline are skipped
///
/// ## Binary Data Handling
///
/// Binary data (non-UTF-8 bytes) is handled gracefully using lossy UTF-8
/// conversion for logging. The original bytes are preserved in the returned buffer.
///
/// ## Log Levels
///
/// Log levels are determined by stream type:
/// - stdout: logged at INFO level for real-time visibility of bootstrap progress
/// - stderr: logged at WARN level for immediate attention to potential issues
///
/// Note: INFO/WARN levels are intentionally chosen over DEBUG/TRACE for usability.
/// Users need to see mmdebstrap/debootstrap progress in real-time. If sensitive
/// data might appear in command output, consider adjusting the log level via
/// environment variables (RUST_LOG).
fn read_pipe_to_buffer<R: Read>(pipe: Option<R>, stream_type: StreamType) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut truncated = false;
    let Some(pipe) = pipe else {
        return buffer;
    };

    let mut reader = BufReader::new(pipe);
    let mut line_buf: Vec<u8> = Vec::with_capacity(MAX_LINE_SIZE);
    let mut skipping_to_newline = false;

    loop {
        let available = match reader.fill_buf() {
            Ok([]) => break, // EOF
            Ok(buf) => buf,
            Err(e) => {
                tracing::warn!(stream = %stream_type, error = %e, "I/O error, stopping read");
                break;
            }
        };

        let mut consumed = 0;

        for (i, &byte) in available.iter().enumerate() {
            if byte == b'\n' {
                // End of line found
                if skipping_to_newline {
                    // We were skipping after truncation; add newline to buffer and reset
                    truncated |= append_with_limit(&mut buffer, b"\n", MAX_OUTPUT_SIZE);
                    skipping_to_newline = false;
                } else {
                    // Process the complete line (excluding the newline itself)
                    let line_content = &line_buf[..];
                    log_line(line_content, stream_type);
                    // Append line + newline to buffer
                    truncated |= append_with_limit(&mut buffer, line_content, MAX_OUTPUT_SIZE);
                    truncated |= append_with_limit(&mut buffer, b"\n", MAX_OUTPUT_SIZE);
                }
                line_buf.clear();
                consumed = i + 1;
            } else if skipping_to_newline {
                // Skip this byte (we're in truncation skip mode)
                consumed = i + 1;
            } else if line_buf.len() >= MAX_LINE_SIZE {
                // Line is too long; truncate and switch to skip mode
                let line_content = &line_buf[..];
                log_truncated_line(line_content, stream_type);
                // Append truncated content to buffer (newline will be added when we find it)
                truncated |= append_with_limit(&mut buffer, line_content, MAX_OUTPUT_SIZE);
                line_buf.clear();
                skipping_to_newline = true;
                consumed = i + 1;
            } else {
                // Normal case: add byte to line buffer
                line_buf.push(byte);
                consumed = i + 1;
            }
        }

        reader.consume(consumed);
    }

    // Handle any remaining data in line_buf (no trailing newline)
    if !line_buf.is_empty() {
        if skipping_to_newline {
            // We were skipping; the remaining data is part of the skipped portion
            // Nothing to log or add
        } else {
            log_line(&line_buf, stream_type);
            truncated |= append_with_limit(&mut buffer, &line_buf, MAX_OUTPUT_SIZE);
        }
    }

    // Warn if output was truncated
    if truncated {
        tracing::warn!(stream = %stream_type, max_bytes = MAX_OUTPUT_SIZE, "output truncated");
    }

    buffer
}

/// Logs a complete line at the appropriate level.
fn log_line(line: &[u8], stream_type: StreamType) {
    let text = String::from_utf8_lossy(line);
    // Trim trailing CR for cleaner output (handles Windows-style CRLF)
    let trimmed = text.trim_end_matches('\r');
    match stream_type {
        StreamType::Stdout => tracing::info!(stream = %stream_type, "{}", trimmed),
        StreamType::Stderr => tracing::warn!(stream = %stream_type, "{}", trimmed),
    }
}

/// Logs a truncated line with a marker and debug information.
fn log_truncated_line(line: &[u8], stream_type: StreamType) {
    let text = String::from_utf8_lossy(line);
    let trimmed = text.trim_end_matches('\r');
    match stream_type {
        StreamType::Stdout => {
            tracing::info!(stream = %stream_type, "{} [truncated]", trimmed)
        }
        StreamType::Stderr => {
            tracing::warn!(stream = %stream_type, "{} [truncated]", trimmed)
        }
    }
    tracing::debug!(
        stream = %stream_type,
        max_line_size = MAX_LINE_SIZE,
        "line exceeded maximum size and was truncated"
    );
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

        // Read both stdout and stderr in separate threads for symmetric panic recovery
        let stdout_handle = thread::Builder::new()
            .name("stdout-reader".to_string())
            .spawn(move || read_pipe_to_buffer(stdout_pipe, StreamType::Stdout))
            .expect("failed to spawn stdout reader thread");
        let stderr_handle = thread::Builder::new()
            .name("stderr-reader".to_string())
            .spawn(move || read_pipe_to_buffer(stderr_pipe, StreamType::Stderr))
            .expect("failed to spawn stderr reader thread");

        // Wait for the child process to complete
        let status = match child.wait() {
            Ok(s) => s,
            Err(e) => {
                // Join both threads to prevent thread leak
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                anyhow::bail!(
                    "failed to wait for command `{}` with args {:?}: {}",
                    spec.command,
                    spec.args,
                    e
                );
            }
        };

        // Collect stdout from the thread (with error logging on panic)
        let stdout = stdout_handle.join().unwrap_or_else(|e| {
            tracing::error!(
                stream = "stdout",
                panic = panic_message(&*e),
                "reader thread panicked"
            );
            Vec::new()
        });

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

        Ok(ExecutionResult {
            status: Some(status),
            stdout,
            stderr,
        })
    }
}
