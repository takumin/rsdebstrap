use anyhow::Result;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use which::which;

/// Maximum size of captured output in bytes (64KB)
///
/// This limit prevents unbounded memory growth when capturing output from
/// long-running bootstrap processes. The value is chosen to be large enough
/// to capture useful diagnostic information while remaining reasonable for
/// error messages.
pub const MAX_OUTPUT_SIZE: usize = 64 * 1024;

/// Maximum line size before truncation (4KB)
///
/// Lines longer than this limit are truncated to prevent OOM issues.
/// This value is chosen to accommodate most reasonable log lines while
/// preventing memory exhaustion from extremely long lines (e.g., minified
/// JavaScript or base64-encoded data).
pub const MAX_LINE_SIZE: usize = 4 * 1024;

/// Initial buffer capacity for captured output (8KB)
///
/// This value balances memory efficiency with typical output sizes.
/// Most commands produce less than 8KB of output, so this avoids
/// unnecessary reallocations. The buffer grows automatically up to
/// [`MAX_OUTPUT_SIZE`] if needed.
pub const INITIAL_BUFFER_CAPACITY: usize = 8 * 1024;

/// A single line entry in the ring buffer.
struct LineEntry {
    /// The line data including the trailing newline (if present).
    data: Vec<u8>,
}

/// A FIFO ring buffer that stores lines up to a maximum total size.
///
/// When the buffer exceeds `max_size`, the oldest lines are removed
/// to make room for new data. This ensures that the most recent output
/// (including error messages at the end of a command) is preserved.
struct RingLineBuffer {
    /// Queue of line entries (oldest at front, newest at back).
    lines: VecDeque<LineEntry>,
    /// Current total size of all line data in bytes.
    total_size: usize,
    /// Maximum allowed total size in bytes.
    max_size: usize,
}

impl RingLineBuffer {
    /// Creates a new ring buffer with the specified maximum size.
    fn new(max_size: usize) -> Self {
        Self {
            lines: VecDeque::new(),
            total_size: 0,
            max_size,
        }
    }

    /// Adds a line to the buffer, removing old lines if necessary.
    ///
    /// If the new line itself exceeds `max_size`, it will be truncated
    /// to fit. Old lines are removed from the front to maintain the
    /// size constraint.
    fn push_line(&mut self, line: Vec<u8>) {
        // ByteProcessor ensures lines don't exceed MAX_LINE_SIZE (plus newline).
        // This assertion catches any future changes that might violate this invariant.
        debug_assert!(
            line.len() <= MAX_LINE_SIZE + 1,
            "line length {} exceeds MAX_LINE_SIZE + 1 ({}); ByteProcessor should have truncated it",
            line.len(),
            MAX_LINE_SIZE + 1
        );

        // Truncate the line if it exceeds max_size (defensive fallback)
        let line = if line.len() > self.max_size {
            line[line.len() - self.max_size..].to_vec()
        } else {
            line
        };

        let line_size = line.len();

        // Remove old lines until we have room for the new line
        while self.total_size + line_size > self.max_size && !self.lines.is_empty() {
            if let Some(old_line) = self.lines.pop_front() {
                self.total_size -= old_line.data.len();
            }
        }

        // Add the new line
        self.total_size += line_size;
        self.lines.push_back(LineEntry { data: line });
    }

    /// Converts the ring buffer into a contiguous `Vec<u8>`.
    ///
    /// The lines are concatenated in order (oldest to newest).
    fn into_vec(self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.total_size);
        for entry in self.lines {
            result.extend(entry.data);
        }
        result
    }
}

/// Type of output stream for logging purposes.
#[derive(Clone, Copy)]
enum StreamType {
    Stdout,
    Stderr,
}

impl StreamType {
    /// Returns the stream type as a static string slice.
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

impl std::fmt::Display for StreamType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result of processing a single byte in [`ByteProcessor`].
///
/// This enum represents the different outcomes when processing input bytes,
/// allowing the caller to understand what action was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessResult {
    /// Byte was added to the line buffer, continue processing.
    ///
    /// This variant enables callers to distinguish normal processing from
    /// line completion or truncation. Having explicit variants improves code
    /// clarity and supports future extensions (e.g., progress reporting).
    Continue,
    /// A complete line was found (newline detected) and processed.
    LineComplete,
    /// The line exceeded [`MAX_LINE_SIZE`] and was truncated.
    LineTruncated,
}

/// Processes bytes from a stream, handling line buffering and truncation.
///
/// This struct encapsulates the state needed to process input bytes one at a time,
/// managing line boundaries and truncation of long lines. Output is stored in a
/// ring buffer that automatically discards old data when the size limit is reached.
///
/// ## Line Ending Recognition
///
/// Only LF (`\n`) is recognized as a line terminator. CR (`\r`) alone
/// (classic Mac format) is not treated as a line ending. This is intentional:
/// - Modern systems (including mmdebstrap/debootstrap) use LF
/// - CRLF (`\r\n`) is handled correctly (CR is preserved, LF terminates)
/// - Simplifies implementation without sacrificing practical utility
struct ByteProcessor<'a> {
    /// Buffer for accumulating the current line.
    line_buf: Vec<u8>,
    /// Ring buffer where complete lines are stored.
    ring_buffer: &'a mut RingLineBuffer,
    /// Whether we are skipping bytes until the next newline (after truncation).
    skipping_to_newline: bool,
    /// The type of stream being processed (for logging).
    stream_type: StreamType,
}

impl<'a> ByteProcessor<'a> {
    /// Creates a new `ByteProcessor` for the given ring buffer and stream type.
    fn new(ring_buffer: &'a mut RingLineBuffer, stream_type: StreamType) -> Self {
        Self {
            line_buf: Vec::with_capacity(MAX_LINE_SIZE),
            ring_buffer,
            skipping_to_newline: false,
            stream_type,
        }
    }

    /// Processes a single byte, returning the result of the operation.
    fn process(&mut self, byte: u8) -> ProcessResult {
        if byte == b'\n' {
            // End of line found
            if self.skipping_to_newline {
                // We were skipping after truncation; add newline to buffer and reset
                self.ring_buffer.push_line(b"\n".to_vec());
                self.skipping_to_newline = false;
            } else {
                // Process the complete line (excluding the newline itself)
                log_line(&self.line_buf, self.stream_type);
                // Append line + newline to ring buffer
                let mut line_with_newline = std::mem::take(&mut self.line_buf);
                line_with_newline.push(b'\n');
                self.ring_buffer.push_line(line_with_newline);
            }
            self.line_buf.clear();
            ProcessResult::LineComplete
        } else if self.skipping_to_newline {
            // Skip this byte (we're in truncation skip mode)
            ProcessResult::Continue
        } else if self.line_buf.len() >= MAX_LINE_SIZE {
            // Line is too long; truncate and switch to skip mode
            log_truncated_line(&self.line_buf, self.stream_type);
            // Append truncated content to ring buffer (newline will be added when we find it)
            self.ring_buffer
                .push_line(std::mem::take(&mut self.line_buf));
            self.skipping_to_newline = true;
            ProcessResult::LineTruncated
        } else {
            // Normal case: add byte to line buffer
            self.line_buf.push(byte);
            ProcessResult::Continue
        }
    }

    /// Finalizes processing, handling any remaining data.
    fn finalize(mut self) {
        // Handle any remaining data in line_buf (no trailing newline)
        if !self.line_buf.is_empty() && !self.skipping_to_newline {
            log_line(&self.line_buf, self.stream_type);
            self.ring_buffer
                .push_line(std::mem::take(&mut self.line_buf));
        }
    }
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
/// ## Ring Buffer Behavior
///
/// Output is stored in a ring buffer that holds up to [`MAX_OUTPUT_SIZE`] (64KB)
/// of data. When the limit is exceeded, the oldest lines are automatically
/// discarded to make room for new data. This ensures that the most recent
/// output (including error messages at the end of a command) is preserved.
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
///
/// ## Line Ending Handling
///
/// The function preserves original line endings (LF, CRLF, CR) in the
/// returned buffer for data fidelity. For logging purposes, trailing CR
/// characters are trimmed to improve readability when viewing CRLF output.
fn read_pipe_to_buffer<R: Read>(pipe: Option<R>, stream_type: StreamType) -> Vec<u8> {
    let Some(pipe) = pipe else {
        return Vec::new();
    };

    let mut ring_buffer = RingLineBuffer::new(MAX_OUTPUT_SIZE);
    let mut reader = BufReader::new(pipe);
    let mut processor = ByteProcessor::new(&mut ring_buffer, stream_type);

    loop {
        let available = match reader.fill_buf() {
            Ok([]) => break, // EOF
            Ok(buf) => buf,
            Err(e) => {
                tracing::warn!(stream = %stream_type, error = %e, "I/O error, stopping read");
                break;
            }
        };

        for &byte in available.iter() {
            processor.process(byte);
        }

        let consumed = available.len();
        reader.consume(consumed);
    }

    processor.finalize();
    ring_buffer.into_vec()
}

/// Logs a complete line at the appropriate level.
///
/// Note: Trailing CR is trimmed for cleaner log output when handling
/// CRLF line endings, but the original bytes are preserved in the buffer.
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
                    "failed to spawn command `{}` with args {:?}: {}",
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
            .map_err(|e| anyhow::anyhow!("failed to spawn stdout reader thread: {}", e))?;

        let stderr_handle = match thread::Builder::new()
            .name("stderr-reader".to_string())
            .spawn(move || read_pipe_to_buffer(stderr_pipe, StreamType::Stderr))
        {
            Ok(handle) => handle,
            Err(e) => {
                // Clean up stdout thread before returning error
                let _ = stdout_handle.join();
                anyhow::bail!("failed to spawn stderr reader thread: {}", e);
            }
        };

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
