//! Internal utilities for streaming command output to logs.
//!
//! This module handles reading from stdout/stderr pipes and logging
//! the output in real-time during command execution.

use std::io::{BufRead, BufReader, Read};

/// Type of output stream for logging purposes.
#[derive(Clone, Copy)]
pub(super) enum StreamType {
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

/// Extracts a human-readable message from a thread panic.
///
/// The returned `&str` borrows from the panic payload, so it is valid
/// as long as the `err` reference is valid.
pub(super) fn panic_message(err: &(dyn std::any::Any + Send)) -> &str {
    err.downcast_ref::<&str>()
        .copied()
        .or_else(|| err.downcast_ref::<String>().map(|s| s.as_str()))
        .unwrap_or("unknown panic")
}

/// Reads from a pipe, streaming output to logs in real-time.
///
/// ## Binary Data Handling
///
/// Binary data (non-UTF-8 bytes) is handled gracefully using lossy UTF-8
/// conversion for logging.
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
/// For logging purposes, trailing CR characters are trimmed to improve
/// readability when viewing CRLF output.
///
/// ## None Pipe Handling
///
/// If the pipe is `None`, a debug message is logged and the function returns
/// early without processing any output.
pub(super) fn read_pipe_to_log<R: Read>(pipe: Option<R>, stream_type: StreamType) {
    let Some(pipe) = pipe else {
        tracing::debug!(stream = %stream_type, "pipe was None, no output will be captured");
        return;
    };

    let mut reader = BufReader::new(pipe);
    let mut line_buf = Vec::new();

    loop {
        line_buf.clear();
        match reader.read_until(b'\n', &mut line_buf) {
            Ok(0) => break, // EOF
            Ok(_) => {
                // Log output (excluding newline)
                let log_content = line_buf.strip_suffix(b"\n").unwrap_or(&line_buf);
                log_line(log_content, stream_type);
            }
            Err(e) => {
                tracing::warn!(stream = %stream_type, error = %e, "I/O error, stopping read");
                break;
            }
        }
    }
}

/// Logs a complete line at the appropriate level.
///
/// Note: Trailing CR is trimmed for cleaner log output when handling
/// CRLF line endings. The input bytes are not modified.
fn log_line(line: &[u8], stream_type: StreamType) {
    let text = String::from_utf8_lossy(line);
    // Trim trailing CR for cleaner output (handles Windows-style CRLF)
    let trimmed = text.trim_end_matches('\r');
    match stream_type {
        StreamType::Stdout => tracing::info!(stream = %stream_type, "{}", trimmed),
        StreamType::Stderr => tracing::warn!(stream = %stream_type, "{}", trimmed),
    }
}
