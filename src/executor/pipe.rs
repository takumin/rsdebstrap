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

impl std::fmt::Display for StreamType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdout => f.write_str("stdout"),
            Self::Stderr => f.write_str("stderr"),
        }
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

/// Reads from a pipe and logs each line in real-time.
///
/// - stdout is logged at INFO level, stderr at WARN level.
///   INFO/WARN levels are chosen so users can see mmdebstrap/debootstrap
///   progress output in real-time during bootstrap operations.
/// - Binary data uses lossy UTF-8 conversion
/// - I/O errors stop reading but don't fail command execution
///   (output streaming is best-effort; command success is determined by exit status)
/// - `None` pipe logs an error and returns (unexpected if `Stdio::piped()` was set)
pub(super) fn read_pipe_to_log<R: Read>(pipe: Option<R>, stream_type: StreamType) {
    let Some(pipe) = pipe else {
        tracing::error!(
            stream = %stream_type,
            "pipe was None (unexpected: Stdio::piped() was set), no output will be captured"
        );
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
                tracing::error!(stream = %stream_type, error = %e, "I/O error, stopping read");
                break;
            }
        }
    }
}

/// Logs a complete line at the appropriate level.
///
/// Trailing CR is trimmed to handle CRLF line endings.
fn log_line(line: &[u8], stream_type: StreamType) {
    let text = String::from_utf8_lossy(line);
    let trimmed = text.trim_end_matches('\r');
    match stream_type {
        StreamType::Stdout => tracing::info!(stream = %stream_type, "{}", trimmed),
        StreamType::Stderr => tracing::warn!(stream = %stream_type, "{}", trimmed),
    }
}
