//! Domain-specific error types for rsdebstrap.
//!
//! This module defines `RsdebstrapError`, a `thiserror`-based enum that
//! provides typed error variants for common failure modes. Public API
//! functions return `Result<T, RsdebstrapError>` for programmatic error
//! handling, while trait boundaries continue to use `anyhow::Result`.
//!
//! `RsdebstrapError` implements `Into<anyhow::Error>`, so the `?` operator
//! converts it automatically at trait boundaries that return `anyhow::Result`.

use std::io;

/// Formats an IO error kind into a human-readable message.
///
/// Provides consistent, user-friendly messages for common IO error kinds
/// (e.g., "I/O error: not found") instead of the OS-level messages
/// (e.g., "No such file or directory (os error 2)"). For unrecognized
/// error kinds, falls back to including the OS-level error message
/// directly (e.g., "I/O error: connection refused").
///
/// The path or operation context is provided separately via
/// `RsdebstrapError::Io { context }`.
pub(crate) fn io_error_kind_message(err: &io::Error) -> String {
    match err.kind() {
        io::ErrorKind::NotFound => "I/O error: not found".to_string(),
        io::ErrorKind::PermissionDenied => "I/O error: permission denied".to_string(),
        io::ErrorKind::IsADirectory => "I/O error: is a directory".to_string(),
        _ => format!("I/O error: {}", err),
    }
}

/// Domain-specific error type for rsdebstrap.
///
/// Provides typed variants for common failure modes, enabling callers
/// to match on error kinds programmatically rather than parsing error
/// message strings.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RsdebstrapError {
    /// A validation constraint was violated.
    #[error("validation error: {0}")]
    Validation(String),

    /// A command execution failed (non-zero exit, spawn failure, wait failure, thread panic, etc.).
    #[error("command execution failed: {command}: {status}")]
    Execution {
        /// The command that was executed.
        command: String,
        /// Human-readable reason for the failure: exit code, signal information,
        /// or a description of the internal error (e.g., thread spawn failure).
        status: String,
    },

    /// An isolation backend operation failed.
    #[error("isolation error: {0}")]
    Isolation(String),

    /// A configuration file could not be loaded or parsed.
    #[error("configuration error: {0}")]
    Config(String),

    /// An I/O operation failed with contextual information.
    #[error("{context}: {message}")]
    Io {
        /// What was being done when the error occurred.
        ///
        /// This is either a file path (e.g., `"/etc/config.yml"`) or an operation
        /// description with a path (e.g., `"failed to read metadata: /path/to/file"`).
        /// When propagated through pipeline validation, the context may be prefixed
        /// with phase information (e.g., `"provisioner 1 validation failed: ..."`).
        /// Combined with `message` in the Display format: `"{context}: {message}"`.
        context: String,
        /// Human-readable description of the I/O failure, derived from
        /// [`io_error_kind_message`] for consistent formatting across the codebase.
        message: String,
        /// The underlying I/O error, preserved for programmatic inspection
        /// (e.g., `source.kind() == ErrorKind::NotFound`).
        #[source]
        source: std::io::Error,
    },
}

impl RsdebstrapError {
    /// Creates an `Io` variant with the `message` field automatically derived
    /// from the `source` via [`io_error_kind_message`].
    ///
    /// This is the preferred way to construct `Io` errors, ensuring that
    /// the `message` field is always consistent with the `source`.
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            message: io_error_kind_message(&source),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_display() {
        let err = RsdebstrapError::Validation("shell path must not be empty".to_string());
        assert_eq!(err.to_string(), "validation error: shell path must not be empty");
    }

    #[test]
    fn test_execution_display() {
        let err = RsdebstrapError::Execution {
            command: "mmdebstrap".to_string(),
            status: "exit status: 1".to_string(),
        };
        assert_eq!(err.to_string(), "command execution failed: mmdebstrap: exit status: 1");
    }

    #[test]
    fn test_execution_display_thread_spawn_failure() {
        let err = RsdebstrapError::Execution {
            command: "mmdebstrap [\"--variant=debootstrap\"]".to_string(),
            status: "failed to spawn stdout reader thread: resource exhausted".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("command execution failed:"));
        assert!(display.contains("mmdebstrap"));
        assert!(display.contains("failed to spawn stdout reader thread"));
    }

    #[test]
    fn test_isolation_display() {
        let err = RsdebstrapError::Isolation(
            "cannot execute command: chroot context has already been torn down".to_string(),
        );
        assert_eq!(
            err.to_string(),
            "isolation error: cannot execute command: chroot context has already been torn down"
        );
    }

    #[test]
    fn test_config_display() {
        let err = RsdebstrapError::Config("YAML parse error at line 3".to_string());
        assert_eq!(err.to_string(), "configuration error: YAML parse error at line 3");
    }

    #[test]
    fn test_io_display() {
        let source = io::Error::new(io::ErrorKind::NotFound, "entity not found");
        let err = RsdebstrapError::Io {
            context: "/path/to/file.yml".to_string(),
            message: "I/O error: not found".to_string(),
            source,
        };
        assert_eq!(err.to_string(), "/path/to/file.yml: I/O error: not found");
    }

    #[test]
    fn test_io_source_preserved() {
        let source = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let err = RsdebstrapError::Io {
            context: "/etc/shadow".to_string(),
            message: "I/O error: permission denied".to_string(),
            source,
        };
        match &err {
            RsdebstrapError::Io { source, .. } => {
                assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_io_error_kind_message_not_found() {
        let err = io::Error::new(io::ErrorKind::NotFound, "not found");
        assert_eq!(io_error_kind_message(&err), "I/O error: not found");
    }

    #[test]
    fn test_io_error_kind_message_permission_denied() {
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        assert_eq!(io_error_kind_message(&err), "I/O error: permission denied");
    }

    #[test]
    fn test_io_error_kind_message_is_a_directory() {
        let err = io::Error::new(io::ErrorKind::IsADirectory, "is a directory");
        assert_eq!(io_error_kind_message(&err), "I/O error: is a directory");
    }

    #[test]
    fn test_io_error_kind_message_other() {
        let err = io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused");
        let msg = io_error_kind_message(&err);
        assert!(msg.starts_with("I/O error: "));
    }

    #[test]
    fn test_into_anyhow_error() {
        let err = RsdebstrapError::Validation("test".to_string());
        let anyhow_err: anyhow::Error = err.into();
        let downcast = anyhow_err.downcast_ref::<RsdebstrapError>();
        assert!(downcast.is_some());
        assert!(matches!(downcast.unwrap(), RsdebstrapError::Validation(_)));
    }
}
