//! Domain-specific error types for rsdebstrap.
//!
//! This module defines `RsdebstrapError`, a `thiserror`-based enum that
//! provides typed error variants for common failure modes. Public API
//! functions return `Result<T, RsdebstrapError>` for programmatic error
//! handling, while trait boundaries continue to use `anyhow::Result`.
//!
//! `RsdebstrapError` implements `std::error::Error` (via `thiserror`), which
//! allows automatic conversion into `anyhow::Error` via the `?` operator
//! at trait boundaries that return `anyhow::Result`.

use std::io;

use crate::executor::format_command_args;

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

    /// A required command was not found in PATH.
    #[error("command not found: {label} '{command}' not found in PATH")]
    CommandNotFound {
        /// The command that was not found.
        command: String,
        /// Human-readable label describing the command's role
        /// (e.g., "privilege escalation command", "command").
        label: String,
    },

    /// An I/O operation failed with contextual information.
    ///
    /// The `Display` implementation formats as `"{context}: {io_error_kind_message}"`,
    /// deriving the human-readable message from the `source` error kind at display time.
    #[error("{context}: {}", io_error_kind_message(source))]
    Io {
        /// What was being done when the error occurred.
        ///
        /// This is either a file path (e.g., `"/etc/config.yml"`) or an operation
        /// description with a path (e.g., `"failed to read metadata: /path/to/file"`).
        /// Callers may prepend additional context (e.g., phase information) when
        /// propagating this error.
        context: String,
        /// The underlying I/O error, preserved for programmatic inspection
        /// (e.g., `source.kind() == ErrorKind::NotFound`).
        #[source]
        source: std::io::Error,
    },
}

impl RsdebstrapError {
    /// Creates an `Io` variant from a context string and an I/O error.
    ///
    /// This is the preferred way to construct `Io` errors.
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Creates a `CommandNotFound` variant for a missing command.
    pub(crate) fn command_not_found(command: impl Into<String>, label: impl Into<String>) -> Self {
        Self::CommandNotFound {
            command: command.into(),
            label: label.into(),
        }
    }

    /// Converts an `anyhow::Error` into a `RsdebstrapError`, preserving the typed
    /// variant if the error is already a `RsdebstrapError`, or wrapping it as
    /// `Validation` otherwise.
    pub(crate) fn from_anyhow_or_validation(e: anyhow::Error) -> Self {
        match e.downcast::<RsdebstrapError>() {
            Ok(typed) => typed,
            Err(e) => Self::Validation(format!("{:#}", e)),
        }
    }

    /// Creates an `Execution` variant from a `CommandSpec` and a status description.
    ///
    /// Formats the command consistently as `"command_name arg1 arg2 ..."`.
    /// This is the preferred way to construct `Execution` errors, ensuring
    /// consistent `command` field formatting across the codebase.
    pub(crate) fn execution(
        spec: &crate::executor::CommandSpec,
        status: impl Into<String>,
    ) -> Self {
        let command = if let Some(method) = &spec.privilege {
            if spec.args.is_empty() {
                format!("{} {}", method.command_name(), spec.command)
            } else {
                format!(
                    "{} {} {}",
                    method.command_name(),
                    spec.command,
                    format_command_args(&spec.args)
                )
            }
        } else if spec.args.is_empty() {
            spec.command.clone()
        } else {
            format!("{} {}", spec.command, format_command_args(&spec.args))
        };
        Self::Execution {
            command,
            status: status.into(),
        }
    }

    /// Creates an `Execution` variant from a command slice and isolation context name.
    ///
    /// This is the preferred way to construct `Execution` errors for commands
    /// executed through an isolation context, formatting the command consistently
    /// as `"arg1 arg2 ... (isolation: context_name)"`.
    pub(crate) fn execution_in_isolation(
        command: &[String],
        isolation_name: &str,
        status: impl Into<String>,
    ) -> Self {
        Self::Execution {
            command: format!("{} (isolation: {})", format_command_args(command), isolation_name),
            status: status.into(),
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
            command: "mmdebstrap --variant=debootstrap".to_string(),
            status: "failed to spawn stdout reader thread: resource exhausted".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("command execution failed:"));
        assert!(display.contains("mmdebstrap"));
        assert!(display.contains("failed to spawn stdout reader thread"));
    }

    #[test]
    fn test_execution_constructor_with_args() {
        use crate::executor::CommandSpec;
        let spec = CommandSpec::new("mmdebstrap", vec!["--variant=debootstrap".into()]);
        let err = RsdebstrapError::execution(&spec, "exit status: 1");
        assert_eq!(
            err.to_string(),
            "command execution failed: mmdebstrap \"--variant=debootstrap\": exit status: 1"
        );
    }

    #[test]
    fn test_execution_constructor_without_args() {
        use crate::executor::CommandSpec;
        let spec = CommandSpec::new("mmdebstrap", vec![]);
        let err = RsdebstrapError::execution(&spec, "exit status: 1");
        assert_eq!(err.to_string(), "command execution failed: mmdebstrap: exit status: 1");
    }

    #[test]
    fn test_execution_constructor_with_privilege_and_args() {
        use crate::executor::CommandSpec;
        use crate::privilege::PrivilegeMethod;
        let spec = CommandSpec::new("chroot", vec!["/tmp/rootfs".into(), "/bin/sh".into()])
            .with_privilege(Some(PrivilegeMethod::Sudo));
        let err = RsdebstrapError::execution(&spec, "exit status: 1");
        assert_eq!(
            err.to_string(),
            "command execution failed: sudo chroot \"/tmp/rootfs\" \"/bin/sh\": exit status: 1"
        );
    }

    #[test]
    fn test_execution_constructor_with_privilege_without_args() {
        use crate::executor::CommandSpec;
        use crate::privilege::PrivilegeMethod;
        let spec = CommandSpec::new("chroot", vec![]).with_privilege(Some(PrivilegeMethod::Doas));
        let err = RsdebstrapError::execution(&spec, "exit status: 1");
        assert_eq!(err.to_string(), "command execution failed: doas chroot: exit status: 1");
    }

    #[test]
    fn test_command_not_found_display() {
        let err = RsdebstrapError::command_not_found("sudo", "privilege escalation command");
        assert_eq!(
            err.to_string(),
            "command not found: privilege escalation command 'sudo' not found in PATH"
        );
    }

    #[test]
    fn test_command_not_found_display_regular_command() {
        let err = RsdebstrapError::command_not_found("mmdebstrap", "command");
        assert_eq!(err.to_string(), "command not found: command 'mmdebstrap' not found in PATH");
    }

    #[test]
    fn test_into_anyhow_error_command_not_found() {
        let err = RsdebstrapError::command_not_found("doas", "privilege escalation command");
        let anyhow_err: anyhow::Error = err.into();
        let downcast = anyhow_err.downcast_ref::<RsdebstrapError>();
        assert!(downcast.is_some());
        assert!(matches!(downcast.unwrap(), RsdebstrapError::CommandNotFound { .. }));
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
            source,
        };
        assert_eq!(err.to_string(), "/path/to/file.yml: I/O error: not found");
    }

    #[test]
    fn test_io_source_preserved() {
        let source = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let err = RsdebstrapError::Io {
            context: "/etc/shadow".to_string(),
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
    fn test_io_constructor_consistency() {
        let source = io::Error::new(io::ErrorKind::NotFound, "not found");
        let err = RsdebstrapError::io("/path/to/file", source);
        // Verify display uses io_error_kind_message
        assert_eq!(err.to_string(), "/path/to/file: I/O error: not found");
        match &err {
            RsdebstrapError::Io { context, source } => {
                assert_eq!(context, "/path/to/file");
                assert_eq!(source.kind(), io::ErrorKind::NotFound);
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
    fn test_execution_in_isolation_constructor() {
        let command: Vec<String> = vec!["/bin/sh".to_string(), "/tmp/task-abc.sh".to_string()];
        let err = RsdebstrapError::execution_in_isolation(&command, "chroot", "exit status: 1");
        assert_eq!(
            err.to_string(),
            "command execution failed: \"/bin/sh\" \"/tmp/task-abc.sh\" \
            (isolation: chroot): exit status: 1"
        );
    }

    #[test]
    fn test_execution_in_isolation_constructor_empty_command() {
        let command: Vec<String> = vec![];
        let err = RsdebstrapError::execution_in_isolation(&command, "mock", "exit status: 2");
        assert_eq!(err.to_string(), "command execution failed:  (isolation: mock): exit status: 2");
    }

    #[test]
    fn test_into_anyhow_error_validation() {
        let err = RsdebstrapError::Validation("test".to_string());
        let anyhow_err: anyhow::Error = err.into();
        let downcast = anyhow_err.downcast_ref::<RsdebstrapError>();
        assert!(downcast.is_some());
        assert!(matches!(downcast.unwrap(), RsdebstrapError::Validation(_)));
    }

    #[test]
    fn test_into_anyhow_error_execution() {
        let err = RsdebstrapError::Execution {
            command: "test".to_string(),
            status: "failed".to_string(),
        };
        let anyhow_err: anyhow::Error = err.into();
        let downcast = anyhow_err.downcast_ref::<RsdebstrapError>();
        assert!(downcast.is_some());
        assert!(matches!(downcast.unwrap(), RsdebstrapError::Execution { .. }));
    }

    #[test]
    fn test_into_anyhow_error_isolation() {
        let err = RsdebstrapError::Isolation("test".to_string());
        let anyhow_err: anyhow::Error = err.into();
        let downcast = anyhow_err.downcast_ref::<RsdebstrapError>();
        assert!(downcast.is_some());
        assert!(matches!(downcast.unwrap(), RsdebstrapError::Isolation(_)));
    }

    #[test]
    fn test_into_anyhow_error_config() {
        let err = RsdebstrapError::Config("test".to_string());
        let anyhow_err: anyhow::Error = err.into();
        let downcast = anyhow_err.downcast_ref::<RsdebstrapError>();
        assert!(downcast.is_some());
        assert!(matches!(downcast.unwrap(), RsdebstrapError::Config(_)));
    }

    #[test]
    fn test_into_anyhow_error_io() {
        let err = RsdebstrapError::io("/path", io::Error::new(io::ErrorKind::NotFound, "test"));
        let anyhow_err: anyhow::Error = err.into();
        let downcast = anyhow_err.downcast_ref::<RsdebstrapError>();
        assert!(downcast.is_some());
        assert!(matches!(downcast.unwrap(), RsdebstrapError::Io { .. }));
    }

    #[test]
    fn test_io_display_permission_denied() {
        let source = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let err = RsdebstrapError::io("/etc/shadow", source);
        assert_eq!(err.to_string(), "/etc/shadow: I/O error: permission denied");
    }

    #[test]
    fn test_from_anyhow_or_validation_preserves_typed_error() {
        let original = RsdebstrapError::Config("test error".to_string());
        let anyhow_err: anyhow::Error = original.into();
        let result = RsdebstrapError::from_anyhow_or_validation(anyhow_err);
        assert!(
            matches!(&result, RsdebstrapError::Config(msg) if msg == "test error"),
            "expected Config variant, got: {:?}",
            result
        );
    }

    #[test]
    fn test_from_anyhow_or_validation_wraps_non_typed_error() {
        let anyhow_err = anyhow::anyhow!("some generic error");
        let result = RsdebstrapError::from_anyhow_or_validation(anyhow_err);
        assert!(
            matches!(
                &result,
                RsdebstrapError::Validation(msg) if msg.contains("some generic error")
            ),
            "expected Validation variant, got: {:?}",
            result
        );
    }

    #[test]
    fn test_io_display_is_a_directory() {
        let source = io::Error::new(io::ErrorKind::IsADirectory, "is a directory");
        let err = RsdebstrapError::io("/path/to/dir", source);
        assert_eq!(err.to_string(), "/path/to/dir: I/O error: is a directory");
    }
}
