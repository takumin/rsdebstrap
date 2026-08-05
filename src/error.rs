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

    /// The user-facing prefix each variant renders with. One table keeps the
    /// wording of every string-carrying variant in a single place; the
    /// constructor tests below cover the variants whose `Display` output is
    /// assembled rather than interpolated verbatim.
    #[test]
    fn test_variant_display_prefixes() {
        let cases = [
            (RsdebstrapError::Validation("boom".to_string()), "validation error: boom"),
            (RsdebstrapError::Isolation("boom".to_string()), "isolation error: boom"),
            (RsdebstrapError::Config("boom".to_string()), "configuration error: boom"),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }
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
    fn test_io_constructor_consistency() {
        let source = io::Error::new(io::ErrorKind::NotFound, "not found");
        let err = RsdebstrapError::io("/path/to/file", source);
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

    /// Every variant survives the trip through `anyhow::Error` as its own type, so
    /// callers can still `downcast_ref` and branch on the variant. One case per
    /// variant guards against a future hand-written `From` impl that flattens one.
    #[test]
    fn test_every_variant_is_recoverable_from_anyhow() {
        let cases: Vec<RsdebstrapError> = vec![
            RsdebstrapError::Validation("test".to_string()),
            RsdebstrapError::Execution {
                command: "test".to_string(),
                status: "failed".to_string(),
            },
            RsdebstrapError::Isolation("test".to_string()),
            RsdebstrapError::Config("test".to_string()),
            RsdebstrapError::io("/path", io::Error::new(io::ErrorKind::NotFound, "test")),
            RsdebstrapError::command_not_found("doas", "privilege escalation command"),
        ];

        for original in cases {
            let expected = format!("{:?}", original);
            let anyhow_err: anyhow::Error = original.into();
            let recovered = anyhow_err
                .downcast_ref::<RsdebstrapError>()
                .unwrap_or_else(|| panic!("expected RsdebstrapError for {}", expected));
            assert_eq!(
                format!("{:?}", recovered),
                expected,
                "variant changed while passing through anyhow::Error",
            );
        }
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
}
