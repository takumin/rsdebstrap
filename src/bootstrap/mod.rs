//! Bootstrap backend implementations.
//!
//! This module provides the trait and implementations for different
//! bootstrap tools (mmdebstrap, debootstrap, etc.).

use anyhow::Result;
use url::Url;

mod args;
pub mod config;
pub mod debootstrap;
pub mod mmdebstrap;

pub use args::{CommandArgsBuilder, FlagValueStyle};
pub use config::Bootstrap;

/// Output classification for pipeline task rootfs usage.
#[derive(Debug)]
pub enum RootfsOutput {
    /// Directory output that can be used for pipeline tasks.
    Directory(camino::Utf8PathBuf),
    /// Non-directory output with a reason.
    NonDirectory { reason: String },
}

/// Trait for bootstrap backend implementations.
///
/// Each bootstrap tool (mmdebstrap, debootstrap, etc.) implements this trait
/// to provide tool-specific command building logic.
pub trait BootstrapBackend {
    /// Returns the command name to execute (e.g., "mmdebstrap", "debootstrap").
    fn command_name(&self) -> &str;

    /// Builds the command-line arguments for the bootstrap command.
    ///
    /// # Arguments
    /// * `output_dir` - The base output directory path
    ///
    /// # Returns
    /// A vector of command-line arguments to pass to the bootstrap tool.
    fn build_args(&self, output_dir: &camino::Utf8Path) -> Result<Vec<String>>;

    /// Returns the rootfs output classification for pipeline task usage.
    fn rootfs_output(&self, output_dir: &camino::Utf8Path) -> Result<RootfsOutput>;

    /// Logs the final command arguments at debug level.
    ///
    /// URL credentials in arguments are masked before logging.
    fn log_command_args(&self, args: &[String]) {
        let name = self.command_name();
        tracing::debug!(
            "{name} would run: {name} {}",
            args.iter()
                .map(|s| sanitize_credential(s))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
}

/// Masks password components in URL strings to prevent credential leakage in logs.
///
/// Handles both bare URLs (`http://user:pass@host/path`) and flag-prefixed URLs
/// (`--flag=http://user:pass@host/path`).
fn sanitize_credential(arg: &str) -> String {
    if !arg.contains("://") {
        return arg.to_string();
    }

    // Try parsing the whole argument as a URL.
    if let Ok(mut parsed) = Url::parse(arg) {
        if parsed.password().is_some() {
            let _ = parsed.set_password(Some("***"));
            return parsed.to_string();
        }
        return arg.to_string();
    }

    // Try `--flag=<url>` form.
    if let Some((prefix, url_part)) = arg.split_once('=')
        && let Ok(mut parsed) = Url::parse(url_part)
        && parsed.password().is_some()
    {
        let _ = parsed.set_password(Some("***"));
        return format!("{prefix}={parsed}");
    }

    arg.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_credential_no_password() {
        assert_eq!(sanitize_credential("http://example.com/path"), "http://example.com/path");
    }

    #[test]
    fn sanitize_credential_with_password() {
        assert_eq!(
            sanitize_credential("http://user:secret@example.com/path"),
            "http://user:***@example.com/path"
        );
    }

    #[test]
    fn sanitize_credential_flag_with_password_url() {
        assert_eq!(
            sanitize_credential("--mirror=http://user:secret@example.com/debian"),
            "--mirror=http://user:***@example.com/debian"
        );
    }

    #[test]
    fn sanitize_credential_non_url_string() {
        assert_eq!(sanitize_credential("--suite=trixie"), "--suite=trixie");
    }
}
