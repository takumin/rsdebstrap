use anyhow::Result;
use camino::Utf8PathBuf;
use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = env!("CARGO_PKG_NAME"),
    version = env!("CARGO_PKG_VERSION"),
    author = env!("CARGO_PKG_AUTHORS"),
    about = env!("CARGO_PKG_DESCRIPTION"),
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Apply the given profile to run mmdebstrap
    Apply(ApplyArgs),

    /// Validate the given YAML profile
    Validate(ValidateArgs),
}

#[derive(Args, Debug)]
pub struct ApplyArgs {
    /// Path to the YAML file defining the profile
    #[arg(short, long, default_value = "profile.yaml")]
    pub file: Utf8PathBuf,

    /// Set the log level
    #[arg(short, long, default_value = "info")]
    pub log_level: LogLevel,

    /// Do not run, just show what would be done
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct ValidateArgs {
    /// Path to the YAML file to validate
    #[arg(short, long, default_value = "profile.yaml")]
    pub file: Utf8PathBuf,

    /// Set the log level
    #[arg(short, long, default_value = "info")]
    pub log_level: LogLevel,
}

/// Represents log levels for controlling the verbosity of logging output.
///
/// This enum maps directly to the log levels used by the `tracing` crate:
/// - `Trace`: Designates very detailed application-level information.
/// - `Debug`: Designates information useful for debugging.
/// - `Info`: Designates general operational messages.
/// - `Warn`: Designates potentially harmful situations.
/// - `Error`: Designates error events that might still allow the application to continue running.
///
/// The `LogLevel` enum is used in CLI commands (`Apply` and `Validate`) to set the desired
/// verbosity level for logging. For example, specifying `--log-level debug` will enable
/// debug-level logging output.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

pub fn parse_args() -> Result<Cli> {
    Ok(Cli::parse())
}
