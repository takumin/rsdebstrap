//! Command-line interface definitions for rsdebstrap.
//!
//! This module defines the CLI structure using the `clap` crate, including
//! all available commands, subcommands, and their respective arguments.
//! It provides a type-safe representation of the user's command-line input
//! that the application can use to determine what actions to take.

use anyhow::Result;
use camino::Utf8PathBuf;
use clap::{Args, Parser, Subcommand, ValueEnum};

/// Top-level CLI structure that serves as the entry point for parsing command-line arguments.
///
/// This struct represents the entire command-line interface for the application.
/// It contains a subcommand field that determines which operation the user wants to perform.
#[derive(Parser, Debug)]
#[command(
    name = env!("CARGO_PKG_NAME"),
    version = env!("CARGO_PKG_VERSION"),
    author = env!("CARGO_PKG_AUTHORS"),
    about = env!("CARGO_PKG_DESCRIPTION"),
)]
pub struct Cli {
    /// The subcommand to execute, defining the primary operation.
    #[command(subcommand)]
    pub command: Commands,
}

/// The available subcommands in the application.
///
/// This enum defines all possible operations that the user can invoke through the CLI.
/// Each variant corresponds to a specific operation with its associated arguments.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Apply the given profile to run mmdebstrap.
    ///
    /// This command executes mmdebstrap with the configuration specified in the profile.
    /// It reads the YAML profile, converts it to mmdebstrap arguments, and executes the command.
    Apply(ApplyArgs),

    /// Validate the given YAML profile.
    ///
    /// This command performs syntax and schema validation on the YAML profile
    /// without executing mmdebstrap. It's useful for checking if a profile
    /// is valid before attempting to apply it.
    Validate(ValidateArgs),
}

/// Arguments for the `Apply` command.
///
/// This struct defines all the arguments that can be passed to the `Apply` command.
/// It includes options for specifying the profile file, log level, and dry run mode.
#[derive(Args, Debug)]
pub struct ApplyArgs {
    /// Path to the YAML file defining the profile.
    ///
    /// This file should contain a valid rsdebstrap profile that defines
    /// how mmdebstrap should be configured and executed.
    #[arg(short, long, default_value = "profile.yaml")]
    pub file: Utf8PathBuf,

    /// Set the log level for controlling verbosity of output.
    ///
    /// This determines the amount of information logged during execution.
    /// Options range from `trace` (most verbose) to `error` (least verbose).
    #[arg(short, long, default_value = "info")]
    pub log_level: LogLevel,

    /// Do not run the actual mmdebstrap command, just show what would be done.
    ///
    /// When this flag is enabled, the application will parse the profile and
    /// construct the mmdebstrap command but will not execute it. Instead, it
    /// will display the command that would be executed.
    #[arg(long)]
    pub dry_run: bool,
}

/// Arguments for the `Validate` command.
///
/// This struct defines all the arguments that can be passed to the `Validate` command.
/// It includes options for specifying the profile file and log level.
#[derive(Args, Debug)]
pub struct ValidateArgs {
    /// Path to the YAML file to validate.
    ///
    /// This file will be checked for syntax and schema correctness
    /// according to the rsdebstrap profile specifications.
    #[arg(short, long, default_value = "profile.yaml")]
    pub file: Utf8PathBuf,

    /// Set the log level for controlling verbosity of output.
    ///
    /// This determines the amount of information logged during validation.
    /// Options range from `trace` (most verbose) to `error` (least verbose).
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

/// Parses command-line arguments into a structured `Cli` instance.
///
/// This function serves as the primary entry point for CLI argument processing.
/// It uses the `clap` crate's parsing capabilities to construct a fully populated
/// `Cli` structure from the arguments provided by the user.
///
/// # Returns
///
/// * `Result<Cli>` - A result containing the parsed CLI arguments if successful,
///   or an error if argument parsing fails.
///
/// # Examples
///
/// ```no_run
/// use rsdebstrap::cli;
///
/// fn main() -> anyhow::Result<()> {
///     let args = cli::parse_args()?;
///     match &args.command {
///         cli::Commands::Apply(opts) => {
///             // Process the apply arguments
///         }
///         cli::Commands::Validate(opts) => {
///             // Process the validate arguments
///         }
///     }
///     Ok(())
/// }
/// ```
pub fn parse_args() -> Result<Cli> {
    Ok(Cli::parse())
}
