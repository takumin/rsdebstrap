use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

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
    #[arg(short, long)]
    pub file: Option<String>,

    /// Do not run, just show what would be done
    #[arg(long)]
    pub dry_run: bool,

    /// Enable debug output
    #[arg(long)]
    pub debug: bool,
}

#[derive(Args, Debug)]
pub struct ValidateArgs {
    /// Path to the YAML file to validate
    #[arg(short, long)]
    pub file: String,
}

pub fn parse_args() -> Result<Cli> {
    Cli::try_parse().with_context(|| "failed to parse command line arguments")
}
