mod cli;
mod command;
mod config;
mod runner;

use anyhow::Result;
use std::process;
use tracing::{error, info};
use tracing_subscriber::FmtSubscriber;
use tracing_subscriber::filter::LevelFilter;

fn main() -> Result<()> {
    let args = cli::parse_args()?;

    let log_level = match &args.command {
        cli::Commands::Apply(opts) => opts.log_level,
        cli::Commands::Validate(opts) => opts.log_level,
    };

    let filter = match log_level {
        cli::LogLevel::Trace => LevelFilter::TRACE,
        cli::LogLevel::Debug => LevelFilter::DEBUG,
        cli::LogLevel::Info => LevelFilter::INFO,
        cli::LogLevel::Warn => LevelFilter::WARN,
        cli::LogLevel::Error => LevelFilter::ERROR,
    };

    tracing::subscriber::set_global_default(
        FmtSubscriber::builder().with_max_level(filter).finish(),
    )
    .expect("failed to set global default tracing subscriber");

    match &args.command {
        cli::Commands::Apply(opts) => {
            let profile = match config::load_profile(opts.file.as_path()) {
                Ok(p) => p,
                Err(e) => {
                    error!("error load profile: {}", e);
                    process::exit(1);
                }
            };
            if !opts.dry_run && !profile.dir.exists() {
                match std::fs::create_dir_all(&profile.dir) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("error create directory: {}", e);
                        process::exit(1);
                    }
                }
            }
            match runner::run_mmdebstrap(&profile, opts.dry_run) {
                Ok(_) => {}
                Err(e) => {
                    error!("error running mmdebstrap: {}", e);
                    process::exit(1);
                }
            }
        }
        cli::Commands::Validate(opts) => {
            let profile = config::load_profile(opts.file.as_path())?;
            info!("validation successful:\n{:#?}", profile);
        }
    }

    Ok(())
}
