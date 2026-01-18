mod backends;
mod cli;
mod config;
mod executor;

use anyhow::Result;
use clap::CommandFactory;
use clap_complete::generate;
use std::io;
use std::process;
use tracing::{error, info};
use tracing_subscriber::FmtSubscriber;
use tracing_subscriber::filter::LevelFilter;

use crate::backends::BootstrapBackend;
use crate::executor::CommandExecutor;

fn main() -> Result<()> {
    let args = cli::parse_args()?;

    // Handle completions subcommand before setting up logging
    // (completion output should be clean without any logging)
    if let cli::Commands::Completions(opts) = &args.command {
        let mut cmd = cli::Cli::command();
        generate(opts.shell, &mut cmd, "rsdebstrap", &mut io::stdout());
        return Ok(());
    }

    let log_level = match &args.command {
        cli::Commands::Apply(opts) => opts.log_level,
        cli::Commands::Validate(opts) => opts.log_level,
        cli::Commands::Completions(_) => unreachable!("completions handled above"),
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
                        error!("failed to create directory: {}: {}", profile.dir, e);
                        process::exit(1);
                    }
                }
            }
            let executor = executor::RealCommandExecutor {
                dry_run: opts.dry_run,
            };

            // Get command name and args based on bootstrap backend
            let (command_name, args) = match &profile.bootstrap {
                config::Bootstrap::Mmdebstrap(cfg) => {
                    let args = match cfg.build_args(&profile.dir) {
                        Ok(a) => a,
                        Err(e) => {
                            error!("failed to build mmdebstrap args: {}", e);
                            process::exit(1);
                        }
                    };
                    (cfg.command_name(), args)
                }
                config::Bootstrap::Debootstrap(cfg) => {
                    let args = match cfg.build_args(&profile.dir) {
                        Ok(a) => a,
                        Err(e) => {
                            error!("failed to build debootstrap args: {}", e);
                            process::exit(1);
                        }
                    };
                    (cfg.command_name(), args)
                }
            };

            match executor.execute(command_name, &args) {
                Ok(_) => {}
                Err(e) => {
                    error!("failed to run {}: {}", command_name, e);
                    process::exit(1);
                }
            }
        }
        cli::Commands::Validate(opts) => {
            let profile = config::load_profile(opts.file.as_path())?;
            info!("validation successful:\n{:#?}", profile);
        }
        cli::Commands::Completions(_) => {
            unreachable!("completions handled earlier");
        }
    }

    Ok(())
}
