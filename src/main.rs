mod backends;
mod cli;
mod config;
mod executor;
mod provisioners;

use anyhow::{Context, Result};
use clap::CommandFactory;
use clap_complete::generate;
use std::io;
use tracing::{info, warn};
use tracing_subscriber::FmtSubscriber;
use tracing_subscriber::filter::LevelFilter;

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
            let profile = config::load_profile(opts.file.as_path())
                .with_context(|| format!("failed to load profile from {}", opts.file))?;
            profile.validate().context("profile validation failed")?;

            if !opts.dry_run && !profile.dir.exists() {
                std::fs::create_dir_all(&profile.dir)
                    .with_context(|| format!("failed to create directory: {}", profile.dir))?;
            }

            let executor = executor::RealCommandExecutor {
                dry_run: opts.dry_run,
            };

            // Bootstrap phase
            let backend = profile.bootstrap.as_backend();
            let command_name = backend.command_name();

            let args = backend
                .build_args(&profile.dir)
                .with_context(|| format!("failed to build arguments for {}", command_name))?;

            executor
                .execute(command_name, &args)
                .with_context(|| format!("failed to execute {}", command_name))?;

            // Provisioning phase
            if !profile.provisioners.is_empty() {
                info!(
                    "starting provisioning phase with {} provisioner(s)",
                    profile.provisioners.len()
                );

                // Determine rootfs path based on bootstrap configuration
                match backend.rootfs_output(&profile.dir) {
                    Ok(backends::RootfsOutput::Directory(rootfs)) => {
                        for (index, provisioner_config) in profile.provisioners.iter().enumerate() {
                            info!(
                                "running provisioner {}/{}",
                                index + 1,
                                profile.provisioners.len()
                            );
                            let provisioner = provisioner_config.as_provisioner();
                            provisioner
                                .provision(&rootfs, &executor, opts.dry_run)
                                .with_context(|| {
                                    format!("failed to run provisioner {}", index + 1)
                                })?;
                        }

                        info!("provisioning phase completed successfully");
                    }
                    Ok(backends::RootfsOutput::NonDirectory { reason }) => warn!(
                        "skipping provisioners: {}. \
                        Provisioners are only supported for directory-based bootstrap targets. \
                        For archive-based targets (tar, squashfs, etc.), \
                        consider using backend-specific hooks instead.",
                        reason
                    ),
                    Err(e) => return Err(e),
                }
            }
        }
        cli::Commands::Validate(opts) => {
            let profile = config::load_profile(opts.file.as_path())?;
            profile.validate().context("profile validation failed")?;
            info!("validation successful:\n{:#?}", profile);
        }
        cli::Commands::Completions(_) => {
            unreachable!("completions handled earlier");
        }
    }

    Ok(())
}
