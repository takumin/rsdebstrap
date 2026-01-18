mod backends;
mod cli;
mod config;
mod executor;
mod provisioners;

use anyhow::{Context, Result};
use camino::Utf8PathBuf;
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
                match determine_rootfs_path(&profile) {
                    Ok(rootfs) => {
                        for (index, provisioner_config) in profile.provisioners.iter().enumerate() {
                            info!(
                                "running provisioner {}/{}",
                                index + 1,
                                profile.provisioners.len()
                            );
                            let provisioner = provisioner_config.as_provisioner();
                            provisioner.provision(&rootfs, &executor).with_context(|| {
                                format!("failed to run provisioner {}", index + 1)
                            })?;
                        }

                        info!("provisioning phase completed successfully");
                    }
                    Err(e) => {
                        warn!(
                            "skipping provisioners: {}. \
                            Provisioners are only supported for directory-based bootstrap targets. \
                            For archive-based targets (tar, squashfs, etc.), \
                            consider using backend-specific hooks instead.",
                            e
                        );
                    }
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

/// Determines the rootfs path from the profile.
///
/// For directory-based outputs, returns the output directory.
/// For archive-based outputs (tar, squashfs, etc.), returns an error
/// as provisioners require a directory to chroot into.
fn determine_rootfs_path(profile: &config::Profile) -> Result<Utf8PathBuf> {
    match &profile.bootstrap {
        config::Bootstrap::Debootstrap(cfg) => {
            // debootstrap always outputs to directory
            Ok(profile.dir.join(&cfg.target))
        }
        config::Bootstrap::Mmdebstrap(cfg) => {
            // Check if target is a directory or archive
            let target_path = profile.dir.join(&cfg.target);

            // If target has an extension, it's likely an archive format
            if target_path.extension().is_some() {
                anyhow::bail!(
                    "archive target detected: {}",
                    target_path.file_name().unwrap_or("unknown")
                );
            }

            Ok(target_path)
        }
    }
}
