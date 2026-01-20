pub mod bootstrap;
pub mod cli;
pub mod config;
pub mod executor;
pub mod provisioners;

use std::fs;

use anyhow::{Context, Result};
use tracing::info;
use tracing_subscriber::{FmtSubscriber, filter::LevelFilter};

use crate::executor::CommandExecutor;

pub fn init_logging(log_level: cli::LogLevel) -> Result<()> {
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
    .context("failed to set global default tracing subscriber")
}

pub fn run_apply(opts: &cli::ApplyArgs, executor: &dyn CommandExecutor) -> Result<()> {
    let profile = config::load_profile(opts.file.as_path())
        .with_context(|| format!("failed to load profile from {}", opts.file))?;
    profile.validate().context("profile validation failed")?;

    if !opts.dry_run && !profile.dir.exists() {
        fs::create_dir_all(&profile.dir)
            .with_context(|| format!("failed to create directory: {}", profile.dir))?;
    }

    // Bootstrap phase
    let backend = profile.bootstrap.as_backend();
    let command_name = backend.command_name();

    let args = backend
        .build_args(&profile.dir)
        .with_context(|| format!("failed to build arguments for {}", command_name))?;

    let spec = executor::CommandSpec::new(command_name, args);
    let result = executor
        .execute(&spec)
        .with_context(|| format!("failed to execute {}", command_name))?;

    if !result.success() {
        anyhow::bail!(
            "{} exited with non-zero status: {}. Spec: {:?}",
            command_name,
            result.status.expect("status should be present on failure"),
            spec
        );
    }

    // Provisioning phase
    if !profile.provisioners.is_empty() {
        info!("starting provisioning phase with {} provisioner(s)", profile.provisioners.len());

        // Get rootfs directory (validation ensures it's a directory if provisioners exist)
        let bootstrap::RootfsOutput::Directory(rootfs) = backend.rootfs_output(&profile.dir)? else {
            unreachable!("validation should have caught provisioners with non-directory output")
        };

        for (index, provisioner_config) in profile.provisioners.iter().enumerate() {
            info!("running provisioner {}/{}", index + 1, profile.provisioners.len());
            let provisioner = provisioner_config.as_provisioner();
            provisioner
                .provision(&rootfs, executor, opts.dry_run)
                .with_context(|| format!("failed to run provisioner {}", index + 1))?;
        }

        info!("provisioning phase completed successfully");
    }

    Ok(())
}

pub fn run_validate(opts: &cli::ValidateArgs) -> Result<()> {
    let profile = config::load_profile(opts.file.as_path())?;
    profile.validate().context("profile validation failed")?;
    info!("validation successful:\n{:#?}", profile);
    Ok(())
}
