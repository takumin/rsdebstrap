pub mod bootstrap;
pub mod cli;
pub mod config;
pub mod error;
pub mod executor;
pub mod isolation;
pub mod pipeline;
pub mod task;

pub use error::RsdebstrapError;

use std::fs;
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::{info, warn};
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

/// Executes the bootstrap phase using the configured backend.
fn run_bootstrap_phase(
    profile: &config::Profile,
    executor: &Arc<dyn CommandExecutor>,
) -> Result<()> {
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
        let status_display = result
            .status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown (no status available)".to_string());
        return Err(RsdebstrapError::execution(&spec, status_display).into());
    }

    Ok(())
}

/// Executes the pipeline phase (pre-processors, provisioners, post-processors).
fn run_pipeline_phase(
    profile: &config::Profile,
    executor: Arc<dyn CommandExecutor>,
    dry_run: bool,
) -> Result<()> {
    let pipeline = profile.pipeline();

    if pipeline.is_empty() {
        return Ok(());
    }

    // Get rootfs directory (validation ensures it's a directory if tasks exist)
    let backend = profile.bootstrap.as_backend();
    let bootstrap::RootfsOutput::Directory(rootfs) = backend.rootfs_output(&profile.dir)? else {
        return Err(RsdebstrapError::Validation(
            "pipeline tasks require directory output but bootstrap is configured for \
            non-directory format. Please set bootstrap format to 'directory' or remove \
            pipeline tasks."
                .to_string(),
        )
        .into());
    };

    let provider = profile.isolation.as_provider();
    pipeline.run(&rootfs, provider.as_ref(), executor, dry_run)
}

pub fn run_apply(opts: &cli::ApplyArgs, executor: Arc<dyn CommandExecutor>) -> Result<()> {
    if opts.dry_run {
        warn!("DRY-RUN MODE: No changes will be made");
    }

    let profile = config::load_profile(opts.file.as_path())
        .with_context(|| format!("failed to load profile from {}", opts.file))?;
    profile.validate().context("profile validation failed")?;

    if !opts.dry_run && !profile.dir.exists() {
        fs::create_dir_all(&profile.dir)
            .with_context(|| format!("failed to create directory: {}", profile.dir))?;
    }

    run_bootstrap_phase(&profile, &executor)?;
    run_pipeline_phase(&profile, executor, opts.dry_run)?;

    Ok(())
}

pub fn run_validate(opts: &cli::ValidateArgs) -> Result<()> {
    let profile = config::load_profile(opts.file.as_path())
        .with_context(|| format!("failed to load profile from {}", opts.file))?;
    profile.validate().context("profile validation failed")?;
    info!("validation successful:\n{:#?}", profile);
    Ok(())
}
