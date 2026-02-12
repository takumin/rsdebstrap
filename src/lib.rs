pub mod bootstrap;
pub mod cli;
pub mod config;
pub mod error;
pub mod executor;
pub mod isolation;
pub mod pipeline;
pub mod privilege;
pub mod task;

pub use error::RsdebstrapError;

use std::fs;
use std::sync::Arc;

use anyhow::{Context, Result};
use camino::Utf8Path;
use tracing::{info, warn};
use tracing_subscriber::{FmtSubscriber, filter::LevelFilter};

use crate::executor::CommandExecutor;
use crate::isolation::mount::RootfsMounts;
use crate::isolation::resolv_conf::RootfsResolvConf;

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

    let privilege = profile.bootstrap.resolved_privilege_method();
    let spec = executor::CommandSpec::new(command_name, args).with_privilege(privilege);
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

    // Set up filesystem mounts (if configured)
    let mount_entries = profile.defaults.isolation.resolved_mounts();
    let privilege = profile.defaults.privilege.as_ref().map(|d| d.method);
    let mut mounts =
        RootfsMounts::new(&rootfs, mount_entries, executor.clone(), privilege, dry_run);
    mounts
        .mount()
        .context("failed to mount filesystems in rootfs")?;

    // Set up resolv.conf (if configured)
    // setup failure is handled by Drop guards for mounts cleanup
    let mut resolv_conf = RootfsResolvConf::new(
        &rootfs,
        profile.defaults.isolation.resolv_conf().cloned(),
        Utf8Path::new("/etc/resolv.conf"),
        executor.clone(),
        privilege,
        dry_run,
    );
    resolv_conf
        .setup()
        .context("failed to set up resolv.conf in rootfs")?;

    // Run the pipeline, then tear down in reverse order:
    // resolv_conf → mounts. Each can independently succeed or fail.
    // Error priority: pipeline > resolv_conf > unmount.
    let pipeline_result = pipeline.run(&rootfs, executor, dry_run);
    let resolv_result = resolv_conf.teardown();
    let unmount_result = mounts.unmount();

    match pipeline_result {
        Err(e) => {
            if let Err(r) = resolv_result {
                tracing::error!("resolv.conf restore also failed: {:#}", r);
            }
            if let Err(u) = unmount_result {
                tracing::error!(
                    "unmount also failed after pipeline error: {:#}. \
                    Drop guard will attempt cleanup.",
                    u
                );
            }
            Err(e)
        }
        Ok(()) => match resolv_result {
            Err(e) => {
                if let Err(u) = unmount_result {
                    tracing::error!(
                        "unmount also failed after resolv.conf restore error: {:#}. \
                        Drop guard will attempt cleanup.",
                        u
                    );
                }
                Err(e)
                    .context("failed to restore resolv.conf after pipeline completed successfully")
            }
            Ok(()) => match unmount_result {
                Ok(()) => Ok(()),
                Err(e) => Err(e)
                    .context("failed to unmount filesystems after pipeline completed successfully"),
            },
        },
    }
}

pub fn run_apply(opts: &cli::ApplyArgs, executor: Arc<dyn CommandExecutor>) -> Result<()> {
    if opts.dry_run {
        warn!("DRY-RUN MODE: No changes will be made");
    }

    let profile = config::load_profile(opts.common.file.as_path())
        .with_context(|| format!("failed to load profile from {}", opts.common.file))?;
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
    let profile = config::load_profile(opts.common.file.as_path())
        .with_context(|| format!("failed to load profile from {}", opts.common.file))?;
    profile.validate().context("profile validation failed")?;
    info!("validation successful:\n{:#?}", profile);
    Ok(())
}
