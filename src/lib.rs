pub mod bootstrap;
pub mod cli;
pub mod config;
pub mod executor;
pub mod isolation;
pub mod provisioners;

use std::fs;
use std::sync::Arc;

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
        anyhow::bail!(
            "{} exited with non-zero status: {}. Spec: {:?}",
            command_name,
            result.status.expect("status should be present on failure"),
            spec
        );
    }

    Ok(())
}

/// Executes the provisioning phase for all configured provisioners.
fn run_provision_phase(
    profile: &config::Profile,
    executor: Arc<dyn CommandExecutor>,
    dry_run: bool,
) -> Result<()> {
    if profile.provisioners.is_empty() {
        return Ok(());
    }

    info!("starting provisioning phase with {} provisioner(s)", profile.provisioners.len());

    // Get rootfs directory (validation ensures it's a directory if provisioners exist)
    let backend = profile.bootstrap.as_backend();
    let bootstrap::RootfsOutput::Directory(rootfs) = backend.rootfs_output(&profile.dir)? else {
        anyhow::bail!(
            "provisioners require directory output but got non-directory format. \
            This should have been caught during validation."
        );
    };

    // Setup isolation context
    let provider = profile.isolation.as_provider();
    let mut context = provider
        .setup(&rootfs, executor, dry_run)
        .context("failed to setup isolation context")?;

    // Run provisioners, ensuring teardown happens even on error
    let provision_result = (|| -> anyhow::Result<()> {
        for (index, provisioner_config) in profile.provisioners.iter().enumerate() {
            info!("running provisioner {}/{}", index + 1, profile.provisioners.len());
            let provisioner = provisioner_config.as_provisioner();
            provisioner
                .provision(context.as_ref(), dry_run)
                .with_context(|| format!("failed to run provisioner {}", index + 1))?;
        }
        Ok(())
    })();

    // Teardown isolation context (always run, even on provisioner error)
    let teardown_result = context.teardown();

    // Handle both errors, chaining if both fail
    match (provision_result, teardown_result) {
        (Ok(()), Ok(())) => {}
        (Err(e), Ok(())) => return Err(e),
        (Ok(()), Err(e)) => return Err(e).context("failed to teardown isolation context"),
        (Err(prov_err), Err(tear_err)) => {
            // Provisioning error is primary; log teardown error separately
            tracing::error!("isolation context teardown also failed: {:#}", tear_err);
            return Err(prov_err);
        }
    }

    info!("provisioning phase completed successfully");
    Ok(())
}

pub fn run_apply(opts: &cli::ApplyArgs, executor: Arc<dyn CommandExecutor>) -> Result<()> {
    let profile = config::load_profile(opts.file.as_path())
        .with_context(|| format!("failed to load profile from {}", opts.file))?;
    profile.validate().context("profile validation failed")?;

    if !opts.dry_run && !profile.dir.exists() {
        fs::create_dir_all(&profile.dir)
            .with_context(|| format!("failed to create directory: {}", profile.dir))?;
    }

    run_bootstrap_phase(&profile, &executor)?;
    run_provision_phase(&profile, executor, opts.dry_run)?;

    Ok(())
}

pub fn run_validate(opts: &cli::ValidateArgs) -> Result<()> {
    let profile = config::load_profile(opts.file.as_path())?;
    profile.validate().context("profile validation failed")?;
    info!("validation successful:\n{:#?}", profile);
    Ok(())
}
