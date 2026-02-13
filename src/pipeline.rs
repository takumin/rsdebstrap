//! Pipeline orchestrator for executing tasks in phases.
//!
//! The pipeline manages per-task isolation contexts and executes
//! tasks in three ordered phases:
//!
//! 1. **Prepare** — preparation tasks before main provisioning
//! 2. **Provision** — main configuration tasks (e.g., package installation, config)
//! 3. **Assemble** — finalization tasks (e.g., cleanup scripts, image creation)
//!
//! Each task gets its own isolation context based on its resolved isolation setting.

use anyhow::{Context, Result};
use camino::Utf8Path;
use std::sync::Arc;
use tracing::{debug, info};

use crate::error::RsdebstrapError;
use crate::executor::CommandExecutor;
use crate::isolation::{DirectProvider, IsolationProvider};
use crate::phase::{AssembleTask, PhaseItem, PrepareTask, ProvisionTask};

// Phase name constants to avoid duplication between validate() and run_phases()
const PHASE_PREPARE: &str = "prepare";
const PHASE_PROVISION: &str = "provision";
const PHASE_ASSEMBLE: &str = "assemble";

/// Pipeline orchestrator for executing tasks in phases.
///
/// Borrows task slices from the profile configuration. The pipeline is
/// responsible for:
/// - Creating per-task isolation contexts
/// - Executing tasks in the correct phase order
/// - Error handling with guaranteed teardown per task
pub struct Pipeline<'a> {
    prepare: &'a [PrepareTask],
    provision: &'a [ProvisionTask],
    assemble: &'a [AssembleTask],
}

impl<'a> Pipeline<'a> {
    /// Creates a new pipeline with the given task phases.
    pub fn new(
        prepare: &'a [PrepareTask],
        provision: &'a [ProvisionTask],
        assemble: &'a [AssembleTask],
    ) -> Self {
        Self {
            prepare,
            provision,
            assemble,
        }
    }

    /// Returns true if the pipeline has no tasks to execute.
    pub fn is_empty(&self) -> bool {
        self.prepare.is_empty() && self.provision.is_empty() && self.assemble.is_empty()
    }

    /// Returns the total number of tasks across all phases.
    pub fn total_tasks(&self) -> usize {
        self.prepare.len() + self.provision.len() + self.assemble.len()
    }

    /// Validates all tasks in the pipeline.
    pub fn validate(&self) -> Result<(), RsdebstrapError> {
        validate_phase_items(PHASE_PREPARE, self.prepare)?;
        validate_phase_items(PHASE_PROVISION, self.provision)?;
        validate_phase_items(PHASE_ASSEMBLE, self.assemble)?;
        Ok(())
    }

    /// Executes all phases of the pipeline with per-task isolation contexts.
    ///
    /// If the pipeline has no tasks, returns immediately. Otherwise, runs
    /// all three phases in order, creating isolation contexts for each task
    /// based on its resolved isolation setting.
    pub fn run(
        &self,
        rootfs: &Utf8Path,
        executor: Arc<dyn CommandExecutor>,
        dry_run: bool,
    ) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }

        info!("starting pipeline with {} task(s)", self.total_tasks());
        self.run_phases(rootfs, &executor, dry_run)?;
        info!("pipeline completed successfully");
        Ok(())
    }

    fn run_phases(
        &self,
        rootfs: &Utf8Path,
        executor: &Arc<dyn CommandExecutor>,
        dry_run: bool,
    ) -> Result<()> {
        run_phase_items(PHASE_PREPARE, self.prepare, rootfs, executor, dry_run)?;
        run_phase_items(PHASE_PROVISION, self.provision, rootfs, executor, dry_run)?;
        run_phase_items(PHASE_ASSEMBLE, self.assemble, rootfs, executor, dry_run)?;
        Ok(())
    }
}

fn run_phase_items<T: PhaseItem>(
    phase_name: &str,
    tasks: &[T],
    rootfs: &Utf8Path,
    executor: &Arc<dyn CommandExecutor>,
    dry_run: bool,
) -> Result<()> {
    if tasks.is_empty() {
        debug!("skipping empty {} phase", phase_name);
        return Ok(());
    }

    info!("running {} phase ({} task(s))", phase_name, tasks.len());

    for (index, task) in tasks.iter().enumerate() {
        info!("running {} {}/{}: {}", phase_name, index + 1, tasks.len(), task.name());
        run_task_item(task, rootfs, executor, dry_run)
            .with_context(|| format!("failed to run {} {}", phase_name, index + 1))?;
    }

    Ok(())
}

/// Runs a single task with its own isolation context.
///
/// Creates the appropriate provider based on the task's resolved isolation
/// config, sets up the context, executes the task, and ensures teardown.
fn run_task_item<T: PhaseItem>(
    task: &T,
    rootfs: &Utf8Path,
    executor: &Arc<dyn CommandExecutor>,
    dry_run: bool,
) -> Result<()> {
    let provider: Box<dyn IsolationProvider> = match task.resolved_isolation_config() {
        Some(config) => config.as_provider(),
        None => Box::new(DirectProvider),
    };

    let mut ctx = provider
        .setup(rootfs, executor.clone(), dry_run)
        .context("failed to setup isolation context")?;

    let run_result = task.execute(ctx.as_ref());
    let teardown_result = ctx.teardown();

    match (run_result, teardown_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Ok(())) => Err(e),
        (Ok(()), Err(e)) => Err(e).context("failed to teardown isolation context"),
        (Err(run_err), Err(tear_err)) => {
            Err(run_err.context(format!("additionally, teardown failed: {:#}", tear_err)))
        }
    }
}

/// Validates all tasks in a single phase, enriching errors with phase context.
///
/// For `Validation` errors, prepends the phase name and task index to the message.
/// For `Io` errors, prepends the phase context to the `context` field while
/// preserving the `source` for programmatic inspection.
/// Other error variants are wrapped in `Validation` with phase context for
/// forward-compatibility, ensuring no future variant loses phase information.
fn validate_phase_items<T: PhaseItem>(
    phase_name: &str,
    tasks: &[T],
) -> Result<(), RsdebstrapError> {
    for (index, task) in tasks.iter().enumerate() {
        task.validate().map_err(|e| match e {
            RsdebstrapError::Validation(msg) => RsdebstrapError::Validation(format!(
                "{} {} validation failed: {}",
                phase_name,
                index + 1,
                msg
            )),
            RsdebstrapError::Io { context, source } => RsdebstrapError::Io {
                context: format!("{} {} validation failed: {}", phase_name, index + 1, context),
                source,
            },
            other => RsdebstrapError::Validation(format!(
                "{} {} validation failed: {}",
                phase_name,
                index + 1,
                other
            )),
        })?;
    }
    Ok(())
}
