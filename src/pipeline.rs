//! Pipeline orchestrator for executing tasks in phases.
//!
//! The pipeline manages the lifecycle of an isolation context and executes
//! tasks in three ordered phases:
//!
//! 1. **Pre-processors** — preparation tasks before main provisioning
//! 2. **Provisioners** — main configuration tasks (e.g., package installation, config)
//! 3. **Post-processors** — finalization tasks (e.g., cleanup scripts)
//!
//! Isolation setup/teardown is handled once for all phases.

use anyhow::{Context, Result};
use camino::Utf8Path;
use std::sync::Arc;
use tracing::{debug, info};

use crate::error::RsdebstrapError;
use crate::executor::CommandExecutor;
use crate::isolation::{IsolationContext, IsolationProvider};
use crate::task::TaskDefinition;

// Phase name constants to avoid duplication between validate() and run_phases()
const PHASE_PRE_PROCESSOR: &str = "pre-processor";
const PHASE_PROVISIONER: &str = "provisioner";
const PHASE_POST_PROCESSOR: &str = "post-processor";

/// Pipeline orchestrator for executing tasks in phases.
///
/// Borrows task slices from the profile configuration. The pipeline is
/// responsible for:
/// - Setting up and tearing down the isolation context
/// - Executing tasks in the correct phase order
/// - Error handling with guaranteed teardown
pub struct Pipeline<'a> {
    pre_processors: &'a [TaskDefinition],
    provisioners: &'a [TaskDefinition],
    post_processors: &'a [TaskDefinition],
}

impl<'a> Pipeline<'a> {
    /// Creates a new pipeline with the given task phases.
    pub fn new(
        pre_processors: &'a [TaskDefinition],
        provisioners: &'a [TaskDefinition],
        post_processors: &'a [TaskDefinition],
    ) -> Self {
        Self {
            pre_processors,
            provisioners,
            post_processors,
        }
    }

    /// Returns the ordered list of phases with their names and task slices.
    fn phases(&self) -> [(&'static str, &'a [TaskDefinition]); 3] {
        [
            (PHASE_PRE_PROCESSOR, self.pre_processors),
            (PHASE_PROVISIONER, self.provisioners),
            (PHASE_POST_PROCESSOR, self.post_processors),
        ]
    }

    /// Returns true if the pipeline has no tasks to execute.
    pub fn is_empty(&self) -> bool {
        self.phases().iter().all(|(_, tasks)| tasks.is_empty())
    }

    /// Returns the total number of tasks across all phases.
    pub fn total_tasks(&self) -> usize {
        self.phases().iter().map(|(_, tasks)| tasks.len()).sum()
    }

    /// Validates all tasks in the pipeline.
    pub fn validate(&self) -> Result<(), RsdebstrapError> {
        for (phase_name, tasks) in &self.phases() {
            self.validate_phase(phase_name, tasks)?;
        }
        Ok(())
    }

    /// Executes all phases of the pipeline within an isolation context.
    ///
    /// If the pipeline has no tasks, returns immediately without setting up
    /// the isolation context. Otherwise, sets up the isolation context, runs
    /// all three phases in order, and ensures teardown happens even if a
    /// phase fails.
    pub fn run(
        &self,
        rootfs: &Utf8Path,
        provider: &dyn IsolationProvider,
        executor: Arc<dyn CommandExecutor>,
        dry_run: bool,
    ) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }

        info!("starting pipeline with {} task(s)", self.total_tasks());

        // Setup isolation context
        let mut ctx = provider
            .setup(rootfs, executor, dry_run)
            .context("failed to setup isolation context")?;

        // Run phases, ensuring teardown happens even on error
        let run_result = self.run_phases(ctx.as_ref());
        let teardown_result = ctx.teardown();

        // Handle both errors, prioritizing the phase error
        match (run_result, teardown_result) {
            (Ok(()), Ok(())) => {}
            (Err(e), Ok(())) => return Err(e),
            (Ok(()), Err(e)) => return Err(e).context("failed to teardown isolation context"),
            (Err(run_err), Err(tear_err)) => {
                return Err(
                    run_err.context(format!("additionally, teardown failed: {:#}", tear_err))
                );
            }
        }

        info!("pipeline completed successfully");
        Ok(())
    }

    fn run_phases(&self, ctx: &dyn IsolationContext) -> Result<()> {
        for (phase_name, tasks) in &self.phases() {
            self.run_phase(phase_name, tasks, ctx)?;
        }
        Ok(())
    }

    fn run_phase(
        &self,
        phase_name: &str,
        tasks: &[TaskDefinition],
        ctx: &dyn IsolationContext,
    ) -> Result<()> {
        if tasks.is_empty() {
            debug!("skipping empty {} phase", phase_name);
            return Ok(());
        }

        info!("running {} phase ({} task(s))", phase_name, tasks.len());

        for (index, task) in tasks.iter().enumerate() {
            info!("running {} {}/{}: {}", phase_name, index + 1, tasks.len(), task.name());
            task.execute(ctx)
                .with_context(|| format!("failed to run {} {}", phase_name, index + 1))?;
        }

        Ok(())
    }

    /// Validates all tasks in a single phase, enriching errors with phase context.
    ///
    /// For `Validation` errors, prepends the phase name and task index to the message.
    /// For `Io` errors, prepends the phase context to the `context` field while
    /// preserving the `source` for programmatic inspection.
    /// Other error variants are wrapped in `Validation` with phase context for
    /// forward-compatibility, ensuring no future variant loses phase information.
    fn validate_phase(
        &self,
        phase_name: &str,
        tasks: &[TaskDefinition],
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
}
