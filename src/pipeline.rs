//! Pipeline orchestrator for executing tasks in phases.
//!
//! The pipeline manages per-task isolation contexts and executes
//! tasks in three ordered phases:
//!
//! 1. **Pre-processors** — preparation tasks before main provisioning
//! 2. **Provisioners** — main configuration tasks (e.g., package installation, config)
//! 3. **Post-processors** — finalization tasks (e.g., cleanup scripts)
//!
//! Each task gets its own isolation context based on its resolved isolation setting.

use anyhow::{Context, Result};
use camino::Utf8Path;
use std::sync::Arc;
use tracing::{debug, info};

use crate::error::RsdebstrapError;
use crate::executor::CommandExecutor;
use crate::isolation::{DirectProvider, IsolationProvider};
use crate::task::TaskDefinition;

// Phase name constants to avoid duplication between validate() and run_phases()
const PHASE_PRE_PROCESSOR: &str = "pre-processor";
const PHASE_PROVISIONER: &str = "provisioner";
const PHASE_POST_PROCESSOR: &str = "post-processor";

/// Pipeline orchestrator for executing tasks in phases.
///
/// Borrows task slices from the profile configuration. The pipeline is
/// responsible for:
/// - Creating per-task isolation contexts
/// - Executing tasks in the correct phase order
/// - Error handling with guaranteed teardown per task
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
        self.phases().into_iter().all(|(_, tasks)| tasks.is_empty())
    }

    /// Returns the total number of tasks across all phases.
    pub fn total_tasks(&self) -> usize {
        self.phases()
            .into_iter()
            .map(|(_, tasks)| tasks.len())
            .sum()
    }

    /// Validates all tasks in the pipeline.
    pub fn validate(&self) -> Result<(), RsdebstrapError> {
        for (phase_name, tasks) in self.phases() {
            self.validate_phase(phase_name, tasks)?;
        }
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
        _provider: &dyn IsolationProvider,
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
        for (phase_name, tasks) in self.phases() {
            self.run_phase(phase_name, tasks, rootfs, executor, dry_run)?;
        }
        Ok(())
    }

    fn run_phase(
        &self,
        phase_name: &str,
        tasks: &[TaskDefinition],
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
            self.run_task(task, rootfs, executor, dry_run)
                .with_context(|| format!("failed to run {} {}", phase_name, index + 1))?;
        }

        Ok(())
    }

    /// Runs a single task with its own isolation context.
    ///
    /// Creates the appropriate provider based on the task's resolved isolation
    /// config, sets up the context, executes the task, and ensures teardown.
    fn run_task(
        &self,
        task: &TaskDefinition,
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
