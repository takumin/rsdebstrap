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

use crate::config::IsolationConfig;
use crate::error::RsdebstrapError;
use crate::executor::CommandExecutor;
use crate::isolation::mount::Unmounted;
use crate::isolation::resolv_conf::Restored;
use crate::isolation::{DirectProvider, IsolationProvider, PlainRootfsContext};
use crate::phase::{
    AssembleConfig, PhaseItem, PrepareConfig, ProvisionItem, ProvisionTask, ResolvedProvisionTask,
};
use crate::privilege::PrivilegeDefaults;
use crate::rootfs::RootfsOps;

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
    prepare: &'a PrepareConfig,
    provision: Vec<ResolvedProvisionTask<'a>>,
    assemble: &'a AssembleConfig,
}

impl<'a> Pipeline<'a> {
    /// Creates a new pipeline with the given task phases, resolving each provision
    /// task's privilege and isolation settings against the profile defaults.
    ///
    /// This is the unvalidated constructor: it resolves settings but performs none of the
    /// semantic checks in [`Profile::validate`](crate::config::Profile::validate), so a
    /// pipeline built here may still name a mount target that does not exist or a script
    /// that is not a regular file. Production goes through
    /// [`Profile::pipeline`](crate::config::Profile::pipeline), which takes the evidence
    /// that validation ran.
    ///
    /// # Errors
    ///
    /// Returns `RsdebstrapError::Validation` if a task declares `privilege: true` but
    /// the profile configures no `defaults.privilege.method`, or if it resolves to
    /// escalated execution without isolation.
    pub fn new(
        prepare: &'a PrepareConfig,
        provision: &'a [ProvisionTask],
        assemble: &'a AssembleConfig,
        privilege_defaults: Option<&PrivilegeDefaults>,
        isolation_defaults: &IsolationConfig,
    ) -> Result<Self, RsdebstrapError> {
        let provision = provision
            .iter()
            .map(|task| task.resolve(privilege_defaults, isolation_defaults))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            prepare,
            provision,
            assemble,
        })
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
        validate_phase_items(PHASE_PREPARE, &self.prepare.items())?;
        validate_phase_items(PHASE_PROVISION, &provision_items(&self.provision))?;
        validate_phase_items(PHASE_ASSEMBLE, &self.assemble.items())?;
        Ok(())
    }

    /// Executes all phases of the pipeline with per-task isolation contexts.
    ///
    /// If the pipeline has no tasks, returns immediately. Equivalent to
    /// [`Self::run_prepare_and_provision`] followed by [`Self::run_assemble`]
    /// with nothing in between; callers that must act between provisioning
    /// and assembly call the two stages themselves.
    pub fn run(
        &self,
        rootfs: &Utf8Path,
        executor: Arc<dyn CommandExecutor>,
        ops: Arc<dyn RootfsOps>,
        dry_run: bool,
    ) -> Result<()> {
        let provisioned = self.run_prepare_and_provision(rootfs, &executor, &ops, dry_run)?;
        // No prepare guard runs here, so nothing detached the rootfs's own
        // resolv.conf and nothing was mounted over it.
        let restored = Restored::nothing_was_detached(provisioned);
        self.run_assemble(Unmounted::nothing_was_mounted(restored), rootfs, &ops, dry_run)
    }

    /// Executes the prepare and provision phases (the first pipeline stage)
    /// and emits the "starting pipeline" banner (counting tasks across all
    /// three phases).
    ///
    /// Callers that need work between provisioning and assembly — e.g.
    /// `run_pipeline_phase()` restoring the temporary resolv.conf — call
    /// this, do that work, then call [`Self::run_assemble`]. Returns
    /// immediately if the pipeline has no tasks.
    pub fn run_prepare_and_provision(
        &self,
        rootfs: &Utf8Path,
        executor: &Arc<dyn CommandExecutor>,
        ops: &Arc<dyn RootfsOps>,
        dry_run: bool,
    ) -> Result<Provisioned> {
        if self.is_empty() {
            return Ok(Provisioned::new());
        }

        info!("starting pipeline with {} task(s)", self.total_tasks());
        // A prepare item has nothing to run: the mount and resolv.conf lifecycles
        // are driven by RAII guards that bracket the whole pipeline. Iterating is
        // still what reports them as the tasks they are.
        run_phase_items(PHASE_PREPARE, &self.prepare.items(), |_| Ok(()))?;
        run_phase_items(PHASE_PROVISION, &provision_items(&self.provision), |task| {
            run_provision_item(task, rootfs, executor, ops, dry_run)
        })?;
        Ok(Provisioned::new())
    }

    /// Executes the assemble phase (the second pipeline stage) and logs
    /// pipeline completion.
    ///
    /// Call only after a successful [`Self::run_prepare_and_provision`].
    /// Returns immediately if the pipeline has no tasks.
    pub fn run_assemble(
        &self,
        _unmounted: Unmounted,
        rootfs: &Utf8Path,
        ops: &Arc<dyn RootfsOps>,
        dry_run: bool,
    ) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }

        // Assemble takes no isolation provider: its items only write files, and
        // the values a `RootfsContext` needs are already here.
        let ctx = PlainRootfsContext::new(rootfs, ops.clone(), dry_run);
        run_phase_items(PHASE_ASSEMBLE, &self.assemble.items(), |task| task.execute(&ctx))?;
        info!("pipeline completed successfully");
        Ok(())
    }
}

/// Evidence that the prepare and provision phases both completed.
///
/// Produced only by [`Pipeline::run_prepare_and_provision`] and consumed by
/// [`RootfsResolvConf::restore`](crate::isolation::resolv_conf::RootfsResolvConf::restore).
#[must_use]
pub struct Provisioned(());

impl Provisioned {
    fn new() -> Self {
        Self(())
    }
}

/// Borrows the provision tasks as `ProvisionItem` trait objects for uniform
/// handling with the named-field prepare/assemble phases.
fn provision_items<'t>(tasks: &'t [ResolvedProvisionTask<'_>]) -> Vec<&'t dyn ProvisionItem> {
    tasks.iter().map(|t| t as &dyn ProvisionItem).collect()
}

/// Logs and error-wraps one phase's items, whatever running one means for that
/// phase. The three phases differ only in `run`; the reporting is shared.
fn run_phase_items<T: PhaseItem + ?Sized>(
    phase_name: &str,
    tasks: &[&T],
    mut run: impl FnMut(&T) -> Result<()>,
) -> Result<()> {
    if tasks.is_empty() {
        debug!("skipping empty {} phase", phase_name);
        return Ok(());
    }

    info!("running {} phase ({} task(s))", phase_name, tasks.len());

    for (index, task) in tasks.iter().enumerate() {
        info!("running {} {}/{}: {}", phase_name, index + 1, tasks.len(), task.name());
        run(task).with_context(|| format!("failed to run {} {}", phase_name, index + 1))?;
    }

    Ok(())
}

/// Runs a single provision task with its own isolation context.
///
/// Creates the appropriate provider based on the task's resolved isolation
/// config, sets up the context, executes the task, and ensures teardown.
fn run_provision_item(
    task: &dyn ProvisionItem,
    rootfs: &Utf8Path,
    executor: &Arc<dyn CommandExecutor>,
    ops: &Arc<dyn RootfsOps>,
    dry_run: bool,
) -> Result<()> {
    let provider: Box<dyn IsolationProvider> = match task.resolved_isolation_config() {
        Some(config) => config.as_provider(),
        None => Box::new(DirectProvider),
    };

    let mut ctx = provider
        .setup(rootfs, executor.clone(), ops.clone(), dry_run)
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
fn validate_phase_items<T: PhaseItem + ?Sized>(
    phase_name: &str,
    tasks: &[&T],
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
