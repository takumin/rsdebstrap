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
#[derive(Debug)]
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
    /// that is not a regular file -- and a relative shell path, which validation refuses,
    /// would reach direct execution and be resolved through the host `PATH`.
    ///
    /// Not public for that reason. The only way in from outside the crate is
    /// [`ValidatedProfile::pipeline`](crate::config::ValidatedProfile::pipeline), which only
    /// the profile those checks ran over can produce -- so "validated" is a property of the
    /// value rather than an order to remember. The tests that drive an unvalidated pipeline
    /// live in this file for the same reason.
    ///
    /// # Errors
    ///
    /// Returns `RsdebstrapError::Validation` if a task declares `privilege: true` but
    /// the profile configures no `defaults.privilege.method`, or if it resolves to
    /// escalated execution without isolation.
    pub(crate) fn new(
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
    /// For pipelines that declare no prepare tasks. What a prepare task declares — a mount,
    /// a temporary resolv.conf — is carried by RAII guards that bracket provisioning, and
    /// this method is by definition the case with nothing in between to hold them. So it
    /// refuses a pipeline that declares any, rather than provisioning without the mounts or
    /// the DNS the profile asked for and reporting success. Those callers use
    /// [`Self::run_prepare_and_provision`] and [`Self::run_assemble`], holding the guards
    /// across the two.
    ///
    /// If the pipeline has no tasks at all, returns immediately.
    pub fn run(
        &self,
        rootfs: &Utf8Path,
        executor: Arc<dyn CommandExecutor>,
        ops: Arc<dyn RootfsOps>,
    ) -> Result<()> {
        if !self.prepare.is_empty() {
            return Err(RsdebstrapError::Validation(
                "pipeline declares prepare tasks, which need the mount and resolv.conf \
                guards held across provisioning: call run_prepare_and_provision, hold them, \
                then run_assemble"
                    .to_string(),
            )
            .into());
        }

        let dry_run = executor.dry_run();
        let provisioned = self.run_prepare_and_provision(rootfs, &executor, &ops)?;
        // Not a claim that guards were run and found to have done nothing: the refusal
        // above is what makes "nothing was detached, nothing was mounted" true here.
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
            run_provision_item(task, rootfs, executor, ops)
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
#[derive(Debug)]
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
) -> Result<()> {
    let (provider, ops): (Box<dyn IsolationProvider>, Arc<dyn RootfsOps>) =
        match task.resolved_isolation_config() {
            Some(config) => (config.to_provider(), ops.clone()),
            // Direct execution is unprivileged by construction — `ProvisionTask::resolve`
            // refuses `isolation: false` together with any resolved privilege — so whatever
            // this task stages has to be written by the identity that will then exec it.
            // The run's shared ops may be the privileged helper, and a script staged
            // through it lands `root:root` with a mode (0700) that denies that exec.
            None => (
                Box::new(DirectProvider),
                crate::rootfs::open(rootfs, None, executor.dry_run())
                    .context("failed to open the rootfs for unisolated staging")?,
            ),
        };

    let mut ctx = provider
        .setup(rootfs, executor.clone(), ops)
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

#[cfg(test)]
mod tests {
    // Inside the crate rather than under `tests/` because `Pipeline::new` is the unvalidated
    // constructor and is `pub(crate)`: a pipeline that skipped `Profile::validate` must not be
    // reachable from outside, and these tests exist precisely to drive one that did.
    use std::sync::{Arc, Mutex};

    use anyhow::Result;
    use camino::{Utf8Path, Utf8PathBuf};

    use super::Pipeline;
    use crate::RsdebstrapError;
    use crate::config::IsolationConfig;
    use crate::executor::{CommandExecutor, CommandSpec, ExecutionResult};
    use crate::phase::{AssembleConfig, PrepareConfig, ProvisionTask, ScriptSource, ShellTask};
    use crate::rootfs::{FileMode, RelPath, RootfsOps, TakenEntry};

    // These tests drive the pipeline in dry-run mode, where no filesystem operation
    // is meant to reach a real rootfs.
    fn dry_run_ops() -> std::sync::Arc<dyn crate::rootfs::RootfsOps> {
        std::sync::Arc::new(crate::rootfs::DryRunRootfsOps::new(Utf8Path::new("/tmp/rootfs")))
    }

    // Empty prepare/assemble phases shared by the provision-focused pipeline tests.
    static EMPTY_PREPARE: PrepareConfig = PrepareConfig {
        mount: None,
        resolv_conf: None,
    };
    static EMPTY_ASSEMBLE: AssembleConfig = AssembleConfig { resolv_conf: None };

    fn provision_pipeline(tasks: &[ProvisionTask]) -> Pipeline<'_> {
        Pipeline::new(&EMPTY_PREPARE, tasks, &EMPTY_ASSEMBLE, None, &IsolationConfig::default())
            .expect("no task declares `privilege: true`, so resolution cannot fail")
    }

    // Records executed commands in order, optionally failing on specific calls.
    struct MockExecutor {
        calls: Mutex<Vec<Vec<String>>>,
        // If set, the Nth call (0-indexed) will return an error.
        fail_on_call: Option<usize>,
        dry_run: bool,
    }

    impl MockExecutor {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail_on_call: None,
                dry_run: true,
            }
        }

        fn failing_on(call_index: usize) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail_on_call: Some(call_index),
                dry_run: true,
            }
        }

        // Reports a real run, for the one test that needs the layers under test to actually
        // stage into a fixture rootfs rather than skip their filesystem work.
        fn real_run() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail_on_call: None,
                dry_run: false,
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandExecutor for MockExecutor {
        // Most of these tests drive the pipeline against a fixture rootfs that does not exist
        // on disk, so every layer has to agree the run is a dry run. It derives that from here.
        fn dry_run(&self) -> bool {
            self.dry_run
        }

        fn execute(&self, spec: &CommandSpec) -> Result<ExecutionResult> {
            let mut calls = self.calls.lock().unwrap();
            let index = calls.len();
            let mut args = vec![spec.command().to_string()];
            args.extend(spec.args().iter().cloned());
            calls.push(args);
            drop(calls);

            if self.fail_on_call == Some(index) {
                anyhow::bail!("simulated failure on call {}", index);
            }
            // A real run that reported no status is treated as a killed process, so outside
            // dry run the mock has to hand back an actual successful exit.
            Ok(ExecutionResult {
                status: (!self.dry_run).then(|| {
                    use std::os::unix::process::ExitStatusExt;
                    std::process::ExitStatus::from_raw(0)
                }),
            })
        }
    }

    // Stands in for the run's shared ops, which `crate::rootfs::open` backs with the
    // privileged helper whenever the profile configures a privilege method. It records
    // instead of performing, so a test can ask what was staged through it.
    #[derive(Default)]
    struct RecordingOps {
        writes: Mutex<Vec<String>>,
    }

    impl RecordingOps {
        fn writes(&self) -> Vec<String> {
            self.writes.lock().unwrap().clone()
        }
    }

    impl RootfsOps for RecordingOps {
        fn write_file(
            &self,
            path: &RelPath,
            _content: &[u8],
            _mode: FileMode,
        ) -> std::result::Result<(), RsdebstrapError> {
            self.writes.lock().unwrap().push(path.to_string());
            Ok(())
        }

        fn write_symlink(
            &self,
            path: &RelPath,
            _target: &[u8],
        ) -> std::result::Result<(), RsdebstrapError> {
            self.writes.lock().unwrap().push(path.to_string());
            Ok(())
        }

        fn put_back(
            &self,
            path: &RelPath,
            _entry: &TakenEntry,
        ) -> std::result::Result<(), RsdebstrapError> {
            self.writes.lock().unwrap().push(path.to_string());
            Ok(())
        }

        fn remove(&self, _path: &RelPath) -> std::result::Result<(), RsdebstrapError> {
            Ok(())
        }

        fn take(
            &self,
            _path: &RelPath,
        ) -> std::result::Result<Option<TakenEntry>, RsdebstrapError> {
            Ok(None)
        }
    }

    fn inline_task(content: &str) -> ProvisionTask {
        ProvisionTask::Shell(ShellTask::new(ScriptSource::Content(content.to_string())))
    }

    fn inline_task_direct(content: &str) -> ProvisionTask {
        let yaml = format!("content: \"{}\"\nisolation: false\n", content);
        ProvisionTask::Shell(yaml_serde::from_str(&yaml).unwrap())
    }

    #[test]
    fn test_pipeline_is_empty_when_all_phases_empty() {
        let pipeline = provision_pipeline(&[]);
        assert!(pipeline.is_empty());
        assert_eq!(pipeline.total_tasks(), 0);
    }

    #[test]
    fn test_pipeline_is_not_empty_with_only_provisioners() {
        let tasks = [inline_task("echo prov")];
        let pipeline = provision_pipeline(&tasks);
        assert!(!pipeline.is_empty());
        assert_eq!(pipeline.total_tasks(), 1);
    }

    #[test]
    fn test_pipeline_total_tasks_counts_all_phases() {
        let tasks = [
            inline_task("echo 1"),
            inline_task("echo 2"),
            inline_task("echo 3"),
            inline_task("echo 4"),
            inline_task("echo 5"),
            inline_task("echo 6"),
        ];
        let pipeline = provision_pipeline(&tasks);
        assert!(!pipeline.is_empty());
        assert_eq!(pipeline.total_tasks(), 6);
    }

    #[test]
    fn test_pipeline_validate_succeeds_for_empty_pipeline() {
        let pipeline = provision_pipeline(&[]);
        assert!(pipeline.validate().is_ok());
    }

    #[test]
    fn test_pipeline_validate_succeeds_for_valid_inline_tasks() {
        let tasks = [inline_task("echo hello")];
        let pipeline = provision_pipeline(&tasks);
        assert!(pipeline.validate().is_ok());
    }

    #[test]
    fn test_pipeline_validate_reports_correct_index() {
        let good = inline_task("echo ok");
        let bad = ProvisionTask::Shell(ShellTask::new(ScriptSource::Script(
            "../../../etc/passwd".into(),
        )));
        let tasks = [good, bad];
        let pipeline = provision_pipeline(&tasks);
        let err = pipeline.validate().unwrap_err();
        let err_msg = format!("{:#}", err);
        assert!(
            err_msg.contains("provision 2 validation failed"),
            "Expected 'provision 2 validation failed' in error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_pipeline_run_empty_returns_ok_without_setup() {
        let pipeline = provision_pipeline(&[]);
        let executor: Arc<dyn CommandExecutor> = Arc::new(MockExecutor::new());

        let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, dry_run_ops());
        assert!(result.is_ok());
    }

    // `run` builds the `Restored`/`Unmounted` evidence itself rather than receiving it from
    // guards. That is only honest with no prepare phase to have skipped, so a pipeline
    // declaring one has to be refused — provisioning it here would run the tasks without the
    // resolv.conf the profile asked for and still report success.
    #[test]
    fn run_refuses_a_pipeline_that_declares_prepare_tasks() {
        let prepare = PrepareConfig {
            mount: None,
            resolv_conf: Some(crate::phase::ResolvConfTask {
                copy: true,
                name_servers: Vec::new(),
                search: Vec::new(),
            }),
        };
        let tasks = [inline_task("echo 1")];
        let pipeline =
            Pipeline::new(&prepare, &tasks, &EMPTY_ASSEMBLE, None, &IsolationConfig::default())
                .expect("no task declares `privilege: true`, so resolution cannot fail");
        let executor: Arc<dyn CommandExecutor> = Arc::new(MockExecutor::new());

        let err = pipeline
            .run(Utf8Path::new("/tmp/rootfs"), executor, dry_run_ops())
            .expect_err("a pipeline with a prepare task must not run through this path");

        assert!(
            err.to_string().contains("run_prepare_and_provision"),
            "expected the error to name the two-stage path, got: {}",
            err
        );
    }

    #[test]
    fn test_pipeline_run_executes_tasks_in_phase_order() {
        let tasks = [
            inline_task("echo 1"),
            inline_task("echo 2"),
            inline_task("echo 3"),
        ];
        let pipeline = provision_pipeline(&tasks);

        let mock_executor = Arc::new(MockExecutor::new());
        let executor: Arc<dyn CommandExecutor> =
            Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

        let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, dry_run_ops());
        assert!(result.is_ok(), "pipeline run failed: {:?}", result);

        assert_eq!(mock_executor.call_count(), 3);

        // Each call goes through ChrootContext which creates:
        // ["chroot", rootfs_path, shell_path, script_path]
        let calls = mock_executor.calls();
        for call in &calls {
            assert_eq!(call[0], String::from("chroot"));
            assert_eq!(call[1], String::from("/tmp/rootfs"));
            assert_eq!(call[2], String::from("/bin/sh"));
        }
    }

    #[test]
    fn test_pipeline_run_tasks_execute_in_order_within_phase() {
        let task1 =
            ShellTask::with_shell(ScriptSource::Content("echo t1".to_string()), "/bin/sh-1");
        let task2 =
            ShellTask::with_shell(ScriptSource::Content("echo t2".to_string()), "/bin/sh-2");
        let task3 =
            ShellTask::with_shell(ScriptSource::Content("echo t3".to_string()), "/bin/sh-3");
        let tasks = [
            ProvisionTask::Shell(task1),
            ProvisionTask::Shell(task2),
            ProvisionTask::Shell(task3),
        ];
        let pipeline = provision_pipeline(&tasks);

        let mock_executor = Arc::new(MockExecutor::new());
        let executor: Arc<dyn CommandExecutor> =
            Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

        let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, dry_run_ops());
        assert!(result.is_ok(), "pipeline run failed: {:?}", result);

        let calls = mock_executor.calls();
        assert_eq!(calls.len(), 3);

        // ChrootContext wraps: ["chroot", rootfs, ...command],
        // so call[0]="chroot", call[1]=rootfs, call[2]=shell
        assert_eq!(calls[0][2], String::from("/bin/sh-1"));
        assert_eq!(calls[1][2], String::from("/bin/sh-2"));
        assert_eq!(calls[2][2], String::from("/bin/sh-3"));
    }

    #[test]
    fn test_pipeline_run_error_stops_remaining_tasks() {
        let tasks = [
            inline_task("echo 1"),
            inline_task("echo 2"),
            inline_task("echo 3"),
        ];
        let pipeline = provision_pipeline(&tasks);

        // failing_on(1): task 1 succeeds, task 2 fails, task 3 never runs
        let mock_executor = Arc::new(MockExecutor::failing_on(1));
        let executor: Arc<dyn CommandExecutor> =
            Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

        let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, dry_run_ops());
        assert!(result.is_err());

        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(
            err_msg.contains("failed to run provision 2"),
            "Expected provision 2 failure, got: {}",
            err_msg
        );

        assert_eq!(mock_executor.call_count(), 2);
    }

    #[test]
    fn test_pipeline_run_task_isolation_disabled_uses_direct() {
        let tasks = [inline_task_direct("echo direct")];
        let pipeline = provision_pipeline(&tasks);

        let mock_executor = Arc::new(MockExecutor::new());
        let executor: Arc<dyn CommandExecutor> =
            Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

        let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, dry_run_ops());
        assert!(result.is_ok(), "pipeline run failed: {:?}", result);

        let calls = mock_executor.calls();
        assert_eq!(calls.len(), 1);

        // DirectContext translates absolute paths to rootfs-prefixed paths,
        // so /bin/sh becomes /tmp/rootfs/bin/sh (no "chroot" wrapper command)
        let first_call = &calls[0];
        assert!(
            first_call[0].starts_with("/tmp/rootfs/"),
            "Expected rootfs-prefixed path (direct execution), got: {:?}",
            first_call[0]
        );
        assert!(
            !first_call.iter().any(|arg| arg == "chroot"),
            "Direct execution should not contain 'chroot' command, got: {:?}",
            first_call
        );
    }

    #[test]
    fn test_pipeline_run_task_isolation_enabled_uses_chroot() {
        let tasks = [inline_task("echo chroot")];
        let pipeline = provision_pipeline(&tasks);

        let mock_executor = Arc::new(MockExecutor::new());
        let executor: Arc<dyn CommandExecutor> =
            Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

        let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, dry_run_ops());
        assert!(result.is_ok(), "pipeline run failed: {:?}", result);

        let calls = mock_executor.calls();
        assert_eq!(calls.len(), 1);

        // ChrootContext wraps: ["chroot", rootfs, shell, script]
        let first_call = &calls[0];
        assert_eq!(
            first_call[0],
            String::from("chroot"),
            "Expected 'chroot' as first argument, got: {:?}",
            first_call[0]
        );
        assert_eq!(first_call[1], String::from("/tmp/rootfs"));
    }

    #[test]
    fn test_pipeline_run_mixed_isolation_chroot_and_direct() {
        // Use custom shell paths to distinguish each call
        let chroot1 = ShellTask::with_shell(
            ScriptSource::Content("echo chroot1".to_string()),
            "/bin/sh-chroot1",
        );
        let task1 = ProvisionTask::Shell(chroot1);

        let task2 = inline_task_direct("echo direct");

        let chroot2 = ShellTask::with_shell(
            ScriptSource::Content("echo chroot2".to_string()),
            "/bin/sh-chroot2",
        );
        let task3 = ProvisionTask::Shell(chroot2);

        let tasks = [task1, task2, task3];
        let pipeline = provision_pipeline(&tasks);

        let mock_executor = Arc::new(MockExecutor::new());
        let executor: Arc<dyn CommandExecutor> =
            Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

        let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, dry_run_ops());
        assert!(result.is_ok(), "pipeline run failed: {:?}", result);

        let calls = mock_executor.calls();
        assert_eq!(calls.len(), 3, "Expected 3 calls, got: {}", calls.len());

        assert_eq!(calls[0][0], "chroot", "Expected first task to use chroot, got: {:?}", calls[0]);
        assert_eq!(calls[0][2], "/bin/sh-chroot1");

        assert!(
            calls[1][0].starts_with("/tmp/rootfs/"),
            "Expected direct task with rootfs-prefixed path, got: {:?}",
            calls[1][0]
        );
        assert!(
            !calls[1].iter().any(|arg| arg == "chroot"),
            "Direct task should not contain 'chroot', got: {:?}",
            calls[1]
        );

        assert_eq!(calls[2][0], "chroot", "Expected third task to use chroot, got: {:?}", calls[2]);
        assert_eq!(calls[2][2], "/bin/sh-chroot2");
    }

    #[test]
    fn test_pipeline_validate_preserves_validation_variant() {
        let bad_task = [ProvisionTask::Shell(ShellTask::new(ScriptSource::Script(
            "../../../etc/passwd".into(),
        )))];
        let pipeline = provision_pipeline(&bad_task);
        let err = pipeline.validate().unwrap_err();
        assert!(
            matches!(
                err,
                RsdebstrapError::Validation(ref msg)
                    if msg.contains("provision 1 validation failed")
            ),
            "Expected RsdebstrapError::Validation with phase context, got: {:?}",
            err,
        );
    }

    #[test]
    fn test_pipeline_validate_preserves_io_variant() {
        let nonexistent_task = [ProvisionTask::Shell(ShellTask::new(ScriptSource::Script(
            "/nonexistent/path/to/script.sh".into(),
        )))];
        let pipeline = provision_pipeline(&nonexistent_task);
        let err = pipeline.validate().unwrap_err();
        match err {
            RsdebstrapError::Io {
                ref context,
                source: ref src,
                ..
            } => {
                assert!(
                    context.contains("provision 1 validation failed"),
                    "Expected phase context in Io.context, got: {}",
                    context,
                );
                assert_eq!(
                    src.kind(),
                    std::io::ErrorKind::NotFound,
                    "Expected NotFound, got: {:?}",
                    src.kind(),
                );
            }
            other => panic!(
                "Expected RsdebstrapError::Io (preserved through validate_phase), got: {:?}",
                other,
            ),
        }
    }

    // A task that resolves to no isolation cannot also resolve to a privilege — `ProvisionTask::
    // resolve` refuses that pair — so its script is exec'd as the calling user. Staging it
    // through the run's shared ops would put it there as whoever those ops speak for: with a
    // privilege method configured that is root, and the 0700 mode staging asks for would then
    // deny the very exec the staging was for. So the direct path must open its own ops.
    #[test]
    fn direct_execution_does_not_stage_through_the_runs_shared_ops() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir(rootfs.join("tmp")).unwrap();
        std::fs::create_dir(rootfs.join("bin")).unwrap();
        std::fs::write(rootfs.join("bin/sh"), "#!/bin/sh\n").unwrap();

        let tasks = [inline_task_direct("echo direct")];
        let pipeline = provision_pipeline(&tasks);
        let executor = Arc::new(MockExecutor::real_run());
        let shared_ops = Arc::new(RecordingOps::default());

        pipeline
            .run(&rootfs, executor.clone(), shared_ops.clone())
            .expect("the direct task should run against the fixture rootfs");

        assert!(
            shared_ops.writes().is_empty(),
            "the script was staged through the shared ops: {:?}",
            shared_ops.writes()
        );

        // The exec still happened, so the script really was staged — just by ops of the
        // direct path's own making.
        let calls = executor.calls();
        assert_eq!(calls.len(), 1, "unexpected calls: {:?}", calls);
        assert!(
            calls[0][1].starts_with(rootfs.join("tmp/task-").as_str()),
            "unexpected argv: {:?}",
            calls[0]
        );
    }
}
