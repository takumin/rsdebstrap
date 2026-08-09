// Tests for the Pipeline orchestrator.

use std::sync::{Arc, Mutex};

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use rsdebstrap::RsdebstrapError;
use rsdebstrap::config::IsolationConfig;
use rsdebstrap::executor::{CommandExecutor, CommandSpec, ExecutionResult};
use rsdebstrap::phase::{AssembleConfig, PrepareConfig, ProvisionTask, ScriptSource, ShellTask};
use rsdebstrap::pipeline::Pipeline;
use rsdebstrap::rootfs::{FileMode, RelPath, RootfsOps, TakenEntry};

// These tests drive the pipeline in dry-run mode, where no filesystem operation
// is meant to reach a real rootfs.
fn dry_run_ops() -> std::sync::Arc<dyn rsdebstrap::rootfs::RootfsOps> {
    std::sync::Arc::new(rsdebstrap::rootfs::DryRunRootfsOps::new(Utf8Path::new("/tmp/rootfs")))
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

// Stands in for the run's shared ops, which `rsdebstrap::rootfs::open` backs with the
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

    fn take(&self, _path: &RelPath) -> std::result::Result<Option<TakenEntry>, RsdebstrapError> {
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
    let bad =
        ProvisionTask::Shell(ShellTask::new(ScriptSource::Script("../../../etc/passwd".into())));
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

#[test]
fn test_pipeline_run_executes_tasks_in_phase_order() {
    let tasks = [
        inline_task("echo 1"),
        inline_task("echo 2"),
        inline_task("echo 3"),
    ];
    let pipeline = provision_pipeline(&tasks);

    let mock_executor = Arc::new(MockExecutor::new());
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

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
    let task1 = ShellTask::with_shell(ScriptSource::Content("echo t1".to_string()), "/bin/sh-1");
    let task2 = ShellTask::with_shell(ScriptSource::Content("echo t2".to_string()), "/bin/sh-2");
    let task3 = ShellTask::with_shell(ScriptSource::Content("echo t3".to_string()), "/bin/sh-3");
    let tasks = [
        ProvisionTask::Shell(task1),
        ProvisionTask::Shell(task2),
        ProvisionTask::Shell(task3),
    ];
    let pipeline = provision_pipeline(&tasks);

    let mock_executor = Arc::new(MockExecutor::new());
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

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
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

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
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

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
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

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
    let chroot1 =
        ShellTask::with_shell(ScriptSource::Content("echo chroot1".to_string()), "/bin/sh-chroot1");
    let task1 = ProvisionTask::Shell(chroot1);

    let task2 = inline_task_direct("echo direct");

    let chroot2 =
        ShellTask::with_shell(ScriptSource::Content("echo chroot2".to_string()), "/bin/sh-chroot2");
    let task3 = ProvisionTask::Shell(chroot2);

    let tasks = [task1, task2, task3];
    let pipeline = provision_pipeline(&tasks);

    let mock_executor = Arc::new(MockExecutor::new());
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

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
