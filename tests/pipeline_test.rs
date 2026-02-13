//! Tests for the Pipeline orchestrator.

use std::sync::{Arc, Mutex};

use anyhow::Result;
use camino::Utf8Path;
use rsdebstrap::RsdebstrapError;
use rsdebstrap::config::IsolationConfig;
use rsdebstrap::executor::{CommandExecutor, CommandSpec, ExecutionResult};
use rsdebstrap::phase::{ProvisionTask, ScriptSource, ShellTask};
use rsdebstrap::pipeline::Pipeline;

// =============================================================================
// Mock infrastructure
// =============================================================================

/// Records executed commands in order, optionally failing on specific calls.
struct MockExecutor {
    calls: Mutex<Vec<Vec<String>>>,
    /// If set, the Nth call (0-indexed) will return an error.
    fail_on_call: Option<usize>,
}

impl MockExecutor {
    fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            fail_on_call: None,
        }
    }

    fn failing_on(call_index: usize) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            fail_on_call: Some(call_index),
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
    fn execute(&self, spec: &CommandSpec) -> Result<ExecutionResult> {
        let mut calls = self.calls.lock().unwrap();
        let index = calls.len();
        let mut args = vec![spec.command.clone()];
        args.extend(spec.args.iter().cloned());
        calls.push(args);
        drop(calls);

        if self.fail_on_call == Some(index) {
            anyhow::bail!("simulated failure on call {}", index);
        }
        Ok(ExecutionResult { status: None })
    }
}

/// Helper to create a simple inline shell task with privilege and isolation resolved.
fn inline_task(content: &str) -> ProvisionTask {
    let mut task = ShellTask::new(ScriptSource::Content(content.to_string()));
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());
    ProvisionTask::Shell(task)
}

/// Helper to create an inline shell task with isolation disabled (direct execution).
fn inline_task_direct(content: &str) -> ProvisionTask {
    let yaml = format!("content: \"{}\"\nisolation: false\n", content);
    let mut task: ShellTask = serde_yaml::from_str(&yaml).unwrap();
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::chroot()); // Disabled stays Disabled
    ProvisionTask::Shell(task)
}

// =============================================================================
// is_empty() / total_tasks() tests
// =============================================================================

#[test]
fn test_pipeline_is_empty_when_all_phases_empty() {
    let pipeline = Pipeline::new(&[], &[], &[]);
    assert!(pipeline.is_empty());
    assert_eq!(pipeline.total_tasks(), 0);
}

#[test]
fn test_pipeline_is_not_empty_with_only_provisioners() {
    let tasks = [inline_task("echo prov")];
    let pipeline = Pipeline::new(&[], &tasks, &[]);
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
    let pipeline = Pipeline::new(&[], &tasks, &[]);
    assert!(!pipeline.is_empty());
    assert_eq!(pipeline.total_tasks(), 6);
}

// =============================================================================
// validate() tests
// =============================================================================

#[test]
fn test_pipeline_validate_succeeds_for_empty_pipeline() {
    let pipeline = Pipeline::new(&[], &[], &[]);
    assert!(pipeline.validate().is_ok());
}

#[test]
fn test_pipeline_validate_succeeds_for_valid_inline_tasks() {
    let tasks = [inline_task("echo hello")];
    let pipeline = Pipeline::new(&[], &tasks, &[]);
    assert!(pipeline.validate().is_ok());
}

#[test]
fn test_pipeline_validate_fails_for_invalid_provisioner() {
    let bad_task = [ProvisionTask::Shell(ShellTask::new(ScriptSource::Script(
        "../../../etc/passwd".into(),
    )))];
    let pipeline = Pipeline::new(&[], &bad_task, &[]);
    let err = pipeline.validate().unwrap_err();
    let err_msg = format!("{:#}", err);
    assert!(
        err_msg.contains("provision 1 validation failed"),
        "Expected 'provision 1 validation failed' in error, got: {}",
        err_msg
    );
}

#[test]
fn test_pipeline_validate_reports_correct_index() {
    let good = inline_task("echo ok");
    let bad =
        ProvisionTask::Shell(ShellTask::new(ScriptSource::Script("../../../etc/passwd".into())));
    let tasks = [good, bad];
    let pipeline = Pipeline::new(&[], &tasks, &[]);
    let err = pipeline.validate().unwrap_err();
    let err_msg = format!("{:#}", err);
    assert!(
        err_msg.contains("provision 2 validation failed"),
        "Expected 'provision 2 validation failed' in error, got: {}",
        err_msg
    );
}

// =============================================================================
// run() tests
// =============================================================================

#[test]
fn test_pipeline_run_empty_returns_ok_without_setup() {
    let pipeline = Pipeline::new(&[], &[], &[]);
    let executor: Arc<dyn CommandExecutor> = Arc::new(MockExecutor::new());

    // Empty pipeline should return Ok without any setup
    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, true);
    assert!(result.is_ok());
}

#[test]
fn test_pipeline_run_executes_tasks_in_phase_order() {
    let tasks = [
        inline_task("echo 1"),
        inline_task("echo 2"),
        inline_task("echo 3"),
    ];
    let pipeline = Pipeline::new(&[], &tasks, &[]);

    let mock_executor = Arc::new(MockExecutor::new());
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, true);
    assert!(result.is_ok(), "pipeline run failed: {:?}", result);

    // All 3 tasks should have been executed
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
fn test_pipeline_run_phase_error_with_successful_teardown() {
    let tasks = [inline_task("echo hello")];
    let pipeline = Pipeline::new(&[], &tasks, &[]);

    let mock_executor = Arc::new(MockExecutor::failing_on(0));
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, true);
    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("failed to run provision 1"),
        "Expected phase error, got: {}",
        err_msg
    );
}

#[test]
fn test_pipeline_run_skips_empty_phases() {
    let prov = [inline_task("echo prov")];
    let pipeline = Pipeline::new(&[], &prov, &[]);

    let mock_executor = Arc::new(MockExecutor::new());
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, true);
    assert!(result.is_ok());
    assert_eq!(mock_executor.call_count(), 1);
}

#[test]
fn test_pipeline_run_tasks_execute_in_order_within_phase() {
    let mut task1 =
        ShellTask::with_shell(ScriptSource::Content("echo t1".to_string()), "/bin/sh-1");
    task1.resolve_privilege(None).unwrap();
    task1.resolve_isolation(&IsolationConfig::default());
    let mut task2 =
        ShellTask::with_shell(ScriptSource::Content("echo t2".to_string()), "/bin/sh-2");
    task2.resolve_privilege(None).unwrap();
    task2.resolve_isolation(&IsolationConfig::default());
    let mut task3 =
        ShellTask::with_shell(ScriptSource::Content("echo t3".to_string()), "/bin/sh-3");
    task3.resolve_privilege(None).unwrap();
    task3.resolve_isolation(&IsolationConfig::default());
    let tasks = [
        ProvisionTask::Shell(task1),
        ProvisionTask::Shell(task2),
        ProvisionTask::Shell(task3),
    ];
    let pipeline = Pipeline::new(&[], &tasks, &[]);

    let mock_executor = Arc::new(MockExecutor::new());
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, true);
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
fn test_pipeline_run_stops_within_phase_on_error() {
    let prov = [
        inline_task("echo prov1"),
        inline_task("echo prov2"),
        inline_task("echo prov3"),
    ];
    let pipeline = Pipeline::new(&[], &prov, &[]);

    // failing_on(1): 2nd call (0-indexed) fails,
    // so task 1 succeeds, task 2 fails, task 3 never runs
    let mock_executor = Arc::new(MockExecutor::failing_on(1));
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, true);
    assert!(result.is_err());
    assert_eq!(mock_executor.call_count(), 2);
}

#[test]
fn test_pipeline_run_stops_on_first_task_error() {
    let tasks = [
        inline_task("echo 1"),
        inline_task("echo 2"),
        inline_task("echo 3"),
    ];
    let pipeline = Pipeline::new(&[], &tasks, &[]);

    let mock_executor = Arc::new(MockExecutor::failing_on(0));
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, true);
    assert!(result.is_err());
    assert_eq!(mock_executor.call_count(), 1);
}

#[test]
fn test_pipeline_run_error_stops_remaining_tasks() {
    let tasks = [
        inline_task("echo 1"),
        inline_task("echo 2"),
        inline_task("echo 3"),
    ];
    let pipeline = Pipeline::new(&[], &tasks, &[]);

    // failing_on(1): task 1 succeeds, task 2 fails, task 3 never runs
    let mock_executor = Arc::new(MockExecutor::failing_on(1));
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, true);
    assert!(result.is_err());

    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("failed to run provision 2"),
        "Expected provision 2 failure, got: {}",
        err_msg
    );

    assert_eq!(mock_executor.call_count(), 2);
}

// =============================================================================
// per-task isolation tests
// =============================================================================

#[test]
fn test_pipeline_run_task_isolation_disabled_uses_direct() {
    let tasks = [inline_task_direct("echo direct")];
    let pipeline = Pipeline::new(&[], &tasks, &[]);

    let mock_executor = Arc::new(MockExecutor::new());
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, true);
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
    let pipeline = Pipeline::new(&[], &tasks, &[]);

    let mock_executor = Arc::new(MockExecutor::new());
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, true);
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
    // Create 3 tasks: chroot → direct → chroot
    // Use custom shell paths to distinguish each call
    let mut chroot1 =
        ShellTask::with_shell(ScriptSource::Content("echo chroot1".to_string()), "/bin/sh-chroot1");
    chroot1.resolve_privilege(None).unwrap();
    chroot1.resolve_isolation(&IsolationConfig::default());
    let task1 = ProvisionTask::Shell(chroot1);

    let task2 = inline_task_direct("echo direct");

    let mut chroot2 =
        ShellTask::with_shell(ScriptSource::Content("echo chroot2".to_string()), "/bin/sh-chroot2");
    chroot2.resolve_privilege(None).unwrap();
    chroot2.resolve_isolation(&IsolationConfig::default());
    let task3 = ProvisionTask::Shell(chroot2);

    let tasks = [task1, task2, task3];
    let pipeline = Pipeline::new(&[], &tasks, &[]);

    let mock_executor = Arc::new(MockExecutor::new());
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, true);
    assert!(result.is_ok(), "pipeline run failed: {:?}", result);

    let calls = mock_executor.calls();
    assert_eq!(calls.len(), 3, "Expected 3 calls, got: {}", calls.len());

    // Call 0: chroot task — first arg is "chroot", shell is /bin/sh-chroot1
    assert_eq!(calls[0][0], "chroot", "Expected first task to use chroot, got: {:?}", calls[0]);
    assert_eq!(calls[0][2], "/bin/sh-chroot1");

    // Call 1: direct task — first arg is rootfs-prefixed (no "chroot")
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

    // Call 2: chroot task — first arg is "chroot", shell is /bin/sh-chroot2
    assert_eq!(calls[2][0], "chroot", "Expected third task to use chroot, got: {:?}", calls[2]);
    assert_eq!(calls[2][2], "/bin/sh-chroot2");
}

// =============================================================================
// validate() variant preservation tests
// =============================================================================

#[test]
fn test_pipeline_validate_preserves_validation_variant() {
    let bad_task = [ProvisionTask::Shell(ShellTask::new(ScriptSource::Script(
        "../../../etc/passwd".into(),
    )))];
    let pipeline = Pipeline::new(&[], &bad_task, &[]);
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
    let pipeline = Pipeline::new(&[], &nonexistent_task, &[]);
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
