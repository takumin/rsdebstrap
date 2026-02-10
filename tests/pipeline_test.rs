//! Tests for the Pipeline orchestrator.

use std::sync::{Arc, Mutex};

use anyhow::Result;
use camino::Utf8Path;
use rsdebstrap::RsdebstrapError;
use rsdebstrap::config::IsolationConfig;
use rsdebstrap::executor::{CommandExecutor, CommandSpec, ExecutionResult};
use rsdebstrap::pipeline::Pipeline;
use rsdebstrap::task::{ScriptSource, ShellTask, TaskDefinition};

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
fn inline_task(content: &str) -> TaskDefinition {
    let mut task = ShellTask::new(ScriptSource::Content(content.to_string()));
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());
    TaskDefinition::Shell(task)
}

/// Helper to create an inline shell task with isolation disabled (direct execution).
fn inline_task_direct(content: &str) -> TaskDefinition {
    let yaml = format!("content: \"{}\"\nisolation: false\n", content);
    let mut task: ShellTask = serde_yaml::from_str(&yaml).unwrap();
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::Chroot); // Disabled stays Disabled
    TaskDefinition::Shell(task)
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
fn test_pipeline_is_not_empty_with_only_pre_processors() {
    let tasks = [inline_task("echo pre")];
    let pipeline = Pipeline::new(&tasks, &[], &[]);
    assert!(!pipeline.is_empty());
    assert_eq!(pipeline.total_tasks(), 1);
}

#[test]
fn test_pipeline_is_not_empty_with_only_provisioners() {
    let tasks = [inline_task("echo prov")];
    let pipeline = Pipeline::new(&[], &tasks, &[]);
    assert!(!pipeline.is_empty());
    assert_eq!(pipeline.total_tasks(), 1);
}

#[test]
fn test_pipeline_is_not_empty_with_only_post_processors() {
    let tasks = [inline_task("echo post")];
    let pipeline = Pipeline::new(&[], &[], &tasks);
    assert!(!pipeline.is_empty());
    assert_eq!(pipeline.total_tasks(), 1);
}

#[test]
fn test_pipeline_total_tasks_counts_all_phases() {
    let pre = [inline_task("echo 1"), inline_task("echo 2")];
    let prov = [inline_task("echo 3")];
    let post = [
        inline_task("echo 4"),
        inline_task("echo 5"),
        inline_task("echo 6"),
    ];
    let pipeline = Pipeline::new(&pre, &prov, &post);
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
    let pipeline = Pipeline::new(&tasks, &tasks, &tasks);
    assert!(pipeline.validate().is_ok());
}

#[test]
fn test_pipeline_validate_fails_for_invalid_pre_processor() {
    let bad_task = [TaskDefinition::Shell(ShellTask::new(ScriptSource::Script(
        "../../../etc/passwd".into(),
    )))];
    let pipeline = Pipeline::new(&bad_task, &[], &[]);
    let err = pipeline.validate().unwrap_err();
    let err_msg = format!("{:#}", err);
    assert!(
        err_msg.contains("pre-processor 1 validation failed"),
        "Expected 'pre-processor 1 validation failed' in error, got: {}",
        err_msg
    );
}

#[test]
fn test_pipeline_validate_fails_for_invalid_provisioner() {
    let bad_task = [TaskDefinition::Shell(ShellTask::new(ScriptSource::Script(
        "../../../etc/passwd".into(),
    )))];
    let pipeline = Pipeline::new(&[], &bad_task, &[]);
    let err = pipeline.validate().unwrap_err();
    let err_msg = format!("{:#}", err);
    assert!(
        err_msg.contains("provisioner 1 validation failed"),
        "Expected 'provisioner 1 validation failed' in error, got: {}",
        err_msg
    );
}

#[test]
fn test_pipeline_validate_fails_for_invalid_post_processor() {
    let bad_task = [TaskDefinition::Shell(ShellTask::new(ScriptSource::Script(
        "../../../etc/passwd".into(),
    )))];
    let pipeline = Pipeline::new(&[], &[], &bad_task);
    let err = pipeline.validate().unwrap_err();
    let err_msg = format!("{:#}", err);
    assert!(
        err_msg.contains("post-processor 1 validation failed"),
        "Expected 'post-processor 1 validation failed' in error, got: {}",
        err_msg
    );
}

#[test]
fn test_pipeline_validate_reports_correct_index() {
    let good = inline_task("echo ok");
    let bad =
        TaskDefinition::Shell(ShellTask::new(ScriptSource::Script("../../../etc/passwd".into())));
    let tasks = [good, bad];
    let pipeline = Pipeline::new(&[], &tasks, &[]);
    let err = pipeline.validate().unwrap_err();
    let err_msg = format!("{:#}", err);
    assert!(
        err_msg.contains("provisioner 2 validation failed"),
        "Expected 'provisioner 2 validation failed' in error, got: {}",
        err_msg
    );
}

#[test]
fn test_pipeline_validate_stops_at_first_failing_phase() {
    let bad_pre = [TaskDefinition::Shell(ShellTask::new(ScriptSource::Script(
        "../../../etc/shadow".into(),
    )))];
    let bad_prov = [TaskDefinition::Shell(ShellTask::new(ScriptSource::Script(
        "../../../etc/passwd".into(),
    )))];
    let pipeline = Pipeline::new(&bad_pre, &bad_prov, &[]);
    let err = pipeline.validate().unwrap_err();
    let err_msg = format!("{:#}", err);
    assert!(
        err_msg.contains("pre-processor 1 validation failed"),
        "Expected pre-processor error, got: {}",
        err_msg
    );
    assert!(
        !err_msg.contains("provisioner"),
        "Should not contain provisioner error when pre-processor fails, got: {}",
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
    let pre = [inline_task("echo pre")];
    let prov = [inline_task("echo prov")];
    let post = [inline_task("echo post")];
    let pipeline = Pipeline::new(&pre, &prov, &post);

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
    let pipeline = Pipeline::new(&tasks, &[], &[]);

    let mock_executor = Arc::new(MockExecutor::failing_on(0));
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, true);
    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("failed to run pre-processor 1"),
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
fn test_pipeline_run_phase_order_is_strictly_pre_prov_post() {
    let mut pre_task =
        ShellTask::with_shell(ScriptSource::Content("echo pre".to_string()), "/bin/sh-pre");
    pre_task.resolve_privilege(None).unwrap();
    pre_task.resolve_isolation(&IsolationConfig::default());
    let pre = [TaskDefinition::Shell(pre_task)];
    let mut prov_task =
        ShellTask::with_shell(ScriptSource::Content("echo prov".to_string()), "/bin/sh-prov");
    prov_task.resolve_privilege(None).unwrap();
    prov_task.resolve_isolation(&IsolationConfig::default());
    let prov = [TaskDefinition::Shell(prov_task)];
    let mut post_task =
        ShellTask::with_shell(ScriptSource::Content("echo post".to_string()), "/bin/sh-post");
    post_task.resolve_privilege(None).unwrap();
    post_task.resolve_isolation(&IsolationConfig::default());
    let post = [TaskDefinition::Shell(post_task)];
    let pipeline = Pipeline::new(&pre, &prov, &post);

    let mock_executor = Arc::new(MockExecutor::new());
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, true);
    assert!(result.is_ok(), "pipeline run failed: {:?}", result);

    let calls = mock_executor.calls();
    assert_eq!(calls.len(), 3);

    // ChrootContext wraps: ["chroot", rootfs, ...command],
    // so call[0]="chroot", call[1]=rootfs, call[2]=shell
    assert_eq!(calls[0][2], String::from("/bin/sh-pre"));
    assert_eq!(calls[1][2], String::from("/bin/sh-prov"));
    assert_eq!(calls[2][2], String::from("/bin/sh-post"));
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
fn test_pipeline_run_stops_on_first_phase_error() {
    let pre = [inline_task("echo pre")];
    let prov = [inline_task("echo prov")];
    let post = [inline_task("echo post")];
    let pipeline = Pipeline::new(&pre, &prov, &post);

    let mock_executor = Arc::new(MockExecutor::failing_on(0));
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, true);
    assert!(result.is_err());
    assert_eq!(mock_executor.call_count(), 1);
}

#[test]
fn test_pipeline_run_provisioner_failure_skips_post_processors() {
    let pre = [inline_task("echo pre")];
    let prov = [inline_task("echo prov")];
    let post = [inline_task("echo post")];
    let pipeline = Pipeline::new(&pre, &prov, &post);

    // failing_on(1): pre (call 0) succeeds, prov (call 1) fails, post never runs
    let mock_executor = Arc::new(MockExecutor::failing_on(1));
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), executor, true);
    assert!(result.is_err());

    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("failed to run provisioner 1"),
        "Expected provisioner failure error, got: {}",
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

// =============================================================================
// validate() variant preservation tests
// =============================================================================

#[test]
fn test_pipeline_validate_preserves_validation_variant() {
    let bad_task = [TaskDefinition::Shell(ShellTask::new(ScriptSource::Script(
        "../../../etc/passwd".into(),
    )))];
    let pipeline = Pipeline::new(&bad_task, &[], &[]);
    let err = pipeline.validate().unwrap_err();
    assert!(
        matches!(
            err,
            RsdebstrapError::Validation(ref msg)
                if msg.contains("pre-processor 1 validation failed")
        ),
        "Expected RsdebstrapError::Validation with phase context, got: {:?}",
        err,
    );
}

#[test]
fn test_pipeline_validate_preserves_io_variant() {
    let nonexistent_task = [TaskDefinition::Shell(ShellTask::new(ScriptSource::Script(
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
                context.contains("provisioner 1 validation failed"),
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
