//! Tests for the Pipeline orchestrator.

use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use camino::Utf8Path;
use rsdebstrap::executor::{CommandExecutor, CommandSpec, ExecutionResult};
use rsdebstrap::isolation::{IsolationContext, IsolationProvider};
use rsdebstrap::pipeline::Pipeline;
use rsdebstrap::task::{ScriptSource, ShellTask, TaskDefinition};

// =============================================================================
// Mock infrastructure
// =============================================================================

/// Records executed commands in order, optionally failing on specific calls.
struct MockExecutor {
    calls: Mutex<Vec<Vec<OsString>>>,
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

    fn calls(&self) -> Vec<Vec<OsString>> {
        self.calls.lock().unwrap().clone()
    }
}

impl CommandExecutor for MockExecutor {
    fn execute(&self, spec: &CommandSpec) -> Result<ExecutionResult> {
        let mut calls = self.calls.lock().unwrap();
        let index = calls.len();
        let mut args = vec![OsString::from(&spec.command)];
        args.extend(spec.args.iter().cloned());
        calls.push(args);
        drop(calls);

        if self.fail_on_call == Some(index) {
            anyhow::bail!("simulated failure on call {}", index);
        }
        Ok(ExecutionResult { status: None })
    }
}

/// Mock isolation provider that tracks setup/teardown calls.
struct MockProvider {
    setup_should_fail: bool,
    teardown_should_fail: bool,
    teardown_called: Arc<AtomicBool>,
}

impl MockProvider {
    fn new() -> Self {
        Self {
            setup_should_fail: false,
            teardown_should_fail: false,
            teardown_called: Arc::new(AtomicBool::new(false)),
        }
    }

    fn with_setup_failure() -> Self {
        Self {
            setup_should_fail: true,
            teardown_should_fail: false,
            teardown_called: Arc::new(AtomicBool::new(false)),
        }
    }

    fn with_teardown_failure() -> Self {
        Self {
            setup_should_fail: false,
            teardown_should_fail: true,
            teardown_called: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl IsolationProvider for MockProvider {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn setup(
        &self,
        rootfs: &Utf8Path,
        executor: Arc<dyn CommandExecutor>,
        dry_run: bool,
    ) -> Result<Box<dyn IsolationContext>> {
        if self.setup_should_fail {
            anyhow::bail!("mock setup failure");
        }
        Ok(Box::new(MockContext {
            rootfs: rootfs.to_owned(),
            executor,
            dry_run,
            teardown_should_fail: self.teardown_should_fail,
            teardown_called: Arc::clone(&self.teardown_called),
            torn_down: false,
        }))
    }
}

/// Mock isolation context that records command execution.
struct MockContext {
    rootfs: camino::Utf8PathBuf,
    executor: Arc<dyn CommandExecutor>,
    dry_run: bool,
    teardown_should_fail: bool,
    teardown_called: Arc<AtomicBool>,
    torn_down: bool,
}

impl IsolationContext for MockContext {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn rootfs(&self) -> &Utf8Path {
        &self.rootfs
    }

    fn dry_run(&self) -> bool {
        self.dry_run
    }

    fn execute(&self, command: &[OsString]) -> Result<ExecutionResult> {
        let spec = CommandSpec::new("mock", command.to_vec());
        self.executor.execute(&spec)
    }

    fn teardown(&mut self) -> Result<()> {
        if self.torn_down {
            return Ok(());
        }
        self.torn_down = true;
        self.teardown_called.store(true, Ordering::SeqCst);
        if self.teardown_should_fail {
            anyhow::bail!("mock teardown failure");
        }
        Ok(())
    }
}

/// Helper to create a simple inline shell task.
fn inline_task(content: &str) -> TaskDefinition {
    TaskDefinition::Shell(ShellTask::new(ScriptSource::Content(content.to_string())))
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
    // Both pre_processors and provisioners have invalid tasks,
    // but validate should stop at the first failing phase (pre-processor)
    // and not report the provisioner error.
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
    let provider = MockProvider::with_setup_failure();
    let executor: Arc<dyn CommandExecutor> = Arc::new(MockExecutor::new());

    // Empty pipeline should return Ok without even calling setup
    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), &provider, executor, true);
    assert!(result.is_ok());
}

#[test]
fn test_pipeline_run_executes_tasks_in_phase_order() {
    // Create distinct tasks for each phase so we can verify ordering
    let pre = [inline_task("echo pre")];
    let prov = [inline_task("echo prov")];
    let post = [inline_task("echo post")];
    let pipeline = Pipeline::new(&pre, &prov, &post);

    let mock_executor = Arc::new(MockExecutor::new());
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;
    let provider = MockProvider::new();

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), &provider, executor, true);
    assert!(result.is_ok(), "pipeline run failed: {:?}", result);

    // All 3 tasks should have been executed
    assert_eq!(mock_executor.call_count(), 3);

    // Verify execution order by checking the script paths in /tmp
    let calls = mock_executor.calls();
    // Each call goes through MockContext which creates CommandSpec with "mock" as command
    // The args are the original command passed to IsolationContext::execute
    // ShellTask creates: [shell_path, script_path_in_chroot]
    // Since we're in dry_run mode, scripts are not actually written
    // but commands are still dispatched
    for call in &calls {
        // call[0] is "mock" (from MockContext)
        // call[1] is "/bin/sh" (the shell)
        // call[2] is "/tmp/task-<uuid>.sh" (the script path)
        assert_eq!(call[0], OsString::from("mock"));
        assert_eq!(call[1], OsString::from("/bin/sh"));
    }

    // Teardown must be called after successful execution
    assert!(
        provider.teardown_called.load(Ordering::SeqCst),
        "teardown must be called after successful execution"
    );
}

#[test]
fn test_pipeline_run_setup_failure() {
    let tasks = [inline_task("echo hello")];
    let pipeline = Pipeline::new(&tasks, &[], &[]);
    let provider = MockProvider::with_setup_failure();
    let executor: Arc<dyn CommandExecutor> = Arc::new(MockExecutor::new());

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), &provider, executor, true);
    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("failed to setup isolation context"),
        "Expected setup failure error, got: {}",
        err_msg
    );
}

#[test]
fn test_pipeline_run_phase_error_with_successful_teardown() {
    // Task execution fails, but teardown succeeds -> returns phase error
    let tasks = [inline_task("echo hello")];
    let pipeline = Pipeline::new(&tasks, &[], &[]);

    let mock_executor = Arc::new(MockExecutor::failing_on(0));
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;
    let provider = MockProvider::new();

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), &provider, executor, true);
    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("failed to run pre-processor 1"),
        "Expected phase error, got: {}",
        err_msg
    );
    // Should NOT contain teardown error
    assert!(
        !err_msg.contains("teardown"),
        "Should not contain teardown error, got: {}",
        err_msg
    );
    // Teardown must still be called even when phases fail
    assert!(
        provider.teardown_called.load(Ordering::SeqCst),
        "teardown must be called even when a phase fails"
    );
}

#[test]
fn test_pipeline_run_successful_phases_with_teardown_error() {
    // All phases succeed, but teardown fails -> returns teardown error
    let tasks = [inline_task("echo hello")];
    let pipeline = Pipeline::new(&tasks, &[], &[]);

    let mock_executor = Arc::new(MockExecutor::new());
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;
    let provider = MockProvider::with_teardown_failure();

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), &provider, executor, true);
    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("failed to teardown isolation context"),
        "Expected teardown error, got: {}",
        err_msg
    );
    // Teardown was attempted (even though it failed)
    assert!(
        provider.teardown_called.load(Ordering::SeqCst),
        "teardown must be called even when it fails"
    );
}

#[test]
fn test_pipeline_run_phase_error_and_teardown_error() {
    // Both phase and teardown fail -> returns phase error with teardown context
    let tasks = [inline_task("echo hello")];
    let pipeline = Pipeline::new(&tasks, &[], &[]);

    let mock_executor = Arc::new(MockExecutor::failing_on(0));
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;
    let provider = MockProvider::with_teardown_failure();

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), &provider, executor, true);
    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    // Phase error should be the primary error returned
    assert!(
        err_msg.contains("failed to run pre-processor 1"),
        "Expected phase error as primary error, got: {}",
        err_msg
    );
    // Teardown error should be attached as context
    assert!(
        err_msg.contains("additionally, teardown failed"),
        "Expected teardown context in error, got: {}",
        err_msg
    );
    // Teardown must be called even when both phases and teardown fail
    assert!(
        provider.teardown_called.load(Ordering::SeqCst),
        "teardown must be called even when both phases and teardown fail"
    );
}

#[test]
fn test_pipeline_run_skips_empty_phases() {
    // Only provisioners phase has tasks; pre and post are empty
    let prov = [inline_task("echo prov")];
    let pipeline = Pipeline::new(&[], &prov, &[]);

    let mock_executor = Arc::new(MockExecutor::new());
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;
    let provider = MockProvider::new();

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), &provider, executor, true);
    assert!(result.is_ok());

    // Only one task should have been executed
    assert_eq!(mock_executor.call_count(), 1);
}

#[test]
fn test_pipeline_run_phase_order_is_strictly_pre_prov_post() {
    // Use distinct shell paths per phase to verify strict ordering
    let pre = [TaskDefinition::Shell(ShellTask::with_shell(
        ScriptSource::Content("echo pre".to_string()),
        "/bin/sh-pre",
    ))];
    let prov = [TaskDefinition::Shell(ShellTask::with_shell(
        ScriptSource::Content("echo prov".to_string()),
        "/bin/sh-prov",
    ))];
    let post = [TaskDefinition::Shell(ShellTask::with_shell(
        ScriptSource::Content("echo post".to_string()),
        "/bin/sh-post",
    ))];
    let pipeline = Pipeline::new(&pre, &prov, &post);

    let mock_executor = Arc::new(MockExecutor::new());
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;
    let provider = MockProvider::new();

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), &provider, executor, true);
    assert!(result.is_ok(), "pipeline run failed: {:?}", result);

    let calls = mock_executor.calls();
    assert_eq!(calls.len(), 3);

    // Verify strict phase ordering via shell path in args[1]
    // call[0] = "mock", call[1] = shell path, call[2] = script path
    assert_eq!(calls[0][1], OsString::from("/bin/sh-pre"));
    assert_eq!(calls[1][1], OsString::from("/bin/sh-prov"));
    assert_eq!(calls[2][1], OsString::from("/bin/sh-post"));
}

#[test]
fn test_pipeline_run_stops_within_phase_on_error() {
    // provisioner phase has 3 tasks; 2nd fails -> 3rd should NOT execute
    let prov = [
        inline_task("echo prov1"),
        inline_task("echo prov2"),
        inline_task("echo prov3"),
    ];
    let pipeline = Pipeline::new(&[], &prov, &[]);

    let mock_executor = Arc::new(MockExecutor::failing_on(1)); // fail on 2nd call (0-indexed)
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;
    let provider = MockProvider::new();

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), &provider, executor, true);
    assert!(result.is_err());

    // 1st task succeeds (call 0), 2nd task fails (call 1), 3rd never executed
    assert_eq!(mock_executor.call_count(), 2);
}

#[test]
fn test_pipeline_run_stops_on_first_phase_error() {
    // pre-processor fails, provisioners and post-processors should NOT execute
    let pre = [inline_task("echo pre")];
    let prov = [inline_task("echo prov")];
    let post = [inline_task("echo post")];
    let pipeline = Pipeline::new(&pre, &prov, &post);

    let mock_executor = Arc::new(MockExecutor::failing_on(0));
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;
    let provider = MockProvider::new();

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), &provider, executor, true);
    assert!(result.is_err());

    // Only 1 call should have been made (the failed pre-processor)
    assert_eq!(mock_executor.call_count(), 1);
}

#[test]
fn test_pipeline_run_provisioner_failure_skips_post_processors() {
    // provisioner fails -> post-processors should NOT execute
    let pre = [inline_task("echo pre")];
    let prov = [inline_task("echo prov")];
    let post = [inline_task("echo post")];
    let pipeline = Pipeline::new(&pre, &prov, &post);

    // fail_on_call=1 means: call 0 (pre) succeeds, call 1 (prov) fails
    let mock_executor = Arc::new(MockExecutor::failing_on(1));
    let executor: Arc<dyn CommandExecutor> = Arc::clone(&mock_executor) as Arc<dyn CommandExecutor>;
    let provider = MockProvider::new();

    let result = pipeline.run(Utf8Path::new("/tmp/rootfs"), &provider, executor, true);
    assert!(result.is_err());

    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("failed to run provisioner 1"),
        "Expected provisioner failure error, got: {}",
        err_msg
    );

    // pre-processor (call 0) succeeded, provisioner (call 1) failed,
    // post-processor should NOT have been executed
    assert_eq!(mock_executor.call_count(), 2);
}
