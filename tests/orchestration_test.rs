use std::ffi::OsString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rsdebstrap::{
    cli,
    executor::{CommandExecutor, CommandSpec, ExecutionResult},
    run_apply, run_validate,
};

type CommandCalls = Arc<Mutex<Vec<(String, Vec<OsString>)>>>;

#[derive(Default)]
struct RecordingExecutor {
    calls: CommandCalls,
}

impl CommandExecutor for RecordingExecutor {
    fn execute(&self, spec: &CommandSpec) -> anyhow::Result<ExecutionResult> {
        self.calls
            .lock()
            .unwrap()
            .push((spec.command.clone(), spec.args.clone()));
        Ok(ExecutionResult { status: None })
    }
}

#[test]
fn run_apply_uses_executor_with_built_args() {
    let opts = cli::ApplyArgs {
        common: cli::CommonArgs {
            file: "examples/debian_trixie_mmdebstrap.yml".into(),
            log_level: cli::LogLevel::Error,
        },
        dry_run: true,
    };
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });

    run_apply(&opts, executor).expect("run_apply should succeed");

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (command, args) = calls.first().expect("at least one call");
    assert_eq!(command, "mmdebstrap");
    assert!(!args.is_empty(), "expected args to be populated");
}

#[test]
fn run_validate_succeeds_on_valid_profile() {
    let opts = cli::ValidateArgs {
        common: cli::CommonArgs {
            file: "examples/debian_trixie_mmdebstrap.yml".into(),
            log_level: cli::LogLevel::Error,
        },
    };

    run_validate(&opts).expect("run_validate should succeed for sample profile");
}

#[test]
fn run_apply_with_pipeline_tasks_uses_isolation() {
    let opts = cli::ApplyArgs {
        common: cli::CommonArgs {
            file: "examples/debian_trixie_with_provisioners.yml".into(),
            log_level: cli::LogLevel::Error,
        },
        dry_run: true,
    };
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });

    run_apply(&opts, executor).expect("run_apply should succeed");

    let calls = calls.lock().unwrap();
    // Expect 2 calls: 1 for bootstrap (mmdebstrap), 1 for pipeline task (chroot)
    assert_eq!(calls.len(), 2);

    // First call should be mmdebstrap
    let (command, _) = &calls[0];
    assert_eq!(command, "mmdebstrap");

    // Second call should be chroot (from pipeline task via isolation)
    let (command, args) = &calls[1];
    assert_eq!(command, "chroot");
    // First arg should be the rootfs path
    assert!(args[0].to_string_lossy().contains("rootfs"));
    // Second arg should be the shell
    assert_eq!(args[1], "/bin/sh");
}

/// An executor that fails on the Nth call (1-indexed).
/// Used to simulate failures at specific points in the execution flow.
struct FailingExecutor {
    fail_on_call: usize,
    call_count: AtomicUsize,
    calls: CommandCalls,
}

impl FailingExecutor {
    fn new(fail_on_call: usize) -> Self {
        Self {
            fail_on_call,
            call_count: AtomicUsize::new(0),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl CommandExecutor for FailingExecutor {
    fn execute(&self, spec: &CommandSpec) -> anyhow::Result<ExecutionResult> {
        let current = self.call_count.fetch_add(1, Ordering::SeqCst) + 1;
        self.calls
            .lock()
            .unwrap()
            .push((spec.command.clone(), spec.args.clone()));

        if current >= self.fail_on_call {
            anyhow::bail!("simulated failure on call {}", current)
        }
        Ok(ExecutionResult { status: None })
    }
}

#[test]
fn test_run_apply_pipeline_and_teardown_both_fail() {
    // This test verifies that when pipeline execution fails, the error is propagated.
    // Note: In dry_run mode, there is no separate teardown command, so only the
    // pipeline task error is verified here. The teardown error handling path is
    // tested in pipeline_test.rs with mock contexts.

    let opts = cli::ApplyArgs {
        common: cli::CommonArgs {
            file: "examples/debian_trixie_with_provisioners.yml".into(),
            log_level: cli::LogLevel::Error,
        },
        dry_run: true,
    };

    // Fail starting from the 2nd call (pipeline task execution)
    // Call 1: mmdebstrap (succeeds)
    // Call 2: chroot for pipeline task (fails) - this is the pipeline error
    // Note: In dry_run mode with chroot isolation, there's no separate teardown command,
    // but the error handling path is still exercised
    let executor: Arc<dyn CommandExecutor> = Arc::new(FailingExecutor::new(2));

    let result = run_apply(&opts, executor);

    // Should fail
    assert!(result.is_err());

    let err = result.unwrap_err();
    let err_string = format!("{:#}", err);

    // The error should be about the pipeline task failing
    assert!(
        err_string.contains("failed to run provisioner"),
        "Expected provisioner error, got: {}",
        err_string
    );
}
