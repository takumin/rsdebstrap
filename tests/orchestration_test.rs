use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use camino::Utf8Path;
use rsdebstrap::{
    cli,
    executor::{CommandExecutor, CommandSpec, ExecutionResult},
    run_apply, run_validate,
};
use tempfile::NamedTempFile;

type CommandCalls = Arc<Mutex<Vec<(String, Vec<String>)>>>;

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

/// Write YAML content to a temporary file and return it (kept alive by caller).
fn write_yaml_tempfile(yaml: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("failed to create temp file");
    file.write_all(yaml.as_bytes())
        .expect("failed to write yaml");
    if !yaml.ends_with('\n') {
        writeln!(file).expect("failed to write trailing newline");
    }
    file
}

/// Minimal bootstrap-only YAML (no provisioners).
fn bootstrap_only_yaml() -> String {
    r#"---
dir: /tmp/orchestration-test-bootstrap
bootstrap:
  type: mmdebstrap
  suite: trixie
  target: rootfs.tar.zst
  mirrors:
  - https://deb.debian.org/debian
  variant: apt
  components:
  - main
  architectures:
  - amd64
"#
    .to_string()
}

/// Minimal YAML with a provisioner (requires directory target for pipeline).
fn provisioner_yaml() -> String {
    r#"---
dir: /tmp/orchestration-test-provisioner
defaults:
  isolation:
    type: chroot
  privilege:
    method: sudo
bootstrap:
  type: mmdebstrap
  suite: trixie
  target: rootfs
  mirrors:
  - https://deb.debian.org/debian
  variant: apt
  components:
  - main
  architectures:
  - amd64
provisioners:
- type: shell
  content: |-
    #!/bin/sh
    set -e
    echo "provisioning"
"#
    .to_string()
}

#[test]
fn run_apply_uses_executor_with_built_args() {
    let file = write_yaml_tempfile(&bootstrap_only_yaml());
    let path = Utf8Path::from_path(file.path()).expect("temp path should be valid UTF-8");
    let opts = cli::ApplyArgs {
        common: cli::CommonArgs {
            file: path.to_owned(),
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
    let file = write_yaml_tempfile(&bootstrap_only_yaml());
    let path = Utf8Path::from_path(file.path()).expect("temp path should be valid UTF-8");
    let opts = cli::ValidateArgs {
        common: cli::CommonArgs {
            file: path.to_owned(),
            log_level: cli::LogLevel::Error,
        },
    };

    run_validate(&opts).expect("run_validate should succeed for sample profile");
}

#[test]
fn run_apply_with_pipeline_tasks_uses_isolation() {
    let file = write_yaml_tempfile(&provisioner_yaml());
    let path = Utf8Path::from_path(file.path()).expect("temp path should be valid UTF-8");
    let opts = cli::ApplyArgs {
        common: cli::CommonArgs {
            file: path.to_owned(),
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
    assert!(args[0].contains("rootfs"));
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

    let file = write_yaml_tempfile(&provisioner_yaml());
    let path = Utf8Path::from_path(file.path()).expect("temp path should be valid UTF-8");
    let opts = cli::ApplyArgs {
        common: cli::CommonArgs {
            file: path.to_owned(),
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
