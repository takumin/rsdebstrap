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
    fn dry_run(&self) -> bool {
        true
    }

    fn execute(&self, spec: &CommandSpec) -> anyhow::Result<ExecutionResult> {
        self.calls
            .lock()
            .unwrap()
            .push((spec.command().to_string(), spec.args().to_vec()));
        Ok(ExecutionResult { status: None })
    }
}

// Write YAML content to a temporary file and return it (kept alive by caller).
fn write_yaml_tempfile(yaml: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("failed to create temp file");
    file.write_all(yaml.as_bytes())
        .expect("failed to write yaml");
    if !yaml.ends_with('\n') {
        writeln!(file).expect("failed to write trailing newline");
    }
    file
}

// Minimal bootstrap-only YAML (no provisioners).
fn bootstrap_only_yaml() -> &'static str {
    // editorconfig-checker-disable
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
    // editorconfig-checker-enable
}

// `bootstrap_only_yaml` with the output directory chosen by the caller, for tests that
// assert on whether the directory ends up existing.
fn bootstrap_only_yaml_in(dir: &Utf8Path) -> String {
    // editorconfig-checker-disable
    format!(
        r#"---
dir: {dir}
bootstrap:
  type: mmdebstrap
  suite: trixie
  target: rootfs.tar.zst
  mirrors:
  - https://deb.debian.org/debian
"#
    )
    // editorconfig-checker-enable
}

// Minimal YAML with a provisioner (requires directory target for pipeline).
fn provisioner_yaml() -> &'static str {
    // editorconfig-checker-disable
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
provision:
- type: shell
  content: |-
    #!/bin/sh
    set -e
    echo "provisioning"
"#
    // editorconfig-checker-enable
}

fn bootstrap_only_debootstrap_yaml() -> &'static str {
    // editorconfig-checker-disable
    r#"---
dir: /tmp/orchestration-test-debootstrap
bootstrap:
  type: debootstrap
  suite: trixie
  target: rootfs
  mirror: https://deb.debian.org/debian
"#
    // editorconfig-checker-enable
}

#[test]
fn run_apply_uses_executor_with_built_args() {
    let file = write_yaml_tempfile(bootstrap_only_yaml());
    let path = Utf8Path::from_path(file.path()).expect("temp path should be valid UTF-8");
    let common = cli::CommonArgs {
        file: path.to_owned(),
        log_level: cli::LogLevel::Error,
    };
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });

    run_apply(&common, executor).expect("run_apply should succeed");

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (command, args) = calls.first().expect("at least one call");
    assert_eq!(command, "mmdebstrap");
    assert!(!args.is_empty(), "expected args to be populated");
}

#[test]
fn run_apply_uses_executor_with_debootstrap_args() {
    let file = write_yaml_tempfile(bootstrap_only_debootstrap_yaml());
    let path = Utf8Path::from_path(file.path()).expect("temp path should be valid UTF-8");
    let common = cli::CommonArgs {
        file: path.to_owned(),
        log_level: cli::LogLevel::Error,
    };
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });

    run_apply(&common, executor).expect("run_apply should succeed");

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (command, args) = calls.first().expect("at least one call");
    assert_eq!(command, "debootstrap");
    // Exact argv guards against a wrong suite/target/mirror slipping through.
    assert_eq!(
        args,
        &vec![
            "trixie".to_string(),
            "/tmp/orchestration-test-debootstrap/rootfs".to_string(),
            "https://deb.debian.org/debian".to_string(),
        ],
        "debootstrap should be invoked with the built suite/target/mirror argv"
    );
}

#[test]
fn run_validate_succeeds_on_valid_profile() {
    let file = write_yaml_tempfile(bootstrap_only_yaml());
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
    let file = write_yaml_tempfile(provisioner_yaml());
    let path = Utf8Path::from_path(file.path()).expect("temp path should be valid UTF-8");
    let common = cli::CommonArgs {
        file: path.to_owned(),
        log_level: cli::LogLevel::Error,
    };
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });

    run_apply(&common, executor).expect("run_apply should succeed");

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);

    let (command, _) = &calls[0];
    assert_eq!(command, "mmdebstrap");

    let (command, args) = &calls[1];
    assert_eq!(command, "chroot");
    assert!(args[0].contains("rootfs"));
    assert_eq!(args[1], "/bin/sh");
}

// An executor that fails on the Nth call (1-indexed).
// Used to simulate failures at specific points in the execution flow.
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
    fn dry_run(&self) -> bool {
        true
    }

    fn execute(&self, spec: &CommandSpec) -> anyhow::Result<ExecutionResult> {
        let current = self.call_count.fetch_add(1, Ordering::SeqCst) + 1;
        self.calls
            .lock()
            .unwrap()
            .push((spec.command().to_string(), spec.args().to_vec()));

        if current >= self.fail_on_call {
            anyhow::bail!("simulated failure on call {}", current)
        }
        Ok(ExecutionResult { status: None })
    }
}

// In dry-run mode there is no separate teardown command, so this covers the
// pipeline task error alone; the teardown error paths live in
// `src/lib.rs`'s `run_pipeline_phase` tests and `src/isolation/mount.rs`.
#[test]
fn run_apply_propagates_provision_failure() {
    let file = write_yaml_tempfile(provisioner_yaml());
    let path = Utf8Path::from_path(file.path()).expect("temp path should be valid UTF-8");
    let common = cli::CommonArgs {
        file: path.to_owned(),
        log_level: cli::LogLevel::Error,
    };

    // Fail starting from the 2nd call (pipeline task execution)
    // Call 1: mmdebstrap (succeeds)
    // Call 2: chroot for pipeline task (fails) - this is the pipeline error
    let executor: Arc<dyn CommandExecutor> = Arc::new(FailingExecutor::new(2));

    let result = run_apply(&common, executor);

    assert!(result.is_err());

    let err = result.unwrap_err();
    let err_string = format!("{:#}", err);

    assert!(
        err_string.contains("failed to run provision"),
        "Expected provisioner error, got: {}",
        err_string
    );
}

// `CommandExecutor::dry_run()` is the only thing that says a run is a dry one, and a mock
// that answers `false` sends this suite's "dry run" cases live without failing anything.
// Pinning the directory catches that: it is the first thing `run_apply` does differently,
// and it does it before any executor call.
#[test]
fn a_dry_run_creates_no_directory() {
    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    let dir = Utf8Path::from_path(tmp.path()).expect("temp path should be valid UTF-8");
    let absent = dir.join("would-be-created");

    let file = write_yaml_tempfile(&bootstrap_only_yaml_in(&absent));
    let path = Utf8Path::from_path(file.path()).expect("temp path should be valid UTF-8");
    let common = cli::CommonArgs {
        file: path.to_owned(),
        log_level: cli::LogLevel::Error,
    };

    run_apply(&common, Arc::new(RecordingExecutor::default())).expect("run_apply should succeed");

    assert!(!absent.exists(), "a dry run created {absent}");
}
