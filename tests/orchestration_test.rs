use std::ffi::OsString;
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
        file: "examples/debian_trixie_mmdebstrap.yml".into(),
        log_level: cli::LogLevel::Error,
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
        file: "examples/debian_trixie_mmdebstrap.yml".into(),
        log_level: cli::LogLevel::Error,
    };

    run_validate(&opts).expect("run_validate should succeed for sample profile");
}

#[test]
fn run_apply_with_provisioners_uses_isolation() {
    let opts = cli::ApplyArgs {
        file: "examples/debian_trixie_with_provisioners.yml".into(),
        log_level: cli::LogLevel::Error,
        dry_run: true,
    };
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });

    run_apply(&opts, executor).expect("run_apply should succeed");

    let calls = calls.lock().unwrap();
    // Expect 2 calls: 1 for bootstrap (mmdebstrap), 1 for provisioner (chroot)
    assert_eq!(calls.len(), 2);

    // First call should be mmdebstrap
    let (command, _) = &calls[0];
    assert_eq!(command, "mmdebstrap");

    // Second call should be chroot (from provisioner via isolation)
    let (command, args) = &calls[1];
    assert_eq!(command, "chroot");
    // First arg should be the rootfs path
    assert!(args[0].to_string_lossy().contains("rootfs"));
    // Second arg should be the shell
    assert_eq!(args[1], "/bin/sh");
}
