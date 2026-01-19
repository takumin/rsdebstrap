use std::cell::RefCell;
use std::ffi::OsString;

use rsdebstrap::{
    cli,
    executor::{CommandExecutor, CommandSpec, ExecutionResult},
    run_apply, run_validate,
};

#[derive(Default)]
struct RecordingExecutor {
    calls: RefCell<Vec<(String, Vec<OsString>)>>,
}

impl CommandExecutor for RecordingExecutor {
    fn execute(&self, spec: &CommandSpec) -> anyhow::Result<ExecutionResult> {
        self.calls
            .borrow_mut()
            .push((spec.command.clone(), spec.args.clone()));
        Ok(ExecutionResult {
            status: success_status(),
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }
}

fn success_status() -> std::process::ExitStatus {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(0)
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(0)
    }
}

#[test]
fn run_apply_uses_executor_with_built_args() {
    let opts = cli::ApplyArgs {
        file: "examples/debian_trixie_mmdebstrap.yml".into(),
        log_level: cli::LogLevel::Error,
        dry_run: true,
    };
    let executor = RecordingExecutor::default();

    run_apply(&opts, &executor).expect("run_apply should succeed");

    let calls = executor.calls.borrow();
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
