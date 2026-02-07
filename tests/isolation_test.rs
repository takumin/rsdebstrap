use std::ffi::OsString;
use std::sync::{Arc, Mutex};

use rsdebstrap::RsdebstrapError;
use rsdebstrap::executor::{CommandExecutor, CommandSpec, ExecutionResult};
use rsdebstrap::isolation::{ChrootProvider, IsolationProvider};

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

// =============================================================================
// IsolationProvider tests
// =============================================================================

#[test]
fn test_chroot_provider_name() {
    let provider = ChrootProvider;
    assert_eq!(provider.name(), "chroot");
}

#[test]
fn test_chroot_provider_setup_creates_context() {
    let provider = ChrootProvider;
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor::default());
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");

    let context = provider.setup(rootfs, executor, false);
    assert!(context.is_ok());

    let context = context.unwrap();
    assert_eq!(context.name(), "chroot");
    assert_eq!(context.rootfs(), rootfs);
}

// =============================================================================
// IsolationContext tests
// =============================================================================

#[test]
fn test_chroot_context_execute_builds_correct_args() {
    let provider = ChrootProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");
    let command: Vec<OsString> = vec!["/bin/sh".into(), "/tmp/script.sh".into()];

    let context = provider.setup(rootfs, executor, false).unwrap();
    let result = context.execute(&command);
    assert!(result.is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (cmd, args) = &calls[0];
    assert_eq!(cmd, "chroot");
    assert_eq!(args.len(), 3);
    assert_eq!(args[0], "/tmp/rootfs");
    assert_eq!(args[1], "/bin/sh");
    assert_eq!(args[2], "/tmp/script.sh");
}

#[test]
fn test_chroot_context_execute_empty_command() {
    let provider = ChrootProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");
    let command: Vec<OsString> = vec![];

    let context = provider.setup(rootfs, executor, false).unwrap();
    let result = context.execute(&command);
    assert!(result.is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (cmd, args) = &calls[0];
    assert_eq!(cmd, "chroot");
    assert_eq!(args.len(), 1);
    assert_eq!(args[0], "/tmp/rootfs");
}

#[test]
fn test_chroot_context_teardown_is_idempotent() {
    let provider = ChrootProvider;
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor::default());
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");

    let mut context = provider.setup(rootfs, executor, false).unwrap();

    // First teardown should succeed
    assert!(context.teardown().is_ok());

    // Second teardown should also succeed (idempotent)
    assert!(context.teardown().is_ok());
}

#[test]
fn test_chroot_context_multiple_executions() {
    let provider = ChrootProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");

    let context = provider.setup(rootfs, executor, false).unwrap();

    // Execute multiple commands
    let cmd1: Vec<OsString> = vec!["/bin/echo".into(), "hello".into()];
    let cmd2: Vec<OsString> = vec!["/bin/ls".into(), "-la".into()];

    assert!(context.execute(&cmd1).is_ok());
    assert!(context.execute(&cmd2).is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);

    // Verify first command
    assert_eq!(calls[0].0, "chroot");
    assert_eq!(calls[0].1[0], "/tmp/rootfs");
    assert_eq!(calls[0].1[1], "/bin/echo");

    // Verify second command
    assert_eq!(calls[1].0, "chroot");
    assert_eq!(calls[1].1[0], "/tmp/rootfs");
    assert_eq!(calls[1].1[1], "/bin/ls");
}

#[test]
fn test_chroot_context_execute_after_teardown_returns_isolation_error() {
    let provider = ChrootProvider;
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor::default());
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");

    let mut context = provider.setup(rootfs, executor, false).unwrap();
    context.teardown().unwrap();

    let command: Vec<OsString> = vec!["/bin/sh".into()];
    let err = context.execute(&command).unwrap_err();
    let downcast = err.downcast_ref::<RsdebstrapError>();
    assert!(downcast.is_some(), "Expected RsdebstrapError in error chain, got: {:#}", err,);
    assert!(
        matches!(downcast.unwrap(), RsdebstrapError::Isolation(_)),
        "Expected RsdebstrapError::Isolation, got: {:?}",
        downcast.unwrap(),
    );
}
