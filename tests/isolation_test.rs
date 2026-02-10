use std::sync::{Arc, Mutex};

use rsdebstrap::RsdebstrapError;
use rsdebstrap::executor::{CommandExecutor, CommandSpec, ExecutionResult};
use rsdebstrap::isolation::{ChrootProvider, DirectProvider, IsolationProvider};
use rsdebstrap::privilege::PrivilegeMethod;

type CommandCalls = Arc<Mutex<Vec<(String, Vec<String>, Option<PrivilegeMethod>)>>>;

#[derive(Default)]
struct RecordingExecutor {
    calls: CommandCalls,
}

impl CommandExecutor for RecordingExecutor {
    fn execute(&self, spec: &CommandSpec) -> anyhow::Result<ExecutionResult> {
        self.calls
            .lock()
            .unwrap()
            .push((spec.command.clone(), spec.args.clone(), spec.privilege));
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
    let command: Vec<String> = vec!["/bin/sh".to_string(), "/tmp/script.sh".to_string()];

    let context = provider.setup(rootfs, executor, false).unwrap();
    let result = context.execute(&command, None);
    assert!(result.is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (cmd, args, privilege) = &calls[0];
    assert_eq!(cmd, "chroot");
    assert_eq!(args.len(), 3);
    assert_eq!(args[0], "/tmp/rootfs");
    assert_eq!(args[1], "/bin/sh");
    assert_eq!(args[2], "/tmp/script.sh");
    assert_eq!(*privilege, None);
}

#[test]
fn test_chroot_context_execute_empty_command() {
    let provider = ChrootProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");
    let command: Vec<String> = vec![];

    let context = provider.setup(rootfs, executor, false).unwrap();
    let result = context.execute(&command, None);
    assert!(result.is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (cmd, args, _privilege) = &calls[0];
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
    let cmd1: Vec<String> = vec!["/bin/echo".to_string(), "hello".to_string()];
    let cmd2: Vec<String> = vec!["/bin/ls".to_string(), "-la".to_string()];

    assert!(context.execute(&cmd1, None).is_ok());
    assert!(context.execute(&cmd2, None).is_ok());

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

    let command: Vec<String> = vec!["/bin/sh".to_string()];
    let err = context.execute(&command, None).unwrap_err();
    let downcast = err.downcast_ref::<RsdebstrapError>();
    assert!(downcast.is_some(), "Expected RsdebstrapError in error chain, got: {:#}", err,);
    assert!(
        matches!(downcast.unwrap(), RsdebstrapError::Isolation(_)),
        "Expected RsdebstrapError::Isolation, got: {:?}",
        downcast.unwrap(),
    );
}

// =============================================================================
// Privilege propagation tests
// =============================================================================

#[test]
fn test_chroot_context_propagates_sudo_privilege() {
    let provider = ChrootProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");
    let command: Vec<String> = vec!["/bin/sh".to_string(), "/tmp/script.sh".to_string()];

    let context = provider.setup(rootfs, executor, false).unwrap();
    let result = context.execute(&command, Some(PrivilegeMethod::Sudo));
    assert!(result.is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (cmd, args, privilege) = &calls[0];
    assert_eq!(cmd, "chroot");
    assert_eq!(args[0], "/tmp/rootfs");
    assert_eq!(args[1], "/bin/sh");
    assert_eq!(args[2], "/tmp/script.sh");
    assert_eq!(*privilege, Some(PrivilegeMethod::Sudo));
}

#[test]
fn test_chroot_context_propagates_doas_privilege() {
    let provider = ChrootProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");
    let command: Vec<String> = vec!["/bin/sh".to_string(), "/tmp/script.sh".to_string()];

    let context = provider.setup(rootfs, executor, false).unwrap();
    let result = context.execute(&command, Some(PrivilegeMethod::Doas));
    assert!(result.is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (_, _, privilege) = &calls[0];
    assert_eq!(*privilege, Some(PrivilegeMethod::Doas));
}

#[test]
fn test_chroot_context_propagates_none_privilege() {
    let provider = ChrootProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");
    let command: Vec<String> = vec!["/bin/sh".to_string()];

    let context = provider.setup(rootfs, executor, false).unwrap();
    let result = context.execute(&command, None);
    assert!(result.is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (_, _, privilege) = &calls[0];
    assert_eq!(*privilege, None);
}

// =============================================================================
// DirectProvider tests
// =============================================================================

#[test]
fn test_direct_provider_name() {
    let provider = DirectProvider;
    assert_eq!(provider.name(), "direct");
}

#[test]
fn test_direct_provider_setup_creates_context() {
    let provider = DirectProvider;
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor::default());
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");

    let context = provider.setup(rootfs, executor, false);
    assert!(context.is_ok());

    let context = context.unwrap();
    assert_eq!(context.name(), "direct");
    assert_eq!(context.rootfs(), rootfs);
}

// =============================================================================
// DirectContext execution tests
// =============================================================================

#[test]
fn test_direct_context_execute_translates_absolute_paths() {
    let provider = DirectProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");
    let command: Vec<String> = vec!["/bin/sh".to_string(), "/tmp/script.sh".to_string()];

    let context = provider.setup(rootfs, executor, false).unwrap();
    let result = context.execute(&command, None);
    assert!(result.is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (cmd, args, _) = &calls[0];
    assert_eq!(cmd, "/tmp/rootfs/bin/sh");
    assert_eq!(args.len(), 1);
    assert_eq!(args[0], "/tmp/rootfs/tmp/script.sh");
}

#[test]
fn test_direct_context_execute_preserves_relative_paths() {
    let provider = DirectProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");
    let command: Vec<String> = vec!["relative/bin".to_string(), "relative/arg".to_string()];

    let context = provider.setup(rootfs, executor, false).unwrap();
    let result = context.execute(&command, None);
    assert!(result.is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (cmd, args, _) = &calls[0];
    assert_eq!(cmd, "relative/bin");
    assert_eq!(args[0], "relative/arg");
}

#[test]
fn test_direct_context_execute_empty_command_returns_error() {
    let provider = DirectProvider;
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor::default());
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");
    let command: Vec<String> = vec![];

    let context = provider.setup(rootfs, executor, false).unwrap();
    let err = context.execute(&command, None).unwrap_err();
    let downcast = err.downcast_ref::<RsdebstrapError>();
    assert!(downcast.is_some(), "Expected RsdebstrapError, got: {:#}", err);
    assert!(
        matches!(
            downcast.unwrap(),
            RsdebstrapError::Isolation(msg) if msg.contains("empty command")
        ),
        "Expected Isolation error with 'empty command', got: {:?}",
        downcast.unwrap(),
    );
}

// =============================================================================
// DirectContext lifecycle tests
// =============================================================================

#[test]
fn test_direct_context_teardown_is_idempotent() {
    let provider = DirectProvider;
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor::default());
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");

    let mut context = provider.setup(rootfs, executor, false).unwrap();

    // First teardown should succeed
    assert!(context.teardown().is_ok());

    // Second teardown should also succeed (idempotent)
    assert!(context.teardown().is_ok());
}

#[test]
fn test_direct_context_multiple_executions() {
    let provider = DirectProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");

    let context = provider.setup(rootfs, executor, false).unwrap();

    let cmd1: Vec<String> = vec!["/bin/echo".to_string(), "hello".to_string()];
    let cmd2: Vec<String> = vec!["/bin/ls".to_string(), "-la".to_string()];

    assert!(context.execute(&cmd1, None).is_ok());
    assert!(context.execute(&cmd2, None).is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);

    // Verify first command (absolute paths translated)
    assert_eq!(calls[0].0, "/tmp/rootfs/bin/echo");

    // Verify second command (absolute paths translated, relative preserved)
    assert_eq!(calls[1].0, "/tmp/rootfs/bin/ls");
    assert_eq!(calls[1].1[0], "-la"); // relative arg preserved
}

#[test]
fn test_direct_context_execute_after_teardown_returns_isolation_error() {
    let provider = DirectProvider;
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor::default());
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");

    let mut context = provider.setup(rootfs, executor, false).unwrap();
    context.teardown().unwrap();

    let command: Vec<String> = vec!["/bin/sh".to_string()];
    let err = context.execute(&command, None).unwrap_err();
    let downcast = err.downcast_ref::<RsdebstrapError>();
    assert!(downcast.is_some(), "Expected RsdebstrapError in error chain, got: {:#}", err);
    assert!(
        matches!(downcast.unwrap(), RsdebstrapError::Isolation(_)),
        "Expected RsdebstrapError::Isolation, got: {:?}",
        downcast.unwrap(),
    );
}

// =============================================================================
// DirectContext privilege propagation tests
// =============================================================================

#[test]
fn test_direct_context_propagates_sudo_privilege() {
    let provider = DirectProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");
    let command: Vec<String> = vec!["/bin/sh".to_string(), "/tmp/script.sh".to_string()];

    let context = provider.setup(rootfs, executor, false).unwrap();
    let result = context.execute(&command, Some(PrivilegeMethod::Sudo));
    assert!(result.is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (cmd, args, privilege) = &calls[0];
    assert_eq!(cmd, "/tmp/rootfs/bin/sh");
    assert_eq!(args[0], "/tmp/rootfs/tmp/script.sh");
    assert_eq!(*privilege, Some(PrivilegeMethod::Sudo));
}

#[test]
fn test_direct_context_propagates_doas_privilege() {
    let provider = DirectProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");
    let command: Vec<String> = vec!["/bin/sh".to_string()];

    let context = provider.setup(rootfs, executor, false).unwrap();
    let result = context.execute(&command, Some(PrivilegeMethod::Doas));
    assert!(result.is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (_, _, privilege) = &calls[0];
    assert_eq!(*privilege, Some(PrivilegeMethod::Doas));
}

#[test]
fn test_direct_context_propagates_none_privilege() {
    let provider = DirectProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");
    let command: Vec<String> = vec!["/bin/sh".to_string()];

    let context = provider.setup(rootfs, executor, false).unwrap();
    let result = context.execute(&command, None);
    assert!(result.is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (_, _, privilege) = &calls[0];
    assert_eq!(*privilege, None);
}
