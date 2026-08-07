use std::sync::{Arc, Mutex};

use rsdebstrap::RsdebstrapError;
use rsdebstrap::executor::{CommandExecutor, CommandSpec, ExecutionResult};
use rsdebstrap::isolation::{ChrootProvider, DirectProvider, IsolationProvider};
use rsdebstrap::privilege::PrivilegeMethod;

type CommandCalls = Arc<Mutex<Vec<(String, Vec<String>, Option<PrivilegeMethod>)>>>;

// These tests assert the argv the isolation layer builds, not filesystem
// effects, so the ops handed to the context are never exercised.
fn mock_ops(rootfs: &camino::Utf8Path) -> Arc<dyn rsdebstrap::rootfs::RootfsOps> {
    Arc::new(rsdebstrap::rootfs::DryRunRootfsOps::new(rootfs))
}

#[derive(Default)]
struct RecordingExecutor {
    calls: CommandCalls,
}

impl CommandExecutor for RecordingExecutor {
    fn execute(&self, spec: &CommandSpec) -> anyhow::Result<ExecutionResult> {
        self.calls.lock().unwrap().push((
            spec.command().to_string(),
            spec.args().to_vec(),
            spec.privilege(),
        ));
        Ok(ExecutionResult { status: None })
    }
}

#[test]
fn test_chroot_provider_setup_creates_context() {
    let provider = ChrootProvider;
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor::default());
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");

    let context = provider.setup(rootfs, executor, mock_ops(rootfs));
    assert!(context.is_ok());

    let context = context.unwrap();
    assert_eq!(context.name(), "chroot");
    assert_eq!(context.rootfs(), rootfs);
}

#[test]
fn test_chroot_context_execute_builds_correct_args() {
    let provider = ChrootProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");
    let command: Vec<String> = vec!["/bin/sh".to_string(), "/tmp/script.sh".to_string()];

    let context = provider.setup(rootfs, executor, mock_ops(rootfs)).unwrap();
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

    let context = provider.setup(rootfs, executor, mock_ops(rootfs)).unwrap();
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

    let mut context = provider.setup(rootfs, executor, mock_ops(rootfs)).unwrap();

    assert!(context.teardown().is_ok());
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

    let context = provider.setup(rootfs, executor, mock_ops(rootfs)).unwrap();

    let cmd1: Vec<String> = vec!["/bin/echo".to_string(), "hello".to_string()];
    let cmd2: Vec<String> = vec!["/bin/ls".to_string(), "-la".to_string()];

    assert!(context.execute(&cmd1, None).is_ok());
    assert!(context.execute(&cmd2, None).is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);

    assert_eq!(calls[0].0, "chroot");
    assert_eq!(calls[0].1[0], "/tmp/rootfs");
    assert_eq!(calls[0].1[1], "/bin/echo");

    assert_eq!(calls[1].0, "chroot");
    assert_eq!(calls[1].1[0], "/tmp/rootfs");
    assert_eq!(calls[1].1[1], "/bin/ls");
}

#[test]
fn test_chroot_context_execute_after_teardown_returns_isolation_error() {
    let provider = ChrootProvider;
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor::default());
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");

    let mut context = provider.setup(rootfs, executor, mock_ops(rootfs)).unwrap();
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

#[test]
fn test_chroot_context_propagates_sudo_privilege() {
    let provider = ChrootProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");
    let command: Vec<String> = vec!["/bin/sh".to_string(), "/tmp/script.sh".to_string()];

    let context = provider.setup(rootfs, executor, mock_ops(rootfs)).unwrap();
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

// `PrivilegeMethod` is passed through to the executor untouched, so `Doas`
// exercises the same path as `Sudo` above. The `None` case is covered by
// `test_chroot_context_execute_builds_correct_args`, which asserts the same
// recorded privilege for the same call.

#[test]
fn test_direct_provider_setup_creates_context() {
    let provider = DirectProvider;
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor::default());
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");

    let context = provider.setup(rootfs, executor, mock_ops(rootfs));
    assert!(context.is_ok());

    let context = context.unwrap();
    assert_eq!(context.name(), "direct");
    assert_eq!(context.rootfs(), rootfs);
}

// A rootfs with the programs these tests name, so the `O_NOFOLLOW` walk
// `DirectContext::execute` performs on the program has something to resolve.
fn seeded_direct_rootfs(programs: &[&str]) -> (tempfile::TempDir, camino::Utf8PathBuf) {
    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    let root = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
    std::fs::create_dir_all(root.join("bin")).unwrap();
    std::fs::create_dir_all(root.join("tmp")).unwrap();
    for program in programs {
        std::fs::write(root.join(program.trim_start_matches('/')), "#!/bin/sh\n").unwrap();
    }
    (tmp, root)
}

#[test]
fn test_direct_context_execute_translates_absolute_paths() {
    let provider = DirectProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let (_tmp, rootfs) = seeded_direct_rootfs(&["/bin/sh"]);
    let command: Vec<String> = vec!["/bin/sh".to_string(), "/tmp/script.sh".to_string()];

    let context = provider
        .setup(&rootfs, executor, mock_ops(&rootfs))
        .unwrap();
    let result = context.execute(&command, None);
    assert!(result.is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (cmd, args, privilege) = &calls[0];
    assert_eq!(cmd, &rootfs.join("bin/sh").to_string());
    assert_eq!(args.len(), 1);
    assert_eq!(args[0], rootfs.join("tmp/script.sh").to_string());
    assert_eq!(*privilege, None);
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

    let context = provider.setup(rootfs, executor, mock_ops(rootfs)).unwrap();
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

    let context = provider.setup(rootfs, executor, mock_ops(rootfs)).unwrap();
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

#[test]
fn test_direct_context_teardown_is_idempotent() {
    let provider = DirectProvider;
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor::default());
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");

    let mut context = provider.setup(rootfs, executor, mock_ops(rootfs)).unwrap();

    assert!(context.teardown().is_ok());
    assert!(context.teardown().is_ok());
}

#[test]
fn test_direct_context_multiple_executions() {
    let provider = DirectProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let (_tmp, rootfs) = seeded_direct_rootfs(&["/bin/echo", "/bin/ls"]);

    let context = provider
        .setup(&rootfs, executor, mock_ops(&rootfs))
        .unwrap();

    let cmd1: Vec<String> = vec!["/bin/echo".to_string(), "hello".to_string()];
    let cmd2: Vec<String> = vec!["/bin/ls".to_string(), "-la".to_string()];

    assert!(context.execute(&cmd1, None).is_ok());
    assert!(context.execute(&cmd2, None).is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);

    assert_eq!(calls[0].0, rootfs.join("bin/echo").to_string());

    assert_eq!(calls[1].0, rootfs.join("bin/ls").to_string());
    assert_eq!(calls[1].1[0], "-la"); // relative arg preserved
}

#[test]
fn test_direct_context_execute_after_teardown_returns_isolation_error() {
    let provider = DirectProvider;
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor::default());
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");

    let mut context = provider.setup(rootfs, executor, mock_ops(rootfs)).unwrap();
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

#[test]
fn test_direct_context_propagates_sudo_privilege() {
    let provider = DirectProvider;
    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let (_tmp, rootfs) = seeded_direct_rootfs(&["/bin/sh"]);
    let command: Vec<String> = vec!["/bin/sh".to_string(), "/tmp/script.sh".to_string()];

    let context = provider
        .setup(&rootfs, executor, mock_ops(&rootfs))
        .unwrap();
    let result = context.execute(&command, Some(PrivilegeMethod::Sudo));
    assert!(result.is_ok());

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (cmd, args, privilege) = &calls[0];
    assert_eq!(cmd, &rootfs.join("bin/sh").to_string());
    assert_eq!(args[0], rootfs.join("tmp/script.sh").to_string());
    assert_eq!(*privilege, Some(PrivilegeMethod::Sudo));
}

// As on the chroot side, `Doas` takes the same pass-through path as `Sudo`.
// The `None` case is covered by
// `test_direct_context_execute_translates_absolute_paths`, which asserts the
// same recorded privilege for the same call.

// A rootfs whose `/bin/sh` is a symlink out of the rootfs used to run whatever it pointed
// at: the path handed to the executor is a string join, and the kernel resolves it at exec.
#[test]
fn direct_context_refuses_a_program_symlinked_out_of_the_rootfs() {
    let (_tmp, rootfs) = seeded_direct_rootfs(&[]);
    let outside = tempfile::tempdir().unwrap();
    let evil = outside.path().join("evil");
    std::fs::write(&evil, "#!/bin/sh\n").unwrap();
    std::os::unix::fs::symlink(&evil, rootfs.join("bin/sh")).unwrap();

    let calls: CommandCalls = Arc::new(Mutex::new(Vec::new()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(RecordingExecutor {
        calls: Arc::clone(&calls),
    });
    let context = DirectProvider
        .setup(&rootfs, executor, mock_ops(&rootfs))
        .unwrap();

    let err = context
        .execute(&["/bin/sh".to_string()], None)
        .expect_err("a symlinked program must be refused");
    assert!(format!("{err:#}").contains("is a symlink"), "unexpected error: {err:#}");
    assert!(calls.lock().unwrap().is_empty(), "nothing should have been executed");
}

// A context used to carry its own `dry_run` flag, so pairing a dry-run executor with a live
// context was expressible and silently performed real work. It now derives the answer from
// the executor, which is the layer that would run the commands.
#[test]
fn context_dry_run_comes_from_the_executor() {
    let (_tmp, rootfs) = seeded_direct_rootfs(&[]);
    let ops = mock_ops(&rootfs);

    let live: Arc<dyn CommandExecutor> =
        Arc::new(rsdebstrap::executor::RealCommandExecutor::new(false));
    let dry: Arc<dyn CommandExecutor> =
        Arc::new(rsdebstrap::executor::RealCommandExecutor::new(true));

    let live_ctx = DirectProvider.setup(&rootfs, live, ops.clone()).unwrap();
    let dry_ctx = DirectProvider.setup(&rootfs, dry, ops).unwrap();

    assert!(!live_ctx.dry_run());
    assert!(dry_ctx.dry_run());
}
