// Security validation tests for ShellTask.

mod helpers;

use std::cell::RefCell;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use anyhow::Result;
use camino::Utf8Path;
use rsdebstrap::RsdebstrapError;
use rsdebstrap::executor::ExecutionResult;
use rsdebstrap::isolation::IsolationContext;
use rsdebstrap::phase::{ScriptSource, ShellTask};
use tempfile::tempdir;

use crate::helpers::MockContext;

// Helper to set up a valid rootfs with /tmp and /bin/sh
fn setup_valid_rootfs(temp_dir: &tempfile::TempDir) {
    let rootfs = temp_dir.path();
    std::fs::create_dir(rootfs.join("tmp")).expect("failed to create tmp dir");
    std::fs::create_dir_all(rootfs.join("bin")).expect("failed to create bin dir");
    std::fs::write(rootfs.join("bin/sh"), "#!/bin/sh\n").expect("failed to write /bin/sh");
}

#[test]
fn test_run_fails_when_tmp_missing() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    let task = ShellTask::new(ScriptSource::Content("echo test".to_string()));

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context, None);

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("/tmp directory not found"),
        "Expected '/tmp directory not found' in error, got: {}",
        err_msg
    );
}

#[test]
fn test_run_fails_when_tmp_is_symlink() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    let tmp_path = temp_dir.path().join("tmp");
    let target_path = temp_dir.path().join("somewhere_else");
    std::fs::create_dir(&target_path).expect("failed to create target dir");
    std::os::unix::fs::symlink(&target_path, &tmp_path).expect("failed to create symlink");

    let task = ShellTask::new(ScriptSource::Content("echo test".to_string()));

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context, None);

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(err_msg.contains("symlink"), "Expected 'symlink' in error, got: {}", err_msg);
}

#[test]
fn test_run_fails_when_tmp_is_file() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    let tmp_path = temp_dir.path().join("tmp");
    std::fs::write(&tmp_path, "not a directory").expect("failed to create tmp file");

    let task = ShellTask::new(ScriptSource::Content("echo test".to_string()));

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context, None);

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("not a directory"),
        "Expected 'not a directory' in error, got: {}",
        err_msg
    );
}

#[test]
fn test_run_fails_when_shell_has_path_traversal() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    std::fs::create_dir(temp_dir.path().join("tmp")).expect("failed to create tmp dir");

    let task =
        ShellTask::with_shell(ScriptSource::Content("echo test".to_string()), "/bin/../etc/passwd");

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context, None);

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(err_msg.contains(".."), "Expected '..' in error, got: {}", err_msg);
}

#[test]
fn test_run_fails_when_shell_not_exists() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    std::fs::create_dir(temp_dir.path().join("tmp")).expect("failed to create tmp dir");

    let task = ShellTask::new(ScriptSource::Content("echo test".to_string()));

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context, None);

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("does not exist"),
        "Expected 'does not exist' in error, got: {}",
        err_msg
    );
}

#[test]
fn test_run_fails_when_shell_is_directory() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    std::fs::create_dir(temp_dir.path().join("tmp")).expect("failed to create tmp dir");
    std::fs::create_dir_all(temp_dir.path().join("bin/sh")).expect("failed to create bin/sh dir");

    let task = ShellTask::new(ScriptSource::Content("echo test".to_string()));

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context, None);

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(err_msg.contains("directory"), "Expected 'directory' in error, got: {}", err_msg);
}

#[test]
fn test_run_dry_run_skips_rootfs_validation() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    // Do NOT create /tmp or /bin/sh - this would fail without dry_run

    let task = ShellTask::new(ScriptSource::Content("echo test".to_string()));

    let context = MockContext::new_dry_run(&rootfs);
    let result = task.execute(&context, None);

    assert!(result.is_ok(), "dry_run should skip validation, got: {:?}", result);

    let commands = context.executed_commands();
    assert_eq!(commands.len(), 1, "Expected exactly one command executed");
    assert_eq!(commands[0][0], "/bin/sh");
}

#[test]
fn test_run_with_external_script_dry_run() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    let script_path = temp_dir.path().join("external_script.sh");
    std::fs::write(&script_path, "#!/bin/sh\necho external\n").expect("failed to write script");
    let script_path_utf8 =
        camino::Utf8PathBuf::from_path_buf(script_path).expect("script path should be valid UTF-8");

    let task = ShellTask::new(ScriptSource::Script(script_path_utf8));

    let context = MockContext::new_dry_run(&rootfs);
    let result = task.execute(&context, None);

    assert!(result.is_ok(), "dry_run with external script should succeed, got: {:?}", result);

    let commands = context.executed_commands();
    assert_eq!(commands.len(), 1, "Expected exactly one command executed");
    assert_eq!(commands[0][0], "/bin/sh");
    let script_arg = &commands[0][1];
    assert!(
        script_arg.starts_with("/tmp/task-"),
        "Expected script path in /tmp, got: {}",
        script_arg
    );
}

#[test]
fn test_run_fails_when_context_execute_errors() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_valid_rootfs(&temp_dir);

    let task = ShellTask::new(ScriptSource::Content("echo test".to_string()));

    let context = MockContext::with_error(&rootfs, "connection to isolation backend lost");
    let result = task.execute(&context, None);

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("connection to isolation backend lost"),
        "Expected error message to contain 'connection to isolation backend lost', got: {}",
        err_msg
    );
}

#[test]
#[ignore] // Non-root only (fails as root); CI runs it via `task test:non_root`
fn test_run_fails_when_script_copy_fails() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_valid_rootfs(&temp_dir);

    let script_path = temp_dir.path().join("external_script.sh");
    std::fs::write(&script_path, "#!/bin/sh\necho external\n").expect("failed to write script");
    let script_path_utf8 =
        camino::Utf8PathBuf::from_path_buf(script_path).expect("script path should be valid UTF-8");

    // Make the rootfs's /tmp read-only so staging the script fails there
    let tmp_path = temp_dir.path().join("tmp");
    let mut perms = std::fs::metadata(&tmp_path)
        .expect("failed to get tmp metadata")
        .permissions();
    perms.set_mode(0o555);
    std::fs::set_permissions(&tmp_path, perms).expect("failed to set tmp permissions");

    let task = ShellTask::new(ScriptSource::Script(script_path_utf8));

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context, None);

    let mut perms = std::fs::metadata(&tmp_path)
        .expect("failed to get tmp metadata")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&tmp_path, perms).expect("failed to restore tmp permissions");

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("failed to stage script"),
        "Expected 'failed to stage script' in error, got: {}",
        err_msg
    );
}

#[test]
fn test_execute_inline_script_success() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_valid_rootfs(&temp_dir);

    let task = ShellTask::new(ScriptSource::Content("echo hello".to_string()));

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context, None);

    assert!(result.is_ok(), "non-dry_run inline script should succeed, got: {:?}", result);

    let commands = context.executed_commands();
    assert_eq!(commands.len(), 1, "Expected exactly one command executed");
    assert_eq!(commands[0][0], "/bin/sh");
    let script_arg = &commands[0][1];
    assert!(
        script_arg.starts_with("/tmp/task-"),
        "Expected script path in /tmp, got: {}",
        script_arg
    );

    // Verify the script file was cleaned up by TempFileGuard (RAII)
    let tmp_dir = temp_dir.path().join("tmp");
    let remaining_scripts: Vec<_> = std::fs::read_dir(&tmp_dir)
        .expect("failed to read tmp dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_str().unwrap().starts_with("task-"))
        .collect();
    assert!(
        remaining_scripts.is_empty(),
        "Expected script to be cleaned up, but found: {:?}",
        remaining_scripts
            .iter()
            .map(|e| e.file_name())
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_execute_external_script_success() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_valid_rootfs(&temp_dir);

    let script_path = temp_dir.path().join("external_script.sh");
    std::fs::write(&script_path, "#!/bin/sh\necho external\n").expect("failed to write script");
    let script_path_utf8 =
        camino::Utf8PathBuf::from_path_buf(script_path).expect("script path should be valid UTF-8");

    let task = ShellTask::new(ScriptSource::Script(script_path_utf8));

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context, None);

    assert!(result.is_ok(), "non-dry_run external script should succeed, got: {:?}", result);

    let commands = context.executed_commands();
    assert_eq!(commands.len(), 1, "Expected exactly one command executed");
    assert_eq!(commands[0][0], "/bin/sh");
    let script_arg = &commands[0][1];
    assert!(
        script_arg.starts_with("/tmp/task-"),
        "Expected script path in /tmp, got: {}",
        script_arg
    );

    // Verify the script file was cleaned up by TempFileGuard (RAII)
    let tmp_dir = temp_dir.path().join("tmp");
    let remaining_scripts: Vec<_> = std::fs::read_dir(&tmp_dir)
        .expect("failed to read tmp dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_str().unwrap().starts_with("task-"))
        .collect();
    assert!(
        remaining_scripts.is_empty(),
        "Expected script to be cleaned up, but found: {:?}",
        remaining_scripts
            .iter()
            .map(|e| e.file_name())
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_execute_inline_script_verifies_file_written() {
    use std::sync::Arc;
    use std::sync::Mutex;

    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_valid_rootfs(&temp_dir);

    let script_content = "#!/bin/sh\necho hello world\n";
    let task = ShellTask::new(ScriptSource::Content(script_content.to_string()));

    let captured_content: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured_clone = Arc::clone(&captured_content);

    struct CapturingContext {
        rootfs: camino::Utf8PathBuf,
        // These tests capture the script content the task hands to the shell,
        // so no rootfs mutation is exercised.
        ops: rsdebstrap::rootfs::LocalRootfsOps,
        captured_content: Arc<Mutex<Option<String>>>,
        executed_commands: RefCell<Vec<Vec<String>>>,
    }

    impl rsdebstrap::isolation::RootfsContext for CapturingContext {
        fn rootfs_ops(&self) -> &dyn rsdebstrap::rootfs::RootfsOps {
            &self.ops
        }

        fn rootfs(&self) -> &Utf8Path {
            &self.rootfs
        }
        fn dry_run(&self) -> bool {
            false
        }
    }

    impl IsolationContext for CapturingContext {
        fn name(&self) -> &'static str {
            "capturing-mock"
        }
        fn execute(
            &self,
            command: &[String],
            _privilege: Option<rsdebstrap::privilege::PrivilegeMethod>,
        ) -> Result<ExecutionResult> {
            self.executed_commands.borrow_mut().push(command.to_vec());
            if command.len() >= 2 {
                let script_path_in_isolation = &command[1];
                let script_path_on_host = self
                    .rootfs
                    .join(script_path_in_isolation.trim_start_matches('/'));
                if let Ok(content) = std::fs::read_to_string(&script_path_on_host) {
                    *self.captured_content.lock().unwrap() = Some(content);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(metadata) = std::fs::metadata(&script_path_on_host) {
                        let mode = metadata.permissions().mode();
                        assert_eq!(mode & 0o700, 0o700, "Script should be executable");
                    }
                }
            }
            Ok(ExecutionResult {
                status: Some(ExitStatus::from_raw(0)),
            })
        }
        fn teardown(&mut self) -> Result<()> {
            Ok(())
        }
    }

    let context = CapturingContext {
        rootfs: rootfs.clone(),
        ops: rsdebstrap::rootfs::LocalRootfsOps::open(&rootfs).expect("rootfs should open"),
        captured_content: captured_clone,
        executed_commands: RefCell::new(Vec::new()),
    };

    let result = task.execute(&context, None);
    assert!(result.is_ok(), "execute should succeed, got: {:?}", result);

    let captured = captured_content.lock().unwrap();
    assert_eq!(
        captured.as_deref(),
        Some(script_content),
        "Script content should match the inline content"
    );
}

#[test]
fn test_execute_external_script_verifies_file_copied() {
    use std::sync::Arc;
    use std::sync::Mutex;

    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_valid_rootfs(&temp_dir);

    let original_content = "#!/bin/sh\necho copied script\n";
    let script_path = temp_dir.path().join("my_script.sh");
    std::fs::write(&script_path, original_content).expect("failed to write script");
    let script_path_utf8 =
        camino::Utf8PathBuf::from_path_buf(script_path).expect("script path should be valid UTF-8");

    let task = ShellTask::new(ScriptSource::Script(script_path_utf8));

    let captured_content: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured_clone = Arc::clone(&captured_content);

    struct CapturingContext {
        rootfs: camino::Utf8PathBuf,
        // These tests capture the script content the task hands to the shell,
        // so no rootfs mutation is exercised.
        ops: rsdebstrap::rootfs::LocalRootfsOps,
        captured_content: Arc<Mutex<Option<String>>>,
        executed_commands: RefCell<Vec<Vec<String>>>,
    }

    impl rsdebstrap::isolation::RootfsContext for CapturingContext {
        fn rootfs_ops(&self) -> &dyn rsdebstrap::rootfs::RootfsOps {
            &self.ops
        }

        fn rootfs(&self) -> &Utf8Path {
            &self.rootfs
        }
        fn dry_run(&self) -> bool {
            false
        }
    }

    impl IsolationContext for CapturingContext {
        fn name(&self) -> &'static str {
            "capturing-mock"
        }
        fn execute(
            &self,
            command: &[String],
            _privilege: Option<rsdebstrap::privilege::PrivilegeMethod>,
        ) -> Result<ExecutionResult> {
            self.executed_commands.borrow_mut().push(command.to_vec());
            if command.len() >= 2 {
                let script_path_in_isolation = &command[1];
                let script_path_on_host = self
                    .rootfs
                    .join(script_path_in_isolation.trim_start_matches('/'));
                if let Ok(content) = std::fs::read_to_string(&script_path_on_host) {
                    *self.captured_content.lock().unwrap() = Some(content);
                }
            }
            Ok(ExecutionResult {
                status: Some(ExitStatus::from_raw(0)),
            })
        }
        fn teardown(&mut self) -> Result<()> {
            Ok(())
        }
    }

    let context = CapturingContext {
        rootfs: rootfs.clone(),
        ops: rsdebstrap::rootfs::LocalRootfsOps::open(&rootfs).expect("rootfs should open"),
        captured_content: captured_clone,
        executed_commands: RefCell::new(Vec::new()),
    };

    let result = task.execute(&context, None);
    assert!(result.is_ok(), "execute should succeed, got: {:?}", result);

    let captured = captured_content.lock().unwrap();
    assert_eq!(
        captured.as_deref(),
        Some(original_content),
        "Copied script content should match the original"
    );
}

#[test]
fn test_execute_with_custom_shell() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    std::fs::create_dir(temp_dir.path().join("tmp")).expect("failed to create tmp dir");
    std::fs::create_dir_all(temp_dir.path().join("bin")).expect("failed to create bin dir");
    std::fs::write(temp_dir.path().join("bin/bash"), "#!/bin/bash\n")
        .expect("failed to write /bin/bash");

    let task =
        ShellTask::with_shell(ScriptSource::Content("echo custom shell".to_string()), "/bin/bash");

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context, None);

    assert!(result.is_ok(), "execute with custom shell should succeed, got: {:?}", result);

    let commands = context.executed_commands();
    assert_eq!(commands.len(), 1, "Expected exactly one command executed");
    assert_eq!(
        commands[0][0], "/bin/bash",
        "Expected custom shell /bin/bash, got: {:?}",
        commands[0][0]
    );
    let script_arg = &commands[0][1];
    assert!(
        script_arg.starts_with("/tmp/task-"),
        "Expected script path in /tmp, got: {}",
        script_arg
    );
}

#[test]
fn test_execute_with_no_exit_status_returns_error() {
    // When a process returns no exit status in non-dry-run mode (e.g., killed by signal),
    // this should be treated as an error rather than silently succeeding.
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_valid_rootfs(&temp_dir);

    let task = ShellTask::new(ScriptSource::Content("echo test".to_string()));

    let context = MockContext::with_no_status(&rootfs);
    let result = task.execute(&context, None);

    assert!(result.is_err(), "status: None should be treated as error");
    let anyhow_err = result.unwrap_err();
    let downcast = anyhow_err.downcast_ref::<RsdebstrapError>();
    assert!(
        downcast.is_some(),
        "Expected RsdebstrapError in error chain, got: {:#}",
        anyhow_err,
    );
    assert!(
        matches!(downcast.unwrap(), RsdebstrapError::Execution { .. }),
        "Expected RsdebstrapError::Execution, got: {:?}",
        downcast.unwrap(),
    );
    let err_msg = format!("{}", anyhow_err);
    assert!(
        err_msg.contains("process exited without status"),
        "Expected 'process exited without status' in error, got: {}",
        err_msg,
    );
}

#[test]
fn test_execute_nonzero_exit_returns_execution_error() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_valid_rootfs(&temp_dir);

    let task = ShellTask::new(ScriptSource::Content("exit 1".to_string()));
    let context = MockContext::with_failure(&rootfs, 1);
    let result = task.execute(&context, None);

    assert!(result.is_err());
    let anyhow_err = result.unwrap_err();
    let downcast = anyhow_err.downcast_ref::<RsdebstrapError>();
    assert!(
        downcast.is_some(),
        "Expected RsdebstrapError in error chain, got: {:#}",
        anyhow_err,
    );
    assert!(
        matches!(downcast.unwrap(), RsdebstrapError::Execution { .. }),
        "Expected RsdebstrapError::Execution, got: {:?}",
        downcast.unwrap(),
    );
    if let RsdebstrapError::Execution { command, status } = downcast.unwrap() {
        assert!(
            command.contains("isolation: mock"),
            "Expected command to contain isolation backend name, got: {}",
            command,
        );
        assert!(
            status.contains("status: 1"),
            "Expected status to contain exit code, got: {}",
            status,
        );
    }
}

// `validate()` rejects a symlinked script, but execution re-reads the path later. If the
// name is repointed in between, the read must fail rather than follow it: the check and the
// use have to land on the same inode.
#[test]
fn execute_refuses_a_script_that_became_a_symlink_after_validation() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap();
    setup_valid_rootfs(&temp_dir);

    let work = tempdir().expect("failed to create work dir");
    let script = camino::Utf8PathBuf::from_path_buf(work.path().join("task.sh")).unwrap();
    std::fs::write(&script, "echo benign\n").unwrap();
    let elsewhere = work.path().join("attacker-target");
    std::fs::write(&elsewhere, "echo malicious\n").unwrap();

    let task = ShellTask::new(ScriptSource::Script(script.clone()));
    task.validate().expect("a regular file passes validation");

    std::fs::remove_file(&script).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &script).unwrap();

    let context = MockContext::new(&rootfs);
    let err = task
        .execute(&context, None)
        .expect_err("the repointed script must be refused");
    assert!(format!("{err:#}").contains("is a symlink"), "unexpected error: {err:#}");
}
