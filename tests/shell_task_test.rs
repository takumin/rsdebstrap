//! Security validation tests for ShellTask.

mod helpers;

use std::cell::RefCell;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use anyhow::Result;
use camino::Utf8Path;
use rsdebstrap::RsdebstrapError;
use rsdebstrap::config::IsolationConfig;
use rsdebstrap::executor::ExecutionResult;
use rsdebstrap::isolation::IsolationContext;
use rsdebstrap::task::{ScriptSource, ShellTask};
use tempfile::tempdir;

use crate::helpers::MockContext;

/// Helper to set up a valid rootfs with /tmp and /bin/sh
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
    let result = task.execute(&context);

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
    let result = task.execute(&context);

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
    let result = task.execute(&context);

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
    let result = task.execute(&context);

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
    let result = task.execute(&context);

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
    let result = task.execute(&context);

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(err_msg.contains("directory"), "Expected 'directory' in error, got: {}", err_msg);
}

#[test]
fn test_run_fails_when_script_execution_fails() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_valid_rootfs(&temp_dir);

    let mut task = ShellTask::new(ScriptSource::Content("exit 1".to_string()));
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

    let context = MockContext::with_failure(&rootfs, 1);
    let result = task.execute(&context);

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("failed") && err_msg.contains("status: 1"),
        "Expected failure message with status 1, got: {}",
        err_msg
    );
}

#[test]
fn test_run_dry_run_skips_rootfs_validation() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    // Do NOT create /tmp or /bin/sh - this would fail without dry_run

    let mut task = ShellTask::new(ScriptSource::Content("echo test".to_string()));
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

    let context = MockContext::new_dry_run(&rootfs);
    let result = task.execute(&context);

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

    let mut task = ShellTask::new(ScriptSource::Script(script_path_utf8));
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

    let context = MockContext::new_dry_run(&rootfs);
    let result = task.execute(&context);

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
fn test_shell_task_accessors() {
    let task = ShellTask::with_shell(ScriptSource::Content("echo test".to_string()), "/bin/bash");

    assert_eq!(task.shell(), "/bin/bash");
    assert_eq!(*task.source(), ScriptSource::Content("echo test".to_string()));
    assert_eq!(task.name(), "<inline>");
    assert_eq!(task.script_path(), None);
}

#[test]
fn test_shell_task_accessors_with_script() {
    let task = ShellTask::new(ScriptSource::Script("/path/to/script.sh".into()));

    assert_eq!(task.shell(), "/bin/sh");
    assert_eq!(*task.source(), ScriptSource::Script("/path/to/script.sh".into()));
    assert_eq!(task.name(), "/path/to/script.sh");
    assert_eq!(task.script_path(), Some(camino::Utf8Path::new("/path/to/script.sh")));
}

#[test]
fn test_run_fails_when_context_execute_errors() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_valid_rootfs(&temp_dir);

    let mut task = ShellTask::new(ScriptSource::Content("echo test".to_string()));
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

    let context = MockContext::with_error(&rootfs, "connection to isolation backend lost");
    let result = task.execute(&context);

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("connection to isolation backend lost"),
        "Expected error message to contain 'connection to isolation backend lost', got: {}",
        err_msg
    );
}

#[test]
#[ignore] // Skip in CI: requires file permission checks (fails as root)
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

    // Make /tmp read-only to cause copy failure
    let tmp_path = temp_dir.path().join("tmp");
    let mut perms = std::fs::metadata(&tmp_path)
        .expect("failed to get tmp metadata")
        .permissions();
    perms.set_mode(0o555);
    std::fs::set_permissions(&tmp_path, perms).expect("failed to set tmp permissions");

    let mut task = ShellTask::new(ScriptSource::Script(script_path_utf8));
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context);

    // Restore permissions for cleanup
    let mut perms = std::fs::metadata(&tmp_path)
        .expect("failed to get tmp metadata")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&tmp_path, perms).expect("failed to restore tmp permissions");

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("failed to copy script"),
        "Expected 'failed to copy script' in error, got: {}",
        err_msg
    );
}

#[test]
fn test_execute_inline_script_success() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_valid_rootfs(&temp_dir);

    let mut task = ShellTask::new(ScriptSource::Content("echo hello".to_string()));
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context);

    assert!(result.is_ok(), "non-dry_run inline script should succeed, got: {:?}", result);

    // Verify the correct command was executed
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

    // Create an external script file
    let script_path = temp_dir.path().join("external_script.sh");
    std::fs::write(&script_path, "#!/bin/sh\necho external\n").expect("failed to write script");
    let script_path_utf8 =
        camino::Utf8PathBuf::from_path_buf(script_path).expect("script path should be valid UTF-8");

    let mut task = ShellTask::new(ScriptSource::Script(script_path_utf8));
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context);

    assert!(result.is_ok(), "non-dry_run external script should succeed, got: {:?}", result);

    // Verify the correct command was executed
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
    let mut task = ShellTask::new(ScriptSource::Content(script_content.to_string()));
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

    // Use a custom mock that captures the script content at execution time
    let captured_content: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured_clone = Arc::clone(&captured_content);

    struct CapturingContext {
        rootfs: camino::Utf8PathBuf,
        captured_content: Arc<Mutex<Option<String>>>,
        executed_commands: RefCell<Vec<Vec<String>>>,
    }

    impl IsolationContext for CapturingContext {
        fn name(&self) -> &'static str {
            "capturing-mock"
        }
        fn rootfs(&self) -> &Utf8Path {
            &self.rootfs
        }
        fn dry_run(&self) -> bool {
            false
        }
        fn execute(
            &self,
            command: &[String],
            _privilege: Option<rsdebstrap::privilege::PrivilegeMethod>,
        ) -> Result<ExecutionResult> {
            self.executed_commands.borrow_mut().push(command.to_vec());
            // Read the script file that was written to rootfs
            if command.len() >= 2 {
                let script_path_in_isolation = &command[1];
                let script_path_on_host = self
                    .rootfs
                    .join(script_path_in_isolation.trim_start_matches('/'));
                if let Ok(content) = std::fs::read_to_string(&script_path_on_host) {
                    *self.captured_content.lock().unwrap() = Some(content);
                }
                // Verify the script is executable
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
        captured_content: captured_clone,
        executed_commands: RefCell::new(Vec::new()),
    };

    let result = task.execute(&context);
    assert!(result.is_ok(), "execute should succeed, got: {:?}", result);

    // Verify the inline content was written correctly
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

    let mut task = ShellTask::new(ScriptSource::Script(script_path_utf8));
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

    let captured_content: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured_clone = Arc::clone(&captured_content);

    struct CapturingContext {
        rootfs: camino::Utf8PathBuf,
        captured_content: Arc<Mutex<Option<String>>>,
        executed_commands: RefCell<Vec<Vec<String>>>,
    }

    impl IsolationContext for CapturingContext {
        fn name(&self) -> &'static str {
            "capturing-mock"
        }
        fn rootfs(&self) -> &Utf8Path {
            &self.rootfs
        }
        fn dry_run(&self) -> bool {
            false
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
        captured_content: captured_clone,
        executed_commands: RefCell::new(Vec::new()),
    };

    let result = task.execute(&context);
    assert!(result.is_ok(), "execute should succeed, got: {:?}", result);

    // Verify the external script was copied correctly
    let captured = captured_content.lock().unwrap();
    assert_eq!(
        captured.as_deref(),
        Some(original_content),
        "Copied script content should match the original"
    );
}

#[test]
fn test_validate_script_path_traversal_rejected() {
    let task = ShellTask::new(ScriptSource::Script("../../../etc/passwd".into()));
    let result = task.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains(".."), "Expected '..' in error message, got: {}", err_msg);
    assert!(
        err_msg.contains("security"),
        "Expected 'security' in error message, got: {}",
        err_msg
    );
}

#[test]
fn test_execute_with_custom_shell() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    // Setup rootfs with /tmp and custom shell /bin/bash
    std::fs::create_dir(temp_dir.path().join("tmp")).expect("failed to create tmp dir");
    std::fs::create_dir_all(temp_dir.path().join("bin")).expect("failed to create bin dir");
    std::fs::write(temp_dir.path().join("bin/bash"), "#!/bin/bash\n")
        .expect("failed to write /bin/bash");

    let mut task =
        ShellTask::with_shell(ScriptSource::Content("echo custom shell".to_string()), "/bin/bash");
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context);

    assert!(result.is_ok(), "execute with custom shell should succeed, got: {:?}", result);

    // Verify the custom shell was used in the command
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

    let mut task = ShellTask::new(ScriptSource::Content("echo test".to_string()));
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

    let context = MockContext::with_no_status(&rootfs);
    let result = task.execute(&context);

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

// =============================================================================
// Type-based error tests (RsdebstrapError variant matching)
// =============================================================================

#[test]
fn test_execute_nonzero_exit_returns_execution_error() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_valid_rootfs(&temp_dir);

    let mut task = ShellTask::new(ScriptSource::Content("exit 1".to_string()));
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());
    let context = MockContext::with_failure(&rootfs, 1);
    let result = task.execute(&context);

    assert!(result.is_err());
    // The error is wrapped in anyhow, so we need to downcast
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
    // Verify the command field contains isolation backend info
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
