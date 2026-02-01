//! Security validation tests for ShellRunner.

use std::cell::RefCell;
use std::ffi::OsString;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use anyhow::Result;
use camino::Utf8Path;
use rsdebstrap::executor::ExecutionResult;
use rsdebstrap::isolation::IsolationContext;
use rsdebstrap::runner::{ScriptSource, ShellRunner};
use tempfile::tempdir;

/// Mock isolation context for testing.
struct MockContext {
    rootfs: camino::Utf8PathBuf,
    /// Whether the execute call should fail with a non-zero exit code
    should_fail: bool,
    /// Exit code to return when executing (ignored if should_fail is false)
    exit_code: Option<i32>,
    /// Whether execute() should return an Err (simulates execution errors)
    should_error: bool,
    /// Error message to return when should_error is true
    error_message: Option<String>,
    /// Recorded commands that were executed
    executed_commands: RefCell<Vec<Vec<OsString>>>,
}

impl MockContext {
    fn new(rootfs: &Utf8Path) -> Self {
        Self {
            rootfs: rootfs.to_owned(),
            should_fail: false,
            exit_code: None,
            should_error: false,
            error_message: None,
            executed_commands: RefCell::new(Vec::new()),
        }
    }

    fn with_failure(rootfs: &Utf8Path, exit_code: i32) -> Self {
        Self {
            rootfs: rootfs.to_owned(),
            should_fail: true,
            exit_code: Some(exit_code),
            should_error: false,
            error_message: None,
            executed_commands: RefCell::new(Vec::new()),
        }
    }

    fn with_error(rootfs: &Utf8Path, message: &str) -> Self {
        Self {
            rootfs: rootfs.to_owned(),
            should_fail: false,
            exit_code: None,
            should_error: true,
            error_message: Some(message.to_string()),
            executed_commands: RefCell::new(Vec::new()),
        }
    }

    fn executed_commands(&self) -> Vec<Vec<OsString>> {
        self.executed_commands.borrow().clone()
    }
}

impl IsolationContext for MockContext {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn rootfs(&self) -> &Utf8Path {
        &self.rootfs
    }

    fn execute(&self, command: &[OsString]) -> Result<ExecutionResult> {
        self.executed_commands.borrow_mut().push(command.to_vec());

        // Check if we should return an error
        if self.should_error {
            anyhow::bail!("{}", self.error_message.as_deref().unwrap_or("mock error"));
        }

        if self.should_fail {
            // Create an ExitStatus from the raw exit code
            // On Unix, exit codes are stored as (code << 8) in the raw wait status
            let status = Some(ExitStatus::from_raw(self.exit_code.unwrap_or(1) << 8));
            Ok(ExecutionResult { status })
        } else {
            // Success case: return exit code 0
            Ok(ExecutionResult {
                status: Some(ExitStatus::from_raw(0)),
            })
        }
    }

    fn teardown(&mut self) -> Result<()> {
        Ok(())
    }
}

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

    // Create rootfs without /tmp directory
    // (temp_dir is empty by default)

    let runner = ShellRunner::new(ScriptSource::Content("echo test".to_string()));

    let context = MockContext::new(&rootfs);
    let result = runner.run(&context, false);

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

    // Create /tmp as a symlink (security issue)
    let tmp_path = temp_dir.path().join("tmp");
    let target_path = temp_dir.path().join("somewhere_else");
    std::fs::create_dir(&target_path).expect("failed to create target dir");
    std::os::unix::fs::symlink(&target_path, &tmp_path).expect("failed to create symlink");

    let runner = ShellRunner::new(ScriptSource::Content("echo test".to_string()));

    let context = MockContext::new(&rootfs);
    let result = runner.run(&context, false);

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(err_msg.contains("symlink"), "Expected 'symlink' in error, got: {}", err_msg);
}

#[test]
fn test_run_fails_when_tmp_is_file() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    // Create /tmp as a regular file instead of a directory
    let tmp_path = temp_dir.path().join("tmp");
    std::fs::write(&tmp_path, "not a directory").expect("failed to create tmp file");

    let runner = ShellRunner::new(ScriptSource::Content("echo test".to_string()));

    let context = MockContext::new(&rootfs);
    let result = runner.run(&context, false);

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

    // Create /tmp directory
    std::fs::create_dir(temp_dir.path().join("tmp")).expect("failed to create tmp dir");

    let runner = ShellRunner::with_shell(
        ScriptSource::Content("echo test".to_string()),
        "/bin/../etc/passwd", // Path traversal attempt
    );

    let context = MockContext::new(&rootfs);
    let result = runner.run(&context, false);

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(err_msg.contains(".."), "Expected '..' in error, got: {}", err_msg);
}

#[test]
fn test_run_fails_when_shell_not_exists() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    // Create /tmp directory but not /bin/sh
    std::fs::create_dir(temp_dir.path().join("tmp")).expect("failed to create tmp dir");

    let runner = ShellRunner::new(ScriptSource::Content("echo test".to_string()));

    let context = MockContext::new(&rootfs);
    let result = runner.run(&context, false);

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

    // Create /tmp and /bin/sh as a directory (not a file)
    std::fs::create_dir(temp_dir.path().join("tmp")).expect("failed to create tmp dir");
    std::fs::create_dir_all(temp_dir.path().join("bin/sh")).expect("failed to create bin/sh dir");

    let runner = ShellRunner::new(ScriptSource::Content("echo test".to_string()));

    let context = MockContext::new(&rootfs);
    let result = runner.run(&context, false);

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

    let runner = ShellRunner::new(ScriptSource::Content("exit 1".to_string()));

    // Use MockContext that returns failure
    let context = MockContext::with_failure(&rootfs, 1);
    let result = runner.run(&context, false);

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

    let runner = ShellRunner::new(ScriptSource::Content("echo test".to_string()));

    let context = MockContext::new(&rootfs);
    // dry_run=true should skip validation and succeed
    let result = runner.run(&context, true);

    assert!(result.is_ok(), "dry_run should skip validation, got: {:?}", result);

    // Verify that execute was still called
    let commands = context.executed_commands();
    assert_eq!(commands.len(), 1, "Expected exactly one command executed");
    assert_eq!(commands[0][0], OsString::from("/bin/sh"));
}

#[test]
fn test_run_with_external_script_dry_run() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    // Create external script file
    let script_path = temp_dir.path().join("external_script.sh");
    std::fs::write(&script_path, "#!/bin/sh\necho external\n").expect("failed to write script");
    let script_path_utf8 =
        camino::Utf8PathBuf::from_path_buf(script_path).expect("script path should be valid UTF-8");

    let runner = ShellRunner::new(ScriptSource::Script(script_path_utf8));

    let context = MockContext::new(&rootfs);
    // dry_run=true should work without fully set up rootfs
    let result = runner.run(&context, true);

    assert!(result.is_ok(), "dry_run with external script should succeed, got: {:?}", result);

    // Verify that execute was called with proper arguments
    let commands = context.executed_commands();
    assert_eq!(commands.len(), 1, "Expected exactly one command executed");
    // First arg should be shell, second should be the script path in /tmp
    assert_eq!(commands[0][0], OsString::from("/bin/sh"));
    let script_arg = commands[0][1].to_string_lossy();
    assert!(
        script_arg.starts_with("/tmp/provision-"),
        "Expected script path in /tmp, got: {}",
        script_arg
    );
}

#[test]
fn test_shell_runner_accessors() {
    let runner =
        ShellRunner::with_shell(ScriptSource::Content("echo test".to_string()), "/bin/bash");

    assert_eq!(runner.shell(), "/bin/bash");
    assert_eq!(*runner.source(), ScriptSource::Content("echo test".to_string()));
    assert_eq!(runner.script_source(), "<inline>");
    assert_eq!(runner.script_path(), None);
}

#[test]
fn test_shell_runner_accessors_with_script() {
    let runner = ShellRunner::new(ScriptSource::Script("/path/to/script.sh".into()));

    assert_eq!(runner.shell(), "/bin/sh");
    assert_eq!(*runner.source(), ScriptSource::Script("/path/to/script.sh".into()));
    assert_eq!(runner.script_source(), "/path/to/script.sh");
    assert_eq!(runner.script_path(), Some(&camino::Utf8PathBuf::from("/path/to/script.sh")));
}

#[test]
fn test_run_fails_when_context_execute_errors() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_valid_rootfs(&temp_dir);

    let runner = ShellRunner::new(ScriptSource::Content("echo test".to_string()));

    // Use MockContext that returns an error from execute()
    let context = MockContext::with_error(&rootfs, "connection to isolation backend lost");
    let result = runner.run(&context, false);

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("connection to isolation backend lost"),
        "Expected error message to contain 'connection to isolation backend lost', got: {}",
        err_msg
    );
}

#[test]
fn test_run_fails_when_script_copy_fails() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_valid_rootfs(&temp_dir);

    // Create external script file
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

    let runner = ShellRunner::new(ScriptSource::Script(script_path_utf8));

    let context = MockContext::new(&rootfs);
    let result = runner.run(&context, false);

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
fn test_validate_script_path_traversal_rejected() {
    let runner = ShellRunner::new(ScriptSource::Script("../../../etc/passwd".into()));
    let result = runner.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains(".."), "Expected '..' in error message, got: {}", err_msg);
    assert!(
        err_msg.contains("security"),
        "Expected 'security' in error message, got: {}",
        err_msg
    );
}
