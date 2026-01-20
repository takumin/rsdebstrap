use rsdebstrap::executor::{CommandExecutor, CommandSpec, RealCommandExecutor};
use std::ffi::OsString;

#[test]
fn dry_run_skips_command_lookup() {
    let executor = RealCommandExecutor { dry_run: true };
    let spec = CommandSpec::new("definitely-not-a-command", Vec::new());

    let result = executor
        .execute(&spec)
        .expect("dry run should not require command to exist");
    assert!(result.status.is_none(), "dry run result should not have an exit status");
}

#[test]
fn non_dry_run_fails_for_nonexistent_command() {
    let executor = RealCommandExecutor { dry_run: false };
    let spec = CommandSpec::new("this-command-should-not-exist", Vec::new());

    let result = executor.execute(&spec);

    assert!(result.is_err());
    if let Err(e) = result {
        assert!(e.to_string().contains("command not found"));
    }
}

#[test]
fn successful_command_captures_stdout() {
    let executor = RealCommandExecutor { dry_run: false };
    let spec = CommandSpec::new("echo", vec![OsString::from("hello world")]);

    let result = executor
        .execute(&spec)
        .expect("echo command should succeed");

    assert!(result.success(), "echo command should return success");
    let stdout_text = String::from_utf8_lossy(&result.stdout);
    assert!(stdout_text.contains("hello world"), "stdout should contain the echoed text");
}

#[test]
fn failed_command_captures_stderr() {
    let executor = RealCommandExecutor { dry_run: false };
    // ls with a non-existent file should fail and write to stderr
    let spec = CommandSpec::new("ls", vec![OsString::from("/this/path/definitely/does/not/exist")]);

    let result = executor
        .execute(&spec)
        .expect("executor should return Ok even when command fails");

    assert!(!result.success(), "ls on non-existent path should fail");
    assert!(!result.stderr.is_empty(), "stderr should contain error output");
    let stderr_text = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr_text.contains("No such file or directory") || stderr_text.contains("cannot access"),
        "stderr should contain error details: {}",
        stderr_text
    );
}

#[test]
fn command_with_stderr_output() {
    let executor = RealCommandExecutor { dry_run: false };
    // Using 'sh -c' to run a command that writes to stderr and exits with error
    let spec = CommandSpec::new(
        "sh",
        vec![
            OsString::from("-c"),
            OsString::from("echo 'error message' >&2 && exit 1"),
        ],
    );

    let result = executor
        .execute(&spec)
        .expect("executor should return Ok even when command fails");

    assert!(!result.success(), "command with exit 1 should fail");
    assert!(!result.stderr.is_empty(), "stderr should contain error output");
    let stderr_text = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr_text.contains("error message"),
        "stderr should include error message: {}",
        stderr_text
    );
}
