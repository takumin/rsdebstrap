use rsdebstrap::executor::{CommandExecutor, CommandSpec, MAX_OUTPUT_SIZE, RealCommandExecutor};
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
    assert_eq!(stdout_text.trim(), "hello world", "stdout should match the echoed text");
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
    // Check that stderr contains the path - this is locale-independent
    assert!(
        stderr_text.contains("/this/path/definitely/does/not/exist"),
        "stderr should contain the target path: {}",
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

#[test]
fn large_output_is_truncated_to_max_size() {
    let executor = RealCommandExecutor { dry_run: false };
    // Generate output larger than MAX_OUTPUT_SIZE (64KB)
    // Using 'yes' with 'head -c' to generate text output with newlines,
    // which is more appropriate for testing line-based reading
    let output_size = 100 * 1024; // 100KB, larger than 64KB limit
    let spec = CommandSpec::new(
        "sh",
        vec![
            OsString::from("-c"),
            OsString::from(format!("yes 'line' | head -c {}", output_size)),
        ],
    );

    let result = executor.execute(&spec).expect("command should succeed");

    assert!(result.success(), "command should succeed");
    assert!(
        result.stdout.len() <= MAX_OUTPUT_SIZE,
        "stdout should be truncated to MAX_OUTPUT_SIZE ({} bytes), got {} bytes",
        MAX_OUTPUT_SIZE,
        result.stdout.len()
    );
    // Output should be substantial (at least half of MAX_OUTPUT_SIZE)
    // since we're generating 100KB and the limit is 64KB
    assert!(
        result.stdout.len() >= MAX_OUTPUT_SIZE / 2,
        "stdout should be substantial (at least {} bytes), got {} bytes",
        MAX_OUTPUT_SIZE / 2,
        result.stdout.len()
    );
}

#[test]
fn binary_output_is_captured_correctly() {
    let executor = RealCommandExecutor { dry_run: false };
    // Generate some binary data (null bytes mixed with text)
    // Use sh -c with printf and POSIX octal escape (\000) for portability
    let spec = CommandSpec::new(
        "sh",
        vec![
            OsString::from("-c"),
            OsString::from(r"printf 'hello\000world\n'"),
        ],
    );

    let result = executor.execute(&spec).expect("command should succeed");

    assert!(result.success(), "command should succeed");
    // Verify the binary data is captured correctly
    // Expected: b"hello\x00world\n" (12 bytes)
    assert_eq!(
        result.stdout, b"hello\x00world\n",
        "stdout should contain the exact binary data including null byte"
    );
}

#[test]
fn binary_after_text_triggers_fallback() {
    let executor = RealCommandExecutor { dry_run: false };
    // Generate output with valid text followed by invalid UTF-8 bytes.
    // This tests the fallback path when UTF-8 decoding fails mid-stream.
    // Note: The implementation uses line-based reading first. When a UTF-8 error
    // occurs, the data that triggered the error may be lost (this is a known
    // limitation of BufReader::read_line). However, any data read successfully
    // before the error and any data read after switching to binary mode is preserved.
    let spec = CommandSpec::new(
        "sh",
        vec![
            OsString::from("-c"),
            // Output text line, then invalid UTF-8 bytes, then more text
            OsString::from(
                r"printf 'first line\n' && printf '\200\201' && printf 'after binary\n'",
            ),
        ],
    );

    let result = executor.execute(&spec).expect("command should succeed");

    assert!(result.success(), "command should succeed");
    // The first line is read in text mode, then UTF-8 error triggers binary mode.
    // Due to BufReader::read_line behavior, the invalid bytes that caused the error
    // may be lost, but subsequent binary data should be captured.
    let stdout_text = String::from_utf8_lossy(&result.stdout);
    assert!(
        stdout_text.contains("first line"),
        "stdout should contain the first line: {:?}",
        result.stdout
    );
}
