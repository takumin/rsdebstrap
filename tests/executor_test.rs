use rsdebstrap::executor::{
    CommandExecutor, CommandSpec, MAX_LINE_SIZE, MAX_OUTPUT_SIZE, RealCommandExecutor,
};
use std::ffi::OsString;

/// Test line length that exceeds MAX_LINE_SIZE (8000 > 4096).
/// Used to verify single long lines are truncated correctly.
const LONG_LINE_TEST_LENGTH: usize = 8000;

/// Test line length for multiple long lines (6000 > 4096).
/// Each line exceeds MAX_LINE_SIZE to verify independent truncation.
const MULTI_LINE_TEST_LENGTH: usize = 6000;

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
    // Generate output larger than the 64KB limit.
    // Using 'yes' with 'head -c' to generate text output with newlines,
    // which is more appropriate for testing line-based reading.
    // We generate 100KB (about 1.5x the limit) to ensure truncation occurs.
    let output_size = MAX_OUTPUT_SIZE + (MAX_OUTPUT_SIZE / 2); // ~100KB
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
        "stdout should be truncated to max output size ({} bytes), got {} bytes",
        MAX_OUTPUT_SIZE,
        result.stdout.len()
    );
    // Output should be substantial (at least half of max size)
    // since we're generating ~100KB and the limit is 64KB
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
fn binary_data_mixed_with_text_is_captured() {
    let executor = RealCommandExecutor { dry_run: false };
    // Generate output with valid text followed by invalid UTF-8 bytes.
    // The implementation reads bytes and uses lossy UTF-8 conversion for logging,
    // but preserves the original bytes in the returned buffer.
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
    // All data should be captured, including invalid UTF-8 bytes
    let stdout_text = String::from_utf8_lossy(&result.stdout);
    assert!(
        stdout_text.contains("first line"),
        "stdout should contain the first line: {:?}",
        result.stdout
    );
    assert!(
        stdout_text.contains("after binary"),
        "stdout should contain text after binary data: {:?}",
        result.stdout
    );
}

#[test]
fn long_line_is_truncated_at_max_line_size() {
    let executor = RealCommandExecutor { dry_run: false };
    // Generate a single line longer than 4KB without newline.
    // We generate LONG_LINE_TEST_LENGTH characters (nearly 2x the 4KB limit) to ensure truncation.
    let spec = CommandSpec::new(
        "sh",
        vec![
            OsString::from("-c"),
            // printf with %0*d generates a string of zeros with specified width
            OsString::from(format!("printf '%0*d' {} 0", LONG_LINE_TEST_LENGTH)),
        ],
    );

    let result = executor.execute(&spec).expect("command should succeed");

    assert!(result.success(), "command should succeed");
    // The output should be truncated to MAX_LINE_SIZE (4KB)
    // Since there's no newline, the line is treated as incomplete but still truncated
    assert!(
        result.stdout.len() <= MAX_LINE_SIZE,
        "stdout should be truncated to max line size ({} bytes), got {} bytes",
        MAX_LINE_SIZE,
        result.stdout.len()
    );
    // Output should be exactly MAX_LINE_SIZE since we generated more than that
    assert_eq!(
        result.stdout.len(),
        MAX_LINE_SIZE,
        "stdout should be exactly max line size when truncated"
    );
}

#[test]
fn multiple_long_lines_are_each_truncated() {
    let executor = RealCommandExecutor { dry_run: false };
    // Generate two lines, each longer than 4KB
    let spec = CommandSpec::new(
        "sh",
        vec![
            OsString::from("-c"),
            // Two lines of MULTI_LINE_TEST_LENGTH zeros each
            OsString::from(format!(
                "printf '%0*d\\n%0*d\\n' {} 1 {} 2",
                MULTI_LINE_TEST_LENGTH, MULTI_LINE_TEST_LENGTH
            )),
        ],
    );

    let result = executor.execute(&spec).expect("command should succeed");

    assert!(result.success(), "command should succeed");
    // Each line should be truncated to 4KB, plus newlines
    // Expected: 4KB + newline + 4KB + newline = 8194 bytes
    let expected_max = MAX_LINE_SIZE * 2 + 2; // Two lines + two newlines
    assert_eq!(
        result.stdout.len(),
        expected_max,
        "stdout should be exactly {} bytes (two truncated lines + newlines), got {} bytes",
        expected_max,
        result.stdout.len()
    );
    // The output should contain exactly two newlines (one after each truncated line)
    let newline_count = result.stdout.iter().filter(|&&b| b == b'\n').count();
    assert_eq!(
        newline_count, 2,
        "stdout should contain exactly 2 newlines, got {}",
        newline_count
    );
}
