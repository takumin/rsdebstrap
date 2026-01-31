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
fn large_output_preserves_most_recent_data() {
    let executor = RealCommandExecutor { dry_run: false };
    // Generate output larger than the 64KB limit with a distinctive ending.
    // The ring buffer should discard old data and keep the most recent output.
    // We generate ~100KB of data followed by a unique marker at the end.
    let output_size = MAX_OUTPUT_SIZE + (MAX_OUTPUT_SIZE / 2); // ~100KB
    let spec = CommandSpec::new(
        "sh",
        vec![
            OsString::from("-c"),
            OsString::from(format!(
                "yes 'line' | head -c {} && echo 'END_MARKER_12345'",
                output_size
            )),
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
    // The ring buffer should preserve the most recent data (the end marker)
    let stdout_text = String::from_utf8_lossy(&result.stdout);
    assert!(
        stdout_text.contains("END_MARKER_12345"),
        "stdout should contain the end marker (most recent data), got: ...{}",
        &stdout_text[stdout_text.len().saturating_sub(100)..]
    );
}

#[test]
fn ring_buffer_preserves_final_error_message() {
    let executor = RealCommandExecutor { dry_run: false };
    // Simulate a command that outputs a lot of data followed by an error message.
    // This is the key use case: we want to preserve the final error message.
    let output_size = MAX_OUTPUT_SIZE + 10000; // Exceed limit
    let spec = CommandSpec::new(
        "sh",
        vec![
            OsString::from("-c"),
            OsString::from(format!(
                "seq 1 {} && echo 'FATAL ERROR: Something went wrong!'",
                output_size / 10 // ~10000 numbers, each ~6 bytes = ~60KB + marker
            )),
        ],
    );

    let result = executor.execute(&spec).expect("command should succeed");

    assert!(result.success(), "command should succeed");
    let stdout_text = String::from_utf8_lossy(&result.stdout);
    assert!(
        stdout_text.contains("FATAL ERROR: Something went wrong!"),
        "stdout should contain the final error message"
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
fn empty_stdout_stderr_handled() {
    let executor = RealCommandExecutor { dry_run: false };
    // 'true' command produces no output and exits successfully
    let spec = CommandSpec::new("true", Vec::new());

    let result = executor.execute(&spec).expect("command should succeed");

    assert!(result.success(), "true command should succeed");
    assert!(result.stdout.is_empty(), "stdout should be empty");
    assert!(result.stderr.is_empty(), "stderr should be empty");
}

#[test]
fn crlf_line_endings_handled_correctly() {
    let executor = RealCommandExecutor { dry_run: false };
    // Generate output with CRLF line endings (Windows-style)
    let spec = CommandSpec::new(
        "sh",
        vec![
            OsString::from("-c"),
            OsString::from(r"printf 'line1\r\nline2\r\n'"),
        ],
    );

    let result = executor.execute(&spec).expect("command should succeed");

    assert!(result.success(), "command should succeed");
    // The raw bytes should preserve CRLF
    assert_eq!(result.stdout, b"line1\r\nline2\r\n", "stdout should preserve CRLF line endings");
}

#[test]
fn mixed_line_endings_lf_crlf_cr() {
    let executor = RealCommandExecutor { dry_run: false };
    // Generate output with mixed line endings: LF, CRLF, and standalone CR
    let spec = CommandSpec::new(
        "sh",
        vec![
            OsString::from("-c"),
            OsString::from(r"printf 'lf_line\ncrlf_line\r\ncr_line\rend\n'"),
        ],
    );

    let result = executor.execute(&spec).expect("command should succeed");

    assert!(result.success(), "command should succeed");
    // Verify raw bytes contain all line ending styles
    let stdout_text = String::from_utf8_lossy(&result.stdout);
    assert!(stdout_text.contains("lf_line\n"), "should contain LF line ending");
    assert!(stdout_text.contains("crlf_line\r\n"), "should contain CRLF line ending");
    assert!(stdout_text.contains("cr_line\r"), "should contain CR (standalone)");
}

#[test]
fn multibyte_utf8_characters_captured_correctly() {
    let executor = RealCommandExecutor { dry_run: false };
    // Generate output with various UTF-8 multibyte characters
    let spec = CommandSpec::new(
        "sh",
        vec![
            OsString::from("-c"),
            OsString::from(r"printf '日本語\némoji: 🎉\n中文字符\n'"),
        ],
    );

    let result = executor.execute(&spec).expect("command should succeed");

    assert!(result.success(), "command should succeed");
    let stdout_text = String::from_utf8_lossy(&result.stdout);
    assert!(stdout_text.contains("日本語"), "should contain Japanese characters");
    assert!(stdout_text.contains("🎉"), "should contain emoji");
    assert!(stdout_text.contains("中文字符"), "should contain Chinese characters");
}
