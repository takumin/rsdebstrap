//! Execution tests for MitamaeTask.

mod helpers;

use rsdebstrap::RsdebstrapError;
use rsdebstrap::config::IsolationConfig;
use rsdebstrap::task::{MitamaeTask, ScriptSource};
use tempfile::tempdir;

use crate::helpers::MockContext;

/// Helper to set up a valid rootfs with /tmp
fn setup_rootfs_with_tmp(temp_dir: &tempfile::TempDir) {
    let rootfs = temp_dir.path();
    std::fs::create_dir(rootfs.join("tmp")).expect("failed to create tmp dir");
}

/// Helper to create a fake mitamae binary in the temp dir
fn create_fake_binary(temp_dir: &tempfile::TempDir) -> camino::Utf8PathBuf {
    let binary_path = temp_dir.path().join("mitamae");
    std::fs::write(&binary_path, "fake mitamae binary").expect("failed to write binary");
    camino::Utf8PathBuf::from_path_buf(binary_path).expect("path should be valid UTF-8")
}

#[test]
fn test_execute_inline_recipe_success() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);

    let mut task = MitamaeTask::new(
        ScriptSource::Content("package 'vim' do\n  action :install\nend\n".to_string()),
        binary,
    );
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context);

    assert!(result.is_ok(), "inline recipe should succeed, got: {:?}", result);

    let commands = context.executed_commands();
    assert_eq!(commands.len(), 1, "Expected exactly one command executed");
    assert_eq!(commands[0].len(), 3, "Expected 3 command elements");

    let binary_arg = &commands[0][0];
    assert!(
        binary_arg.starts_with("/tmp/mitamae-"),
        "Expected binary in /tmp/mitamae-*, got: {}",
        binary_arg
    );
    assert_eq!(commands[0][1], "local");
    let recipe_arg = &commands[0][2];
    assert!(
        recipe_arg.starts_with("/tmp/recipe-") && recipe_arg.ends_with(".rb"),
        "Expected recipe in /tmp/recipe-*.rb, got: {}",
        recipe_arg
    );
}

#[test]
fn test_execute_external_recipe_success() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);

    // Create an external recipe file
    let recipe_path = temp_dir.path().join("default.rb");
    std::fs::write(&recipe_path, "package 'vim'\n").expect("failed to write recipe");
    let recipe_utf8 =
        camino::Utf8PathBuf::from_path_buf(recipe_path).expect("path should be valid UTF-8");

    let mut task = MitamaeTask::new(ScriptSource::Script(recipe_utf8), binary);
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context);

    assert!(result.is_ok(), "external recipe should succeed, got: {:?}", result);

    let commands = context.executed_commands();
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].len(), 3);
    assert_eq!(commands[0][1], "local");
}

#[test]
fn test_execute_dry_run_skips_file_operations() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    // Do NOT create /tmp - dry_run should skip validation
    let mut task = MitamaeTask::new(
        ScriptSource::Content("package 'vim'".to_string()),
        "/usr/local/bin/mitamae".into(),
    );
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

    let context = MockContext::new_dry_run(&rootfs);
    let result = task.execute(&context);

    assert!(result.is_ok(), "dry_run should skip validation, got: {:?}", result);

    let commands = context.executed_commands();
    assert_eq!(commands.len(), 1, "Expected exactly one command executed");
    assert_eq!(commands[0].len(), 3);
    let binary_arg = &commands[0][0];
    assert!(
        binary_arg.starts_with("/tmp/mitamae-"),
        "Expected binary path in /tmp, got: {}",
        binary_arg
    );
    assert_eq!(commands[0][1], "local");
}

#[test]
fn test_execute_failure_returns_error() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);

    let mut task = MitamaeTask::new(ScriptSource::Content("package 'vim'".to_string()), binary);
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

    let context = MockContext::with_failure(&rootfs, 1);
    let result = task.execute(&context);

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
}

#[test]
fn test_execute_command_construction() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);

    let mut task = MitamaeTask::new(ScriptSource::Content("package 'vim'".to_string()), binary);
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

    let context = MockContext::new(&rootfs);
    task.execute(&context).expect("execute should succeed");

    let commands = context.executed_commands();
    assert_eq!(commands.len(), 1);

    // Verify the 3-element command structure: [binary, "local", recipe]
    let cmd = &commands[0];
    assert_eq!(cmd.len(), 3, "Command should have exactly 3 elements");

    let binary_arg = &cmd[0];
    assert!(
        binary_arg.starts_with("/tmp/mitamae-"),
        "First element should be mitamae binary, got: {}",
        binary_arg
    );

    assert_eq!(cmd[1], "local", "Second element should be 'local'");

    let recipe_arg = &cmd[2];
    assert!(
        recipe_arg.starts_with("/tmp/recipe-") && recipe_arg.ends_with(".rb"),
        "Third element should be recipe path, got: {}",
        recipe_arg
    );
}

#[test]
fn test_execute_cleans_up_files() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);

    let mut task = MitamaeTask::new(ScriptSource::Content("package 'vim'".to_string()), binary);
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

    let context = MockContext::new(&rootfs);
    task.execute(&context).expect("execute should succeed");

    // Verify temp files were cleaned up by TempFileGuard (RAII)
    let tmp_dir = temp_dir.path().join("tmp");
    let remaining: Vec<_> = std::fs::read_dir(&tmp_dir)
        .expect("failed to read tmp dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_str().unwrap().to_string();
            name.starts_with("mitamae-") || name.starts_with("recipe-")
        })
        .collect();
    assert!(
        remaining.is_empty(),
        "Expected temp files to be cleaned up, but found: {:?}",
        remaining.iter().map(|e| e.file_name()).collect::<Vec<_>>()
    );
}

#[test]
fn test_execute_fails_when_context_execute_errors() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);

    let mut task = MitamaeTask::new(ScriptSource::Content("package 'vim'".to_string()), binary);
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
fn test_execute_with_no_exit_status_returns_error() {
    // When a process returns no exit status in non-dry-run mode (e.g., killed by signal),
    // this should be treated as an error rather than silently succeeding.
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);

    let mut task = MitamaeTask::new(ScriptSource::Content("package 'vim'".to_string()), binary);
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

#[test]
fn test_execute_without_tmp_directory() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    // Do NOT create /tmp
    let binary = create_fake_binary(&temp_dir);

    let mut task = MitamaeTask::new(ScriptSource::Content("package 'vim'".to_string()), binary);
    task.resolve_privilege(None).unwrap();
    task.resolve_isolation(&IsolationConfig::default());

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
