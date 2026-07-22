use camino::Utf8Path;
use rsdebstrap::executor::{CommandExecutor, CommandSpec, RealCommandExecutor};

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
        let msg = e.to_string();
        assert!(
            msg.contains("not found in PATH"),
            "Expected 'not found in PATH' in error, got: {}",
            msg
        );
        // Verify it's a CommandNotFound variant
        let typed = e.downcast_ref::<rsdebstrap::RsdebstrapError>();
        assert!(typed.is_some(), "Expected RsdebstrapError, got: {:#}", e);
        assert!(
            matches!(typed.unwrap(), rsdebstrap::RsdebstrapError::CommandNotFound { .. }),
            "Expected CommandNotFound variant, got: {:?}",
            typed.unwrap()
        );
    }
}

#[test]
fn execute_checked_returns_error_for_non_zero_exit() {
    let executor = RealCommandExecutor { dry_run: false };
    let spec = CommandSpec::new("sh", vec!["-c".into(), "exit 7".into()]);

    let err = executor
        .execute_checked(&spec)
        .expect_err("command should have failed");

    let typed_err = err
        .downcast_ref::<rsdebstrap::RsdebstrapError>()
        .expect("error should be a RsdebstrapError");

    assert!(
        matches!(typed_err, rsdebstrap::RsdebstrapError::Execution { .. }),
        "Expected Execution variant, got: {:?}",
        typed_err
    );
    assert!(
        err.to_string().contains("exit status: 7"),
        "Expected exit status in error, got: {}",
        err
    );
}

#[test]
fn cwd_is_applied_to_child() {
    let executor = RealCommandExecutor { dry_run: false };
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let sentinel = "rsdebstrap_cwd_sentinel";
    std::fs::File::create(dir.path().join(sentinel)).expect("failed to create sentinel");
    let cwd = Utf8Path::from_path(dir.path())
        .expect("temp dir path should be valid UTF-8")
        .to_owned();

    // With cwd applied, `test -f <sentinel>` finds the file created in that dir.
    let spec =
        CommandSpec::new("sh", vec!["-c".into(), format!("test -f {sentinel}")]).with_cwd(cwd);
    let result = executor.execute(&spec).expect("execute should spawn");
    assert_eq!(result.code(), Some(0), "cwd should be applied so the sentinel is found");

    // Negative control: without cwd, the child cannot find the sentinel.
    let spec_no_cwd = CommandSpec::new("sh", vec!["-c".into(), format!("test -f {sentinel}")]);
    let result_no_cwd = executor
        .execute(&spec_no_cwd)
        .expect("execute should spawn");
    assert_ne!(result_no_cwd.code(), Some(0), "without cwd the sentinel should not be found");
}

#[test]
fn env_is_applied_to_child() {
    let executor = RealCommandExecutor { dry_run: false };
    let script = "test \"$RSDEBSTRAP_ENV_TEST\" = present";

    // With the env var set, the shell test succeeds (exit 0).
    let spec = CommandSpec::new("sh", vec!["-c".into(), script.into()])
        .with_env("RSDEBSTRAP_ENV_TEST", "present");
    let result = executor.execute(&spec).expect("execute should spawn");
    assert_eq!(result.code(), Some(0), "env var should be visible to the child");

    // Negative control: without the env var it is unset, so the test fails.
    let spec_no_env = CommandSpec::new("sh", vec!["-c".into(), script.into()]);
    let result_no_env = executor
        .execute(&spec_no_env)
        .expect("execute should spawn");
    assert_ne!(result_no_env.code(), Some(0), "without the env var the test should fail");
}
