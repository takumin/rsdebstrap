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

    let result = executor.execute_checked(&spec);

    assert!(result.is_err());
    let err = result.unwrap_err();
    let typed = err.downcast_ref::<rsdebstrap::RsdebstrapError>();
    assert!(typed.is_some(), "Expected RsdebstrapError, got: {:#}", err);
    assert!(
        matches!(typed.unwrap(), rsdebstrap::RsdebstrapError::Execution { .. }),
        "Expected Execution variant, got: {:?}",
        typed.unwrap()
    );
    assert!(
        err.to_string().contains("exit status: 7"),
        "Expected exit status in error, got: {}",
        err
    );
}
