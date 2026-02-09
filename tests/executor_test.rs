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
        assert!(
            e.to_string().contains("not found in PATH"),
            "Expected 'not found in PATH' in error, got: {}",
            e
        );
    }
}
