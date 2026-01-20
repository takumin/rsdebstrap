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
