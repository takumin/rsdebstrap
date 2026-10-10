// Real `sudo`, whose `env_reset` is what `--preserve-env` gets a privileged spec's variables
// past. `#[ignore]`d because it needs passwordless sudo whose policy allows preserving the
// environment (a rule for `ALL` commands does). Run with:
//
//     cargo test --test sudo_preserve_env_test -- --ignored

use std::process::Command;

use rsdebstrap::executor::{CommandExecutor, CommandSpec, PrivilegedProgram, RealCommandExecutor};
use rsdebstrap::privilege::PrivilegeMethod;

// `-n` makes sudo fail immediately instead of prompting, so an unconfigured machine skips.
fn passwordless_sudo_available() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .is_ok_and(|s| s.success())
}

// `chroot /` is a `PrivilegedProgram` with no effect, so the spec is one the executor really
// builds.
#[test]
#[ignore = "requires passwordless sudo"]
fn a_privileged_command_receives_its_variables_through_real_sudo() {
    if !passwordless_sudo_available() {
        eprintln!("skipping: passwordless sudo is not available");
        return;
    }

    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let out = dir.path().join("out");
    let spec = CommandSpec::privileged(
        PrivilegedProgram::Chroot,
        vec![
            "/".to_string(),
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(r#"printf '%s|%s' "$(id -u)" "$SECRET" > '{}'"#, out.display()),
        ],
        Some(PrivilegeMethod::Sudo),
    )
    .with_env("SECRET", "s3cret value");
    RealCommandExecutor::new(false)
        .execute_checked(&spec)
        .expect("the privileged command should succeed");

    assert_eq!(std::fs::read_to_string(&out).unwrap(), "0|s3cret value");
}
