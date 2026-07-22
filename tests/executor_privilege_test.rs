//! Real-execution test for `RealCommandExecutor` privilege wrapping.
//!
//! This test mutates the process-global `PATH` so `which::which` resolves a fake
//! `sudo`. Under edition 2024 `std::env::set_var` is `unsafe` and races with any
//! concurrent env access; keeping this as the *only* test in its own binary
//! guarantees no other test runs in-process, which makes the mutation sound
//! without pulling in a serialization crate.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use rsdebstrap::executor::{CommandExecutor, CommandSpec, RealCommandExecutor};
use rsdebstrap::privilege::PrivilegeMethod;

#[test]
fn privilege_wrapping_prepends_escalation_command() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let marker = dir.path().join("argv.txt");

    // A fake `sudo` that records the argv it was handed, then execs it.
    let fake_sudo = dir.path().join("sudo");
    let script =
        format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{}\"\nexec \"$@\"\n", marker.display());
    std::fs::write(&fake_sudo, script).expect("failed to write fake sudo");
    let mut perms = std::fs::metadata(&fake_sudo)
        .expect("failed to stat fake sudo")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&fake_sudo, perms).expect("failed to chmod fake sudo");

    // Prepend the temp dir so `which::which("sudo")` resolves our fake binary.
    let original_path = std::env::var_os("PATH");
    let new_path = match &original_path {
        Some(p) => format!("{}:{}", dir.path().display(), p.to_string_lossy()),
        None => dir.path().display().to_string(),
    };
    // SAFETY: this is the only test in this binary, so no other thread reads or
    // writes the environment concurrently.
    unsafe {
        std::env::set_var("PATH", &new_path);
    }

    let executor = RealCommandExecutor { dry_run: false };
    let spec = CommandSpec::new("sh", vec!["-c".into(), "exit 0".into()])
        .with_privilege(Some(PrivilegeMethod::Sudo));
    let result = executor.execute(&spec);

    // Restore PATH immediately, before any assertion can unwind.
    // SAFETY: same as above — single-threaded access within this binary.
    unsafe {
        match original_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
    }

    let result = result.expect("execute should spawn the fake sudo");
    assert_eq!(
        result.code(),
        Some(0),
        "fake sudo should exec the wrapped command, which exits 0"
    );

    // The fake sudo recorded its argv: the resolved command path (absolute,
    // ending in /sh) followed by the original args — proving the escalation
    // command was prepended and spec.command was resolved to argv[0].
    let recorded = std::fs::read_to_string(&marker).expect("marker file should exist");
    let lines: Vec<&str> = recorded.lines().collect();
    assert_eq!(lines.len(), 3, "expected 3 argv entries, got: {:?}", lines);
    assert!(
        lines[0].ends_with("/sh"),
        "argv[0] should be the resolved absolute path to sh, got: {}",
        lines[0]
    );
    assert_eq!(lines[1], "-c", "original args should follow argv[0]");
    assert_eq!(lines[2], "exit 0", "original args should follow argv[0]");
}
