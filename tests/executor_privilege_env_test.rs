// Real-execution test for how `RealCommandExecutor` hands a privileged spec its environment
// past an escalation that resets it: set on `sudo` and named in `--preserve-env`, never in
// the argv.
//
// Like `executor_privilege_test.rs`, this mutates the process-global `PATH` so `which::which`
// resolves fakes, and is the only test in its binary so that mutation is sound.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use rsdebstrap::executor::{
    BootstrapProgram, CommandExecutor, CommandSpec, PrivilegedProgram, RealCommandExecutor,
};
use rsdebstrap::privilege::PrivilegeMethod;

fn write_script(path: &Path, body: &str) {
    std::fs::write(path, body).expect("failed to write fake program");
    let mut perms = std::fs::metadata(path)
        .expect("failed to stat fake program")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).expect("failed to chmod fake program");
}

#[test]
fn privileged_spec_env_survives_an_environment_reset() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let argv = dir.path().join("argv.txt");
    let seen = dir.path().join("seen.txt");

    // Stands in for sudo's `env_reset`: every exported variable is dropped except PATH and
    // the names `--preserve-env=` lists.
    write_script(
        &dir.path().join("sudo"),
        &format!(
            r#"#!/bin/sh
printf '%s\n' "$@" > "{}"
keep=
case "$1" in --preserve-env=*) keep=${{1#--preserve-env=}}; shift;; esac
for name in $(env | sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p'); do
    case ",PATH,$keep," in *",$name,"*) ;; *) unset "$name";; esac
done
exec "$@"
"#,
            argv.display()
        ),
    );
    write_script(
        &dir.path().join("mmdebstrap"),
        &format!("#!/bin/sh\nprintf '%s' \"$HTTP_PROXY\" > \"{}\"\n", seen.display()),
    );

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

    let spec = CommandSpec::privileged(
        PrivilegedProgram::Bootstrap(BootstrapProgram::Mmdebstrap),
        vec!["--arg".to_string()],
        Some(PrivilegeMethod::Sudo),
    )
    .with_env("HTTP_PROXY", "http://proxy.example:3128");
    let result = RealCommandExecutor::new(false).execute_checked(&spec);

    // SAFETY: same as above — single-threaded access within this binary.
    unsafe {
        match original_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
    }

    result.expect("the fake sudo should run the fake mmdebstrap");

    // The value never appears in the escalated argv, where the process list would show it.
    let recorded = std::fs::read_to_string(&argv).expect("argv marker should exist");
    assert!(!recorded.contains("proxy.example"), "value leaked into argv: {recorded}");
    let lines: Vec<&str> = recorded.lines().collect();
    assert_eq!(lines.len(), 3, "unexpected argv: {lines:?}");
    assert_eq!(lines[0], "--preserve-env=HTTP_PROXY");
    assert!(lines[1].ends_with("/mmdebstrap"), "got: {}", lines[1]);
    assert_eq!(lines[2], "--arg");

    assert_eq!(
        std::fs::read_to_string(&seen).expect("seen marker should exist"),
        "http://proxy.example:3128"
    );
}
