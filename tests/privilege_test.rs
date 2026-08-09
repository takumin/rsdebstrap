mod helpers;

use rsdebstrap::RsdebstrapError;
use rsdebstrap::config::Profile;
use rsdebstrap::phase::{ScriptSource, ShellTask};
use rsdebstrap::privilege::{PrivilegeDefaults, PrivilegeMethod};
use tempfile::tempdir;

fn task_privilege(profile: &Profile, index: usize) -> Option<PrivilegeMethod> {
    profile.provision[index]
        .privilege()
        .resolve(profile.defaults.privilege.as_ref())
        .expect("resolve should succeed")
}

fn bootstrap_privilege(profile: &Profile) -> Option<PrivilegeMethod> {
    profile
        .bootstrap
        .resolve_privilege(profile.defaults.privilege.as_ref())
        .expect("resolve should succeed")
}

#[test]
fn test_default_privilege_sudo_inherited_by_bootstrap_and_tasks() {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
        dir: /tmp/test
        defaults:
          privilege:
            method: sudo
        bootstrap:
          type: mmdebstrap
          suite: bookworm
          target: rootfs
          format: directory
        provision:
          - type: shell
            content: echo "hello"
        "#
    ))
    .expect("profile should load");
    // editorconfig-checker-enable

    assert_eq!(bootstrap_privilege(&profile), Some(PrivilegeMethod::Sudo));

    assert_eq!(
        task_privilege(&profile, 0),
        Some(PrivilegeMethod::Sudo),
        "task should inherit Sudo from defaults"
    );
}

#[test]
fn test_task_level_privilege_overrides_default() {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
        dir: /tmp/test
        defaults:
          privilege:
            method: sudo
        bootstrap:
          type: mmdebstrap
          suite: bookworm
          target: rootfs
          format: directory
        provision:
          - type: shell
            content: echo "hello"
            privilege:
              method: doas
        "#
    ))
    .expect("profile should load");
    // editorconfig-checker-enable

    assert_eq!(bootstrap_privilege(&profile), Some(PrivilegeMethod::Sudo));

    assert_eq!(
        task_privilege(&profile, 0),
        Some(PrivilegeMethod::Doas),
        "task-level method should win over defaults.privilege.method"
    );
}

#[test]
fn test_privilege_false_disables_escalation() {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
        dir: /tmp/test
        defaults:
          privilege:
            method: sudo
        bootstrap:
          type: mmdebstrap
          suite: bookworm
          target: rootfs
          format: directory
          privilege: false
        provision:
          - type: shell
            content: echo "hello"
            privilege: false
        "#
    ))
    .expect("profile should load");
    // editorconfig-checker-enable

    assert_eq!(bootstrap_privilege(&profile), None);

    assert_eq!(
        task_privilege(&profile, 0),
        None,
        "privilege: false on the task must suppress the inherited method"
    );
}

#[test]
fn test_privilege_true_without_defaults_returns_validation_error() {
    // editorconfig-checker-disable
    let result = helpers::load_profile_from_yaml_typed(crate::yaml!(
        r#"---
        dir: /tmp/test
        bootstrap:
          type: mmdebstrap
          suite: bookworm
          target: rootfs
          format: directory
          privilege: true
        "#
    ));
    // editorconfig-checker-enable

    let err = result.unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected RsdebstrapError::Validation, got: {:?}",
        err
    );
    assert!(
        err.to_string().contains("defaults.privilege.method"),
        "Expected error about missing defaults, got: {}",
        err
    );
}

#[test]
fn test_privilege_true_on_task_without_defaults_returns_validation_error() {
    // editorconfig-checker-disable
    let result = helpers::load_profile_from_yaml_typed(crate::yaml!(
        r#"---
        dir: /tmp/test
        bootstrap:
          type: mmdebstrap
          suite: bookworm
          target: rootfs
          format: directory
        provision:
          - type: shell
            content: echo "hello"
            privilege: true
        "#
    ));
    // editorconfig-checker-enable

    let err = result.unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected RsdebstrapError::Validation, got: {:?}",
        err
    );
    assert!(
        err.to_string().contains("defaults.privilege.method"),
        "Expected error about missing defaults, got: {}",
        err
    );
}

#[test]
fn test_no_defaults_no_privilege_results_in_none() {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
        dir: /tmp/test
        bootstrap:
          type: mmdebstrap
          suite: bookworm
          target: rootfs
          format: directory
        provision:
          - type: shell
            content: echo "hello"
        "#
    ))
    .expect("profile should load");
    // editorconfig-checker-enable

    assert_eq!(
        bootstrap_privilege(&profile),
        None,
        "Inherit with no defaults should resolve to no escalation"
    );

    assert_eq!(
        task_privilege(&profile, 0),
        None,
        "Inherit with no defaults should resolve to no escalation"
    );
}

#[test]
fn test_default_privilege_doas_inherited() {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
        dir: /tmp/test
        defaults:
          privilege:
            method: doas
        bootstrap:
          type: debootstrap
          suite: trixie
          target: rootfs
        provision:
          - type: shell
            content: echo "hello"
        "#
    ))
    .expect("profile should load");
    // editorconfig-checker-enable

    assert_eq!(bootstrap_privilege(&profile), Some(PrivilegeMethod::Doas));
}

fn setup_valid_rootfs(temp_dir: &tempfile::TempDir) {
    let rootfs = temp_dir.path();
    std::fs::create_dir(rootfs.join("tmp")).expect("failed to create tmp dir");
    std::fs::create_dir_all(rootfs.join("bin")).expect("failed to create bin dir");
    std::fs::write(rootfs.join("bin/sh"), "#!/bin/sh\n").expect("failed to write /bin/sh");
}

#[test]
fn test_shell_task_propagates_sudo_privilege_to_mock_context() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_valid_rootfs(&temp_dir);

    let task = ShellTask::new(ScriptSource::Content("echo hello".to_string()));
    let defaults = PrivilegeDefaults {
        method: PrivilegeMethod::Sudo,
    };
    let privilege = task
        .privilege()
        .resolve(Some(&defaults))
        .expect("resolve should succeed");

    let context = helpers::MockContext::new(&rootfs);
    let result = task.execute(&context, privilege);
    assert!(result.is_ok(), "execute should succeed, got: {:?}", result);

    let privileges = context.executed_privileges();
    assert_eq!(privileges.len(), 1, "Expected exactly one execution");
    assert_eq!(
        privileges[0],
        Some(PrivilegeMethod::Sudo),
        "Expected Sudo privilege to be propagated"
    );
}

#[test]
fn test_shell_task_propagates_none_privilege_to_mock_context() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_valid_rootfs(&temp_dir);

    let task = ShellTask::new(ScriptSource::Content("echo hello".to_string()));
    let privilege = task
        .privilege()
        .resolve(None)
        .expect("resolve should succeed");

    let context = helpers::MockContext::new(&rootfs);
    let result = task.execute(&context, privilege);
    assert!(result.is_ok(), "execute should succeed, got: {:?}", result);

    let privileges = context.executed_privileges();
    assert_eq!(privileges.len(), 1, "Expected exactly one execution");
    assert_eq!(privileges[0], None, "Expected no privilege escalation (None)");
}

// `isolation: false` runs the program the task names from inside the rootfs directly on the
// host. Escalating that would hand root to whatever the half-built rootfs contains.
#[test]
fn test_direct_execution_may_not_be_escalated() {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml_typed(crate::yaml!(
        r#"---
        dir: /tmp/test
        defaults:
          privilege:
            method: sudo
        bootstrap:
          type: mmdebstrap
          suite: bookworm
          target: rootfs
          format: directory
        provision:
          - type: shell
            content: echo "hello"
            isolation: false
        "#
    ));
    // editorconfig-checker-enable

    let err = profile.expect_err("escalated direct execution must be refused at load time");
    assert!(matches!(err, RsdebstrapError::Validation(_)));
    assert!(err.to_string().contains("isolation: false"), "unexpected error: {err}");
}

// The same task with privilege explicitly off is fine: that is the way to say it.
#[test]
fn test_direct_execution_is_allowed_without_privilege() {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
        dir: /tmp/test
        defaults:
          privilege:
            method: sudo
        bootstrap:
          type: mmdebstrap
          suite: bookworm
          target: rootfs
          format: directory
        provision:
          - type: shell
            content: echo "hello"
            isolation: false
            privilege: false
        "#
    ))
    .expect("profile should load");
    // editorconfig-checker-enable

    assert_eq!(task_privilege(&profile, 0), None);
}
