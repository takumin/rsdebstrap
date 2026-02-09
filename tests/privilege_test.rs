mod helpers;

use rsdebstrap::RsdebstrapError;
use rsdebstrap::config::Bootstrap;
use rsdebstrap::privilege::{Privilege, PrivilegeDefaults, PrivilegeMethod};
use rsdebstrap::task::{ScriptSource, ShellTask, TaskDefinition};
use tempfile::tempdir;

// =============================================================================
// Privilege inheritance and resolution integration tests
// =============================================================================

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
        provisioners:
          - type: shell
            content: echo "hello"
        "#
    ))
    .expect("profile should load");
    // editorconfig-checker-enable

    // Bootstrap should have resolved to Sudo
    match &profile.bootstrap {
        Bootstrap::Mmdebstrap(cfg) => {
            assert_eq!(cfg.privilege, Privilege::Method(PrivilegeMethod::Sudo));
        }
        other => panic!("expected mmdebstrap, got: {:?}", other),
    }

    // Task should also inherit Sudo from defaults.
    // The resolved privilege field is private, but we verify the profile
    // loads without error (resolve_privilege succeeded).
    assert!(
        matches!(&profile.provisioners[0], TaskDefinition::Shell(_)),
        "expected Shell task"
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
        provisioners:
          - type: shell
            content: echo "hello"
            privilege:
              method: doas
        "#
    ))
    .expect("profile should load");
    // editorconfig-checker-enable

    // Bootstrap inherits sudo from defaults
    match &profile.bootstrap {
        Bootstrap::Mmdebstrap(cfg) => {
            assert_eq!(cfg.privilege, Privilege::Method(PrivilegeMethod::Sudo));
        }
        other => panic!("expected mmdebstrap, got: {:?}", other),
    }

    // Profile loads successfully with task-level doas override
    assert_eq!(profile.provisioners.len(), 1);
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
        provisioners:
          - type: shell
            content: echo "hello"
            privilege: false
        "#
    ))
    .expect("profile should load");
    // editorconfig-checker-enable

    // Bootstrap privilege should be disabled
    match &profile.bootstrap {
        Bootstrap::Mmdebstrap(cfg) => {
            assert_eq!(cfg.privilege, Privilege::Disabled);
        }
        other => panic!("expected mmdebstrap, got: {:?}", other),
    }
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
        provisioners:
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
        provisioners:
          - type: shell
            content: echo "hello"
        "#
    ))
    .expect("profile should load");
    // editorconfig-checker-enable

    // Bootstrap with no defaults and no explicit privilege
    // → Disabled (resolved from Inherit with no defaults)
    match &profile.bootstrap {
        Bootstrap::Mmdebstrap(cfg) => {
            assert_eq!(
                cfg.privilege,
                Privilege::Disabled,
                "Inherit with no defaults should resolve to Disabled"
            );
        }
        other => panic!("expected mmdebstrap, got: {:?}", other),
    }

    // Task should also have no privilege escalation
    assert_eq!(profile.provisioners.len(), 1);
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
        provisioners:
          - type: shell
            content: echo "hello"
        "#
    ))
    .expect("profile should load");
    // editorconfig-checker-enable

    // Bootstrap should have resolved to Doas
    match &profile.bootstrap {
        Bootstrap::Debootstrap(cfg) => {
            assert_eq!(cfg.privilege, Privilege::Method(PrivilegeMethod::Doas));
        }
        other => panic!("expected debootstrap, got: {:?}", other),
    }
}

// =============================================================================
// MockContext-based privilege propagation tests
// =============================================================================

/// Helper to set up a valid rootfs with /tmp and /bin/sh
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

    let mut task = ShellTask::new(ScriptSource::Content("echo hello".to_string()));
    let defaults = PrivilegeDefaults {
        method: PrivilegeMethod::Sudo,
    };
    task.resolve_privilege(Some(&defaults))
        .expect("resolve_privilege should succeed");

    let context = helpers::MockContext::new(&rootfs);
    let result = task.execute(&context);
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

    let mut task = ShellTask::new(ScriptSource::Content("echo hello".to_string()));
    // No defaults → privilege resolves to None
    task.resolve_privilege(None)
        .expect("resolve_privilege should succeed");

    let context = helpers::MockContext::new(&rootfs);
    let result = task.execute(&context);
    assert!(result.is_ok(), "execute should succeed, got: {:?}", result);

    let privileges = context.executed_privileges();
    assert_eq!(privileges.len(), 1, "Expected exactly one execution");
    assert_eq!(privileges[0], None, "Expected no privilege escalation (None)");
}
