mod helpers;

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use rsdebstrap::RsdebstrapError;
use rsdebstrap::bootstrap::mmdebstrap::{self, Format};
use rsdebstrap::config::load_profile;
use rsdebstrap::task::TaskDefinition;
use tempfile::tempdir;

#[test]
fn test_load_profile_basic() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs.tar.zst
"#
    ))?;
    // editorconfig-checker-enable

    assert_eq!(profile.dir, "/tmp/test");

    let cfg = helpers::get_mmdebstrap_config(&profile).expect("expected mmdebstrap config");
    assert_eq!(cfg.suite, "bookworm");
    assert_eq!(cfg.target, "rootfs.tar.zst");
    assert_eq!(cfg.mode, mmdebstrap::Mode::Auto);
    assert_eq!(cfg.format, mmdebstrap::Format::Auto);
    assert_eq!(cfg.variant, mmdebstrap::Variant::Debootstrap);
    assert!(cfg.components.is_empty());
    assert!(cfg.architectures.is_empty());
    assert!(cfg.include.is_empty());
    assert!(cfg.keyring.is_empty());
    assert!(cfg.aptopt.is_empty());
    assert!(cfg.dpkgopt.is_empty());
    assert!(cfg.setup_hook.is_empty());
    assert!(cfg.extract_hook.is_empty());
    assert!(cfg.essential_hook.is_empty());
    assert!(cfg.customize_hook.is_empty());
    assert!(cfg.mirrors.is_empty());

    Ok(())
}

#[test]
fn test_load_profile_full() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
dir: /tmp/debian-test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs.tar.zst
  components:
  - main
  - contrib
  architectures:
  - amd64
  include:
  - curl
  - ca-certificates
  keyring:
  - '/etc/apt/trusted.gpg'
  aptopt:
  - 'Apt::Install-Recommends "true"'
  dpkgopt:
  - 'path-exclude=/usr/share/man/*'
  setup_hook:
  - 'echo setup'
  extract_hook:
  - 'echo extract'
  essential_hook:
  - 'echo essential'
  customize_hook:
  - 'echo customize'
"#
    ))?;
    // editorconfig-checker-enable

    assert_eq!(profile.dir, "/tmp/debian-test");

    let cfg = helpers::get_mmdebstrap_config(&profile).expect("expected mmdebstrap config");
    assert_eq!(cfg.suite, "bookworm");
    assert_eq!(cfg.target, "rootfs.tar.zst");
    assert_eq!(cfg.mode, mmdebstrap::Mode::Auto);
    assert_eq!(cfg.format, mmdebstrap::Format::Auto);
    assert_eq!(cfg.variant, mmdebstrap::Variant::Debootstrap);
    assert_eq!(cfg.components, vec!["main", "contrib"]);
    assert_eq!(cfg.architectures, vec!["amd64"]);
    assert_eq!(cfg.include, vec!["curl", "ca-certificates"]);
    assert_eq!(cfg.keyring, vec!["/etc/apt/trusted.gpg"]);
    assert_eq!(cfg.aptopt, vec!["Apt::Install-Recommends \"true\""]);
    assert_eq!(cfg.dpkgopt, vec!["path-exclude=/usr/share/man/*"]);
    assert_eq!(cfg.setup_hook, vec!["echo setup"]);
    assert_eq!(cfg.extract_hook, vec!["echo extract"]);
    assert_eq!(cfg.essential_hook, vec!["echo essential"]);
    assert_eq!(cfg.customize_hook, vec!["echo customize"]);
    assert!(cfg.mirrors.is_empty());

    Ok(())
}

#[test]
fn test_load_profile_invalid_file() {
    let path = Utf8PathBuf::from("/non/existent/file.yml");
    let result = load_profile(path.as_path());
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("I/O error"),
        "Expected error message to contain 'I/O error', got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("not found"),
        "Expected error message to contain 'not found', got: {}",
        err_msg
    );
    assert!(
        err_msg.contains(&path.to_string()),
        "Expected error message to contain path '{}', got: {}",
        path,
        err_msg
    );
}

#[test]
fn test_load_profile_invalid_yaml() -> Result<()> {
    // editorconfig-checker-disable
    let result = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
invalid: yaml
  no_proper_structure
"#
    ));
    // editorconfig-checker-enable
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("YAML parse error"),
        "Expected error message to contain 'YAML parse error', got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("line"),
        "Expected error message to contain line number information, got: {}",
        err_msg
    );

    Ok(())
}

#[test]
fn test_load_profile_with_mirrors() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
dir: /tmp/debian-mirror-test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs.tar.zst
  mirrors:
  - 'http://ftp.jp.debian.org/debian'
  - 'http://security.debian.org/debian-security'
"#
    ))?;
    // editorconfig-checker-enable

    assert_eq!(profile.dir, "/tmp/debian-mirror-test");

    let cfg = helpers::get_mmdebstrap_config(&profile).expect("expected mmdebstrap config");
    assert_eq!(cfg.suite, "bookworm");
    assert_eq!(cfg.target, "rootfs.tar.zst");
    assert_eq!(
        cfg.mirrors,
        vec![
            "http://ftp.jp.debian.org/debian",
            "http://security.debian.org/debian-security"
        ]
    );

    Ok(())
}

#[test]
fn test_load_profile_debootstrap() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
dir: /tmp/debian-debootstrap-test
bootstrap:
  type: debootstrap
  suite: trixie
  target: rootfs
  variant: minbase
  arch: amd64
  components:
  - main
  - contrib
  include:
  - curl
  mirror: 'https://deb.debian.org/debian'
  merged_usr: true
"#
    ))?;
    // editorconfig-checker-enable

    assert_eq!(profile.dir, "/tmp/debian-debootstrap-test");

    let cfg = helpers::get_debootstrap_config(&profile).expect("expected debootstrap config");
    use rsdebstrap::bootstrap::debootstrap::Variant;

    assert_eq!(cfg.suite, "trixie");
    assert_eq!(cfg.target, "rootfs");
    assert_eq!(cfg.variant, Variant::Minbase);
    assert_eq!(cfg.arch, Some("amd64".to_string()));
    assert_eq!(cfg.components, vec!["main", "contrib"]);
    assert_eq!(cfg.include, vec!["curl"]);
    assert_eq!(cfg.mirror, Some("https://deb.debian.org/debian".to_string()));
    assert_eq!(cfg.merged_usr, Some(true));

    Ok(())
}

#[test]
fn test_profile_parsing_rejects_incomplete_shell_task() -> Result<()> {
    // editorconfig-checker-disable
    // With ScriptSource enum, missing script/content is now a parse error, not validation error
    let result = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs.tar.zst
provisioners:
  - type: shell
"#
    ));
    // editorconfig-checker-enable

    assert_error_contains!(result, "either 'script' or 'content' must be specified");

    Ok(())
}

#[test]
fn test_profile_parsing_rejects_shell_task_with_script_and_content() -> Result<()> {
    // editorconfig-checker-disable
    let result = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs.tar.zst
provisioners:
  - type: shell
    script: /tmp/provision.sh
    content: echo "hello"
"#
    ));
    // editorconfig-checker-enable

    assert_error_contains!(result, "mutually exclusive");

    Ok(())
}

#[test]
fn test_profile_validation_rejects_dir_file() -> Result<()> {
    let dir_file = tempfile::NamedTempFile::new()?;
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(format!(
        r#"---
dir: {}
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs.tar.zst
"#,
        dir_file.path().display()
    ))?;
    // editorconfig-checker-enable

    assert!(profile.validate().is_err());

    Ok(())
}

#[test]
fn test_load_profile_resolves_shell_script_relative_to_profile_dir() -> Result<()> {
    let temp_dir = tempdir()?;
    let profile_path = temp_dir.path().join("profile.yml");
    let scripts_dir = temp_dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir)?;
    let script_path = scripts_dir.join("provision.sh");
    std::fs::write(&script_path, "#!/bin/sh\necho hello\n")?;

    // editorconfig-checker-disable
    std::fs::write(
        &profile_path,
        crate::yaml!(
            r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs.tar.zst
provisioners:
  - type: shell
    script: scripts/provision.sh
"#
        ),
    )?;
    // editorconfig-checker-enable

    let path = Utf8Path::from_path(&profile_path).unwrap();
    let profile = load_profile(path)?;

    match profile.provisioners.as_slice() {
        [TaskDefinition::Shell(shell)] => {
            assert_eq!(
                shell.script_path().unwrap().canonicalize_utf8()?,
                Utf8PathBuf::from_path_buf(script_path.canonicalize()?).unwrap()
            );
        }
        _ => panic!("expected one shell task"),
    }

    Ok(())
}

#[test]
fn test_load_profile_resolves_dir_relative_to_profile_dir() -> Result<()> {
    let temp_dir = tempdir()?;
    let profile_dir = temp_dir.path().join("profiles");
    std::fs::create_dir_all(&profile_dir)?;
    let profile_path = profile_dir.join("profile.yml");
    let output_dir = profile_dir.join("output");
    std::fs::create_dir_all(&output_dir)?;

    // editorconfig-checker-disable
    std::fs::write(
        &profile_path,
        crate::yaml!(
            r#"---
dir: output
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs.tar.zst
"#
        ),
    )?;
    // editorconfig-checker-enable

    let path = Utf8Path::from_path(&profile_path).unwrap();
    let profile = load_profile(path)?;

    assert_eq!(
        profile.dir.canonicalize_utf8()?,
        output_dir
            .canonicalize()
            .map(|p| Utf8PathBuf::from_path_buf(p).unwrap())?
    );

    Ok(())
}

#[test]
fn test_shell_task_validation_requires_script_file() -> Result<()> {
    let temp_dir = tempdir()?;
    let profile_path = temp_dir.path().join("profile.yml");

    // editorconfig-checker-disable
    std::fs::write(
        &profile_path,
        crate::yaml!(
            r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs.tar.zst
provisioners:
  - type: shell
    script: scripts/missing.sh
"#
        ),
    )?;
    // editorconfig-checker-enable

    let path = Utf8Path::from_path(&profile_path).unwrap();
    let profile = load_profile(path)?;

    assert!(profile.validate().is_err());

    Ok(())
}

#[test]
fn test_shell_task_path_resolution_with_relative_profile_path() -> Result<()> {
    // Acquire global lock to prevent parallel CWD modifications
    let _lock = helpers::CWD_TEST_LOCK.lock().unwrap();

    let temp_dir = tempdir()?;
    let profile_dir = temp_dir.path().join("configs");
    let scripts_dir = profile_dir.join("scripts");
    std::fs::create_dir_all(&scripts_dir)?;

    // Create a dummy script file
    let script_path = scripts_dir.join("test.sh");
    std::fs::write(&script_path, "#!/bin/bash\necho test")?;

    // Create profile YAML with relative script path
    let profile_path = profile_dir.join("profile.yml");
    // editorconfig-checker-disable
    std::fs::write(
        &profile_path,
        crate::yaml!(
            r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs
  format: directory
provisioners:
  - type: shell
    script: scripts/test.sh
"#
        ),
    )?;
    // editorconfig-checker-enable

    // Use RAII guard to automatically restore working directory
    let cwd_guard = helpers::CwdGuard::new()?;
    cwd_guard.change_to(temp_dir.path())?;

    // Load profile using relative path from the new working directory
    let relative_profile_path = Utf8Path::new("configs/profile.yml");
    let profile = load_profile(relative_profile_path)?;

    // CwdGuard will automatically restore the original directory when dropped

    // Verify the script path resolves to the expected absolute path
    let expected_script_path = Utf8PathBuf::from_path_buf(script_path.canonicalize()?)
        .expect("script path should be valid UTF-8");
    match &profile.provisioners[..] {
        [TaskDefinition::Shell(shell)] => {
            let script = shell.script_path().expect("script should be set");
            assert_eq!(
                script.canonicalize_utf8()?,
                expected_script_path,
                "Script path should resolve to the expected absolute path"
            );
        }
        _ => panic!("expected one shell task"),
    }

    Ok(())
}

/// Helper function to test task validation rejection with non-directory output
fn test_task_validation_rejects_target(target: &str) -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(format!(
        r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: {}
provisioners:
  - type: shell
    content: echo "hello"
"#,
        target
    ))?;
    // editorconfig-checker-enable

    let result = profile.validate();
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("pipeline tasks require directory output"));

    Ok(())
}

#[test]
fn test_profile_validation_rejects_provisioners_with_tar_output() -> Result<()> {
    test_task_validation_rejects_target("rootfs.tar.zst")
}

#[test]
fn test_profile_validation_accepts_provisioners_with_directory_output() -> Result<()> {
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
    ))?;
    // editorconfig-checker-enable

    let result = profile.validate();
    assert!(result.is_ok());

    Ok(())
}

#[test]
fn test_profile_validation_accepts_provisioners_with_debootstrap() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
dir: /tmp/test
bootstrap:
  type: debootstrap
  suite: bookworm
  target: rootfs
provisioners:
  - type: shell
    content: echo "hello"
"#
    ))?;
    // editorconfig-checker-enable

    let result = profile.validate();
    assert!(result.is_ok());

    Ok(())
}

#[test]
fn test_profile_validation_rejects_provisioners_with_squashfs_output() -> Result<()> {
    test_task_validation_rejects_target("rootfs.squashfs")
}

#[test]
fn test_load_profile_with_explicit_chroot_isolation() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
dir: /tmp/test
defaults:
  isolation:
    type: chroot
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs
  format: directory
"#
    ))?;
    // editorconfig-checker-enable

    use rsdebstrap::config::IsolationConfig;
    assert!(matches!(profile.defaults.isolation, IsolationConfig::Chroot));

    Ok(())
}

#[test]
fn test_load_profile_isolation_defaults_to_chroot() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs
  format: directory
"#
    ))?;
    // editorconfig-checker-enable

    use rsdebstrap::config::IsolationConfig;
    assert!(matches!(profile.defaults.isolation, IsolationConfig::Chroot));

    Ok(())
}

/// Helper to test mmdebstrap format parsing with the given format name and expected value.
fn test_load_profile_format(format_name: &str, expected: Format) -> Result<()> {
    let profile = helpers::load_profile_from_yaml(format!(
        "---\ndir: /tmp/test\nbootstrap:\n  type: mmdebstrap\n  suite: bookworm\n  \
        target: rootfs.{0}\n  format: {0}\n",
        format_name
    ))?;
    let cfg = helpers::get_mmdebstrap_config(&profile).expect("expected mmdebstrap config");
    assert_eq!(cfg.format, expected);
    Ok(())
}

#[test]
fn test_load_profile_format_tar_xz() -> Result<()> {
    test_load_profile_format("tar.xz", Format::TarXz)
}

#[test]
fn test_load_profile_format_tar_gz() -> Result<()> {
    test_load_profile_format("tar.gz", Format::TarGz)
}

#[test]
fn test_load_profile_format_tar_zst() -> Result<()> {
    test_load_profile_format("tar.zst", Format::TarZst)
}

#[test]
#[ignore] // Skip in CI: requires file permission manipulation
fn test_load_profile_permission_denied() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempdir()?;
    let profile_path = temp_dir.path().join("profile.yml");
    // editorconfig-checker-disable
    std::fs::write(
        &profile_path,
        crate::yaml!(
            r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs.tar.zst
"#
        ),
    )?;
    // editorconfig-checker-enable

    // Remove read permissions
    std::fs::set_permissions(&profile_path, std::fs::Permissions::from_mode(0o000))?;

    let path = Utf8Path::from_path(&profile_path).unwrap();
    let result = load_profile(path);

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("I/O error"),
        "Expected error message to contain 'I/O error', got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("permission denied"),
        "Expected error message to contain 'permission denied', got: {}",
        err_msg
    );

    Ok(())
}

#[test]
fn test_load_profile_yaml_missing_required_field() -> Result<()> {
    // Missing 'bootstrap' field which is required
    // editorconfig-checker-disable
    let result = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
dir: /tmp/test
"#
    ));
    // editorconfig-checker-enable

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("YAML parse error"),
        "Expected error message to contain 'YAML parse error', got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("bootstrap"),
        "Expected error message to mention missing 'bootstrap' field, got: {}",
        err_msg
    );

    Ok(())
}

#[test]
fn test_load_profile_is_a_directory() {
    let path = Utf8PathBuf::from("/tmp");
    let result = load_profile(path.as_path());
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not a directory"),
        "Expected error message to contain 'not a directory', got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("/tmp") || err_msg.contains("/private/tmp"),
        "Expected error message to contain path '/tmp' or '/private/tmp', got: {}",
        err_msg
    );
}

#[test]
fn test_load_profile_yaml_error_includes_path_and_location() -> Result<()> {
    let temp_dir = tempdir()?;
    let profile_path = temp_dir.path().join("profile.yml");
    // editorconfig-checker-disable
    std::fs::write(
        &profile_path,
        crate::yaml!(
            r#"---
dir: /tmp/test
  invalid_indent
"#
        ),
    )?;
    // editorconfig-checker-enable

    let path = Utf8Path::from_path(&profile_path).unwrap();
    let result = load_profile(path);

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("YAML parse error"),
        "Expected error message to contain 'YAML parse error', got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("line"),
        "Expected error message to contain line number, got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("column"),
        "Expected error message to contain column number, got: {}",
        err_msg
    );
    // Should contain the file path
    assert!(
        err_msg.contains(path.as_str()),
        "Expected error message to contain file path, got: {}",
        err_msg
    );

    Ok(())
}

// =============================================================================
// pre_processors / post_processors tests
// =============================================================================

#[test]
fn test_load_profile_with_pre_processors() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
        dir: /tmp/test
        bootstrap:
          type: mmdebstrap
          suite: bookworm
          target: rootfs
          format: directory
        pre_processors:
          - type: shell
            content: echo "pre-processing"
        "#
    ))?;
    // editorconfig-checker-enable

    assert_eq!(profile.pre_processors.len(), 1);
    assert!(profile.provisioners.is_empty());
    assert!(profile.post_processors.is_empty());

    match &profile.pre_processors[0] {
        TaskDefinition::Shell(task) => {
            assert_eq!(task.name(), "<inline>");
        }
        other => panic!("Expected Shell task, got: {:?}", other),
    }

    Ok(())
}

#[test]
fn test_load_profile_with_post_processors() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
        dir: /tmp/test
        bootstrap:
          type: mmdebstrap
          suite: bookworm
          target: rootfs
          format: directory
        post_processors:
          - type: shell
            content: echo "post-processing"
        "#
    ))?;
    // editorconfig-checker-enable

    assert!(profile.pre_processors.is_empty());
    assert!(profile.provisioners.is_empty());
    assert_eq!(profile.post_processors.len(), 1);

    match &profile.post_processors[0] {
        TaskDefinition::Shell(task) => {
            assert_eq!(task.name(), "<inline>");
        }
        other => panic!("Expected Shell task, got: {:?}", other),
    }

    Ok(())
}

#[test]
fn test_load_profile_with_all_three_phases() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
        dir: /tmp/test
        bootstrap:
          type: mmdebstrap
          suite: bookworm
          target: rootfs
          format: directory
        pre_processors:
          - type: shell
            content: echo "pre"
        provisioners:
          - type: shell
            content: echo "main"
        post_processors:
          - type: shell
            content: echo "post"
        "#
    ))?;
    // editorconfig-checker-enable

    assert_eq!(profile.pre_processors.len(), 1);
    assert_eq!(profile.provisioners.len(), 1);
    assert_eq!(profile.post_processors.len(), 1);

    Ok(())
}

#[test]
fn test_load_profile_phases_default_to_empty() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
        dir: /tmp/test
        bootstrap:
          type: mmdebstrap
          suite: bookworm
          target: rootfs.tar.zst
        "#
    ))?;
    // editorconfig-checker-enable

    assert!(profile.pre_processors.is_empty());
    assert!(profile.provisioners.is_empty());
    assert!(profile.post_processors.is_empty());

    Ok(())
}

/// Helper to test that a phase rejects non-directory (tar) bootstrap output.
fn test_phase_rejects_tar_output(phase_key: &str) -> Result<()> {
    let profile = helpers::load_profile_from_yaml(format!(
        "---\ndir: /tmp/test\nbootstrap:\n  type: mmdebstrap\n  suite: bookworm\n  \
        target: rootfs.tar.zst\n{}:\n  - type: shell\n    \
        content: echo \"test\"\n",
        phase_key
    ))?;
    let result = profile.validate();
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("pipeline tasks require directory output"));
    Ok(())
}

#[test]
fn test_profile_validation_rejects_pre_processors_with_tar_output() -> Result<()> {
    test_phase_rejects_tar_output("pre_processors")
}

#[test]
fn test_profile_validation_rejects_post_processors_with_tar_output() -> Result<()> {
    test_phase_rejects_tar_output("post_processors")
}

#[test]
fn test_load_profile_resolves_pre_processor_script_path() -> Result<()> {
    let temp_dir = tempdir()?;
    let profile_path = temp_dir.path().join("profile.yml");
    let scripts_dir = temp_dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir)?;
    let script_path = scripts_dir.join("pre.sh");
    std::fs::write(&script_path, "#!/bin/sh\necho pre\n")?;

    // editorconfig-checker-disable
    std::fs::write(
        &profile_path,
        crate::yaml!(
            r#"---
            dir: /tmp/test
            bootstrap:
              type: mmdebstrap
              suite: bookworm
              target: rootfs
              format: directory
            pre_processors:
              - type: shell
                script: scripts/pre.sh
            "#
        ),
    )?;
    // editorconfig-checker-enable

    let path = Utf8Path::from_path(&profile_path).unwrap();
    let profile = load_profile(path)?;

    match profile.pre_processors.as_slice() {
        [TaskDefinition::Shell(shell)] => {
            assert_eq!(
                shell.script_path().unwrap().canonicalize_utf8()?,
                Utf8PathBuf::from_path_buf(script_path.canonicalize()?).unwrap()
            );
        }
        _ => panic!("expected one shell pre_processor"),
    }

    Ok(())
}

#[test]
fn test_load_profile_resolves_post_processor_script_path() -> Result<()> {
    let temp_dir = tempdir()?;
    let profile_path = temp_dir.path().join("profile.yml");
    let scripts_dir = temp_dir.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir)?;
    let script_path = scripts_dir.join("post.sh");
    std::fs::write(&script_path, "#!/bin/sh\necho post\n")?;

    // editorconfig-checker-disable
    std::fs::write(
        &profile_path,
        crate::yaml!(
            r#"---
            dir: /tmp/test
            bootstrap:
              type: mmdebstrap
              suite: bookworm
              target: rootfs
              format: directory
            post_processors:
              - type: shell
                script: scripts/post.sh
            "#
        ),
    )?;
    // editorconfig-checker-enable

    let path = Utf8Path::from_path(&profile_path).unwrap();
    let profile = load_profile(path)?;

    match profile.post_processors.as_slice() {
        [TaskDefinition::Shell(shell)] => {
            assert_eq!(
                shell.script_path().unwrap().canonicalize_utf8()?,
                Utf8PathBuf::from_path_buf(script_path.canonicalize()?).unwrap()
            );
        }
        _ => panic!("expected one shell post_processor"),
    }

    Ok(())
}

// =============================================================================
// MitamaeTask integration tests
// =============================================================================

#[test]
fn test_load_profile_resolves_mitamae_binary_relative_to_profile_dir() -> Result<()> {
    let temp_dir = tempdir()?;
    let profile_path = temp_dir.path().join("profile.yml");
    let bin_dir = temp_dir.path().join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    let binary_path = bin_dir.join("mitamae");
    std::fs::write(&binary_path, "fake mitamae binary")?;

    // editorconfig-checker-disable
    std::fs::write(
        &profile_path,
        crate::yaml!(
            r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs
  format: directory
provisioners:
  - type: mitamae
    binary: bin/mitamae
    content: "package 'vim'"
"#
        ),
    )?;
    // editorconfig-checker-enable

    let path = Utf8Path::from_path(&profile_path).unwrap();
    let profile = load_profile(path)?;

    match profile.provisioners.as_slice() {
        [TaskDefinition::Mitamae(mitamae)] => {
            assert_eq!(
                mitamae.binary().unwrap().canonicalize_utf8()?,
                Utf8PathBuf::from_path_buf(binary_path.canonicalize()?).unwrap()
            );
        }
        _ => panic!("expected one mitamae task"),
    }

    Ok(())
}

#[test]
fn test_load_profile_resolves_mitamae_recipe_relative_to_profile_dir() -> Result<()> {
    let temp_dir = tempdir()?;
    let profile_path = temp_dir.path().join("profile.yml");
    let bin_dir = temp_dir.path().join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    let binary_path = bin_dir.join("mitamae");
    std::fs::write(&binary_path, "fake mitamae binary")?;
    let recipes_dir = temp_dir.path().join("recipes");
    std::fs::create_dir_all(&recipes_dir)?;
    let recipe_path = recipes_dir.join("default.rb");
    std::fs::write(&recipe_path, "package 'vim'\n")?;

    // editorconfig-checker-disable
    std::fs::write(
        &profile_path,
        crate::yaml!(
            r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs
  format: directory
provisioners:
  - type: mitamae
    binary: bin/mitamae
    script: recipes/default.rb
"#
        ),
    )?;
    // editorconfig-checker-enable

    let path = Utf8Path::from_path(&profile_path).unwrap();
    let profile = load_profile(path)?;

    match profile.provisioners.as_slice() {
        [TaskDefinition::Mitamae(mitamae)] => {
            assert_eq!(
                mitamae.script_path().unwrap().canonicalize_utf8()?,
                Utf8PathBuf::from_path_buf(recipe_path.canonicalize()?).unwrap()
            );
            assert_eq!(
                mitamae.binary().unwrap().canonicalize_utf8()?,
                Utf8PathBuf::from_path_buf(binary_path.canonicalize()?).unwrap()
            );
        }
        _ => panic!("expected one mitamae task"),
    }

    Ok(())
}

#[test]
fn test_mitamae_task_validation_requires_binary_file() -> Result<()> {
    let temp_dir = tempdir()?;
    let profile_path = temp_dir.path().join("profile.yml");

    // editorconfig-checker-disable
    std::fs::write(
        &profile_path,
        crate::yaml!(
            r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs
  format: directory
provisioners:
  - type: mitamae
    binary: bin/nonexistent_mitamae
    content: "package 'vim'"
"#
        ),
    )?;
    // editorconfig-checker-enable

    let path = Utf8Path::from_path(&profile_path).unwrap();
    let profile = load_profile(path)?;

    assert!(profile.validate().is_err());

    Ok(())
}

// =============================================================================
// Type-based error tests (RsdebstrapError variant matching)
// =============================================================================

#[test]
fn test_load_profile_invalid_file_returns_io_error() {
    let path = "/non/existent/file.yml";
    let result = load_profile(Utf8Path::new(path));
    let err = result.unwrap_err();
    match &err {
        RsdebstrapError::Io {
            context, source, ..
        } => {
            assert_eq!(
                source.kind(),
                std::io::ErrorKind::NotFound,
                "Expected NotFound IO error kind, got: {:?}",
                source.kind()
            );
            assert!(
                context.contains(path),
                "Expected context to contain path '{}', got: {}",
                path,
                context
            );
        }
        other => panic!("Expected RsdebstrapError::Io, got: {:?}", other),
    }
}

#[test]
fn test_load_profile_directory_returns_validation_error() {
    let result = load_profile(Utf8Path::new("/tmp"));
    let err = result.unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected RsdebstrapError::Validation, got: {:?}",
        err
    );
}

#[test]
fn test_load_profile_invalid_yaml_returns_config_error() -> Result<()> {
    // editorconfig-checker-disable
    let result = helpers::load_profile_from_yaml_typed(crate::yaml!(
        r#"---
invalid: yaml
  no_proper_structure
"#
    ));
    // editorconfig-checker-enable
    let err = result.unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Config(_)),
        "Expected RsdebstrapError::Config, got: {:?}",
        err
    );

    Ok(())
}

#[test]
fn test_profile_validation_dir_is_file_returns_validation_error() -> Result<()> {
    let dir_file = tempfile::NamedTempFile::new()?;
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(format!(
        r#"---
dir: {}
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs.tar.zst
"#,
        dir_file.path().display()
    ))?;
    // editorconfig-checker-enable

    let err = profile.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected RsdebstrapError::Validation, got: {:?}",
        err
    );

    Ok(())
}

#[test]
fn test_profile_validation_tar_output_with_tasks_returns_validation_error() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs.tar.zst
provisioners:
  - type: shell
    content: echo "hello"
"#
    ))?;
    // editorconfig-checker-enable

    let err = profile.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected RsdebstrapError::Validation, got: {:?}",
        err
    );

    Ok(())
}

#[test]
fn test_profile_validation_missing_script_preserves_io_error() -> Result<()> {
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
    script: /nonexistent/script.sh
"#
    ))?;
    // editorconfig-checker-enable

    // Pipeline validation should preserve the Io error variant (not flatten to Validation)
    let err = profile.validate().unwrap_err();
    match &err {
        RsdebstrapError::Io {
            context, source, ..
        } => {
            assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            assert!(
                context.contains("/nonexistent/script.sh"),
                "Expected context to contain script path, got: {}",
                context
            );
        }
        other => {
            panic!("Expected RsdebstrapError::Io (preserved through pipeline), got: {:?}", other)
        }
    }

    Ok(())
}

// =============================================================================
// MitamaeDefaults tests
// =============================================================================

#[test]
fn test_load_profile_mitamae_defaults_binary_resolves_for_current_arch() -> Result<()> {
    let temp_dir = tempdir()?;
    let profile_path = temp_dir.path().join("profile.yml");
    let bin_dir = temp_dir.path().join("bin");
    std::fs::create_dir_all(&bin_dir)?;

    let arch = std::env::consts::ARCH;
    let binary_name = format!("mitamae-{}", arch);
    let binary_path = bin_dir.join(&binary_name);
    std::fs::write(&binary_path, "fake mitamae binary")?;

    // editorconfig-checker-disable
    std::fs::write(
        &profile_path,
        format!(
            r#"---
dir: /tmp/test
defaults:
  mitamae:
    binary:
      {}: bin/{}
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs
  format: directory
provisioners:
  - type: mitamae
    content: "package 'vim'"
"#,
            arch, binary_name
        ),
    )?;
    // editorconfig-checker-enable

    let path = Utf8Path::from_path(&profile_path).unwrap();
    let profile = load_profile(path)?;

    match profile.provisioners.as_slice() {
        [TaskDefinition::Mitamae(mitamae)] => {
            assert_eq!(
                mitamae.binary().unwrap().canonicalize_utf8()?,
                Utf8PathBuf::from_path_buf(binary_path.canonicalize()?).unwrap(),
                "binary should be resolved from defaults for arch '{}'",
                arch
            );
        }
        _ => panic!("expected one mitamae task"),
    }

    Ok(())
}

#[test]
fn test_load_profile_mitamae_task_binary_overrides_defaults() -> Result<()> {
    let temp_dir = tempdir()?;
    let profile_path = temp_dir.path().join("profile.yml");
    let bin_dir = temp_dir.path().join("bin");
    std::fs::create_dir_all(&bin_dir)?;

    let arch = std::env::consts::ARCH;
    let default_binary = bin_dir.join(format!("mitamae-default-{}", arch));
    std::fs::write(&default_binary, "default binary")?;
    let override_binary = bin_dir.join("mitamae-override");
    std::fs::write(&override_binary, "override binary")?;

    // editorconfig-checker-disable
    std::fs::write(
        &profile_path,
        format!(
            r#"---
dir: /tmp/test
defaults:
  mitamae:
    binary:
      {}: bin/mitamae-default-{}
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs
  format: directory
provisioners:
  - type: mitamae
    binary: bin/mitamae-override
    content: "package 'vim'"
"#,
            arch, arch
        ),
    )?;
    // editorconfig-checker-enable

    let path = Utf8Path::from_path(&profile_path).unwrap();
    let profile = load_profile(path)?;

    match profile.provisioners.as_slice() {
        [TaskDefinition::Mitamae(mitamae)] => {
            assert_eq!(
                mitamae.binary().unwrap().canonicalize_utf8()?,
                Utf8PathBuf::from_path_buf(override_binary.canonicalize()?).unwrap(),
                "task-level binary should override defaults"
            );
        }
        _ => panic!("expected one mitamae task"),
    }

    Ok(())
}

#[test]
fn test_load_profile_mitamae_defaults_no_matching_arch() -> Result<()> {
    let temp_dir = tempdir()?;
    let profile_path = temp_dir.path().join("profile.yml");

    // editorconfig-checker-disable
    std::fs::write(
        &profile_path,
        crate::yaml!(
            r#"---
dir: /tmp/test
defaults:
  mitamae:
    binary:
      nonexistent_arch: /usr/local/bin/mitamae-nonexistent
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs
  format: directory
provisioners:
  - type: mitamae
    content: "package 'vim'"
"#
        ),
    )?;
    // editorconfig-checker-enable

    let path = Utf8Path::from_path(&profile_path).unwrap();
    let profile = load_profile(path)?;

    match profile.provisioners.as_slice() {
        [TaskDefinition::Mitamae(mitamae)] => {
            assert_eq!(
                mitamae.binary(),
                None,
                "binary should remain None when no matching arch in defaults"
            );
        }
        _ => panic!("expected one mitamae task"),
    }

    // Validation should fail because binary is not set
    let err = profile.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected Validation error, got: {:?}",
        err
    );
    let msg = err.to_string();
    assert!(
        msg.contains(std::env::consts::ARCH),
        "Expected architecture '{}' in error, got: {}",
        std::env::consts::ARCH,
        msg
    );

    Ok(())
}

// =============================================================================
// Task-level isolation tests
// =============================================================================

#[test]
fn test_load_profile_task_isolation_absent_resolves_to_chroot() -> Result<()> {
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
    ))?;
    // editorconfig-checker-enable

    use rsdebstrap::config::IsolationConfig;
    match &profile.provisioners[0] {
        TaskDefinition::Shell(task) => {
            assert_eq!(
                task.resolved_isolation_config(),
                Some(&IsolationConfig::Chroot),
                "Absent isolation should resolve to Chroot from defaults"
            );
        }
        other => panic!("Expected Shell task, got: {:?}", other),
    }

    Ok(())
}

#[test]
fn test_load_profile_task_isolation_true_resolves_to_chroot() -> Result<()> {
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
    isolation: true
"#
    ))?;
    // editorconfig-checker-enable

    use rsdebstrap::config::IsolationConfig;
    match &profile.provisioners[0] {
        TaskDefinition::Shell(task) => {
            assert_eq!(
                task.resolved_isolation_config(),
                Some(&IsolationConfig::Chroot),
                "isolation: true should resolve to Chroot from defaults"
            );
        }
        other => panic!("Expected Shell task, got: {:?}", other),
    }

    Ok(())
}

#[test]
fn test_load_profile_task_isolation_false_resolves_to_none() -> Result<()> {
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
    isolation: false
"#
    ))?;
    // editorconfig-checker-enable

    match &profile.provisioners[0] {
        TaskDefinition::Shell(task) => {
            assert_eq!(
                task.resolved_isolation_config(),
                None,
                "isolation: false should resolve to None (Disabled)"
            );
        }
        other => panic!("Expected Shell task, got: {:?}", other),
    }

    Ok(())
}

#[test]
fn test_load_profile_task_isolation_explicit_chroot_resolves_to_chroot() -> Result<()> {
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
    isolation:
      type: chroot
"#
    ))?;
    // editorconfig-checker-enable

    use rsdebstrap::config::IsolationConfig;
    match &profile.provisioners[0] {
        TaskDefinition::Shell(task) => {
            assert_eq!(
                task.resolved_isolation_config(),
                Some(&IsolationConfig::Chroot),
                "isolation: {{type: chroot}} should resolve to Chroot"
            );
        }
        other => panic!("Expected Shell task, got: {:?}", other),
    }

    Ok(())
}

#[test]
fn test_load_profile_mitamae_task_isolation_false() -> Result<()> {
    let temp_dir = tempdir()?;
    let profile_path = temp_dir.path().join("profile.yml");
    let bin_dir = temp_dir.path().join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    let binary_path = bin_dir.join("mitamae");
    std::fs::write(&binary_path, "fake mitamae binary")?;

    // editorconfig-checker-disable
    std::fs::write(
        &profile_path,
        crate::yaml!(
            r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs
  format: directory
provisioners:
  - type: mitamae
    binary: bin/mitamae
    content: "package 'vim'"
    isolation: false
"#
        ),
    )?;
    // editorconfig-checker-enable

    let path = Utf8Path::from_path(&profile_path).unwrap();
    let profile = load_profile(path)?;

    match profile.provisioners.as_slice() {
        [TaskDefinition::Mitamae(mitamae)] => {
            assert_eq!(
                mitamae.resolved_isolation_config(),
                None,
                "isolation: false on mitamae task should resolve to None"
            );
        }
        _ => panic!("expected one mitamae task"),
    }

    Ok(())
}

#[test]
fn test_load_profile_mixed_task_isolation_settings() -> Result<()> {
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
    content: echo "with isolation"
    isolation: true
  - type: shell
    content: echo "without isolation"
    isolation: false
  - type: shell
    content: echo "default isolation"
"#
    ))?;
    // editorconfig-checker-enable

    use rsdebstrap::config::IsolationConfig;

    assert_eq!(profile.provisioners.len(), 3);

    match &profile.provisioners[0] {
        TaskDefinition::Shell(task) => {
            assert_eq!(task.resolved_isolation_config(), Some(&IsolationConfig::Chroot));
        }
        other => panic!("Expected Shell task, got: {:?}", other),
    }
    match &profile.provisioners[1] {
        TaskDefinition::Shell(task) => {
            assert_eq!(task.resolved_isolation_config(), None);
        }
        other => panic!("Expected Shell task, got: {:?}", other),
    }
    match &profile.provisioners[2] {
        TaskDefinition::Shell(task) => {
            assert_eq!(task.resolved_isolation_config(), Some(&IsolationConfig::Chroot));
        }
        other => panic!("Expected Shell task, got: {:?}", other),
    }

    Ok(())
}
