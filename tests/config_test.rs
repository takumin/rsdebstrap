mod helpers;

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
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

    let cfg = helpers::get_mmdebstrap_config(&profile);
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

    let cfg = helpers::get_mmdebstrap_config(&profile);
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
        err_msg.contains("file not found"),
        "Expected error message to contain 'file not found', got: {}",
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

    let cfg = helpers::get_mmdebstrap_config(&profile);
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

    let cfg = helpers::get_debootstrap_config(&profile);
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
fn test_profile_parsing_rejects_incomplete_shell_provisioner() -> Result<()> {
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

    assert!(result.is_err());
    // The error message should indicate that neither 'script' nor 'content' was found
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("flattened") || err_msg.contains("script") || err_msg.contains("content"),
        "Expected error about missing script/content, got: {}",
        err_msg
    );

    Ok(())
}

#[test]
fn test_profile_validation_rejects_shell_provisioner_with_script_and_content() -> Result<()> {
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
    script: /tmp/provision.sh
    content: echo "hello"
"#
    ))?;
    // editorconfig-checker-enable

    assert!(profile.validate().is_err());

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
        _ => panic!("expected one shell provisioner"),
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
fn test_shell_provisioner_validation_requires_script_file() -> Result<()> {
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
fn test_shell_provisioner_path_resolution_with_relative_profile_path() -> Result<()> {
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
        _ => panic!("expected one shell provisioner"),
    }

    Ok(())
}

/// Helper function to test provisioner validation rejection with non-directory output
fn test_provisioner_validation_rejects_target(target: &str) -> Result<()> {
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
    test_provisioner_validation_rejects_target("rootfs.tar.zst")
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
    test_provisioner_validation_rejects_target("rootfs.squashfs")
}

#[test]
fn test_load_profile_with_explicit_chroot_isolation() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
dir: /tmp/test
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
    assert!(matches!(profile.isolation, IsolationConfig::Chroot));

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
    assert!(matches!(profile.isolation, IsolationConfig::Chroot));

    Ok(())
}

#[test]
fn test_load_profile_format_tar_xz() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs.tar.xz
  format: tar.xz
"#
    ))?;
    // editorconfig-checker-enable

    let cfg = helpers::get_mmdebstrap_config(&profile);
    assert_eq!(cfg.format, Format::TarXz);

    Ok(())
}

#[test]
fn test_load_profile_format_tar_gz() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs.tar.gz
  format: tar.gz
"#
    ))?;
    // editorconfig-checker-enable

    let cfg = helpers::get_mmdebstrap_config(&profile);
    assert_eq!(cfg.format, Format::TarGz);

    Ok(())
}

#[test]
fn test_load_profile_format_tar_zst() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs.tar.zst
  format: tar.zst
"#
    ))?;
    // editorconfig-checker-enable

    let cfg = helpers::get_mmdebstrap_config(&profile);
    assert_eq!(cfg.format, Format::TarZst);

    Ok(())
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
        err_msg.contains("I/O error"),
        "Expected error message to contain 'I/O error', got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("is a directory"),
        "Expected error message to contain 'is a directory', got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("/tmp"),
        "Expected error message to contain path '/tmp', got: {}",
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
        err_msg.contains(&profile_path.to_string_lossy().to_string()),
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

#[test]
fn test_profile_validation_rejects_pre_processors_with_tar_output() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
        dir: /tmp/test
        bootstrap:
          type: mmdebstrap
          suite: bookworm
          target: rootfs.tar.zst
        pre_processors:
          - type: shell
            content: echo "pre"
        "#
    ))?;
    // editorconfig-checker-enable

    let result = profile.validate();
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("pipeline tasks require directory output"));

    Ok(())
}

#[test]
fn test_profile_validation_rejects_post_processors_with_tar_output() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
        dir: /tmp/test
        bootstrap:
          type: mmdebstrap
          suite: bookworm
          target: rootfs.tar.zst
        post_processors:
          - type: shell
            content: echo "post"
        "#
    ))?;
    // editorconfig-checker-enable

    let result = profile.validate();
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("pipeline tasks require directory output"));

    Ok(())
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
