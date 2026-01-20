mod helpers;

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use rsdebstrap::backends::mmdebstrap;
use rsdebstrap::config::{ProvisionerConfig, load_profile};
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
    use rsdebstrap::backends::debootstrap::Variant;

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
fn test_profile_validation_rejects_incomplete_shell_provisioner() -> Result<()> {
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
"#
    ))?;
    // editorconfig-checker-enable

    assert!(profile.validate().is_err());

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
    let profile = helpers::load_profile_from_yaml(&format!(
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
        [ProvisionerConfig::Shell(shell)] => {
            assert_eq!(
                shell.script.as_ref().unwrap(),
                &Utf8PathBuf::from_path_buf(script_path).unwrap()
            );
        }
        _ => panic!("expected one shell provisioner"),
    }

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

/// Helper function to test provisioner validation rejection with non-directory output
fn test_provisioner_validation_rejects_target(target: &str) -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(&format!(
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
    assert!(err_msg.contains("provisioners require directory output"));

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
