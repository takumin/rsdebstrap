use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use rsdebstrap::config::load_profile;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_load_profile_basic() -> Result<()> {
    let mut file = NamedTempFile::new()?;
    // editorconfig-checker-disable
    writeln!(
        file,
        r#"---
dir: /tmp/test
mmdebstrap:
  suite: bookworm
  target: rootfs.tar.zst
"#
    )?;
    // editorconfig-checker-enable

    let path = Utf8Path::from_path(file.path()).unwrap();
    let profile = load_profile(path)?;

    assert_eq!(profile.dir, "/tmp/test");
    assert_eq!(profile.mmdebstrap.suite, "bookworm");
    assert_eq!(profile.mmdebstrap.target, "rootfs.tar.zst");
    assert_eq!(profile.mmdebstrap.mode, rsdebstrap::config::Mode::Auto);
    assert_eq!(profile.mmdebstrap.format, rsdebstrap::config::Format::Auto);
    assert_eq!(profile.mmdebstrap.variant, rsdebstrap::config::Variant::Debootstrap);
    assert!(profile.mmdebstrap.components.is_empty());
    assert!(profile.mmdebstrap.architectures.is_empty());
    assert!(profile.mmdebstrap.include.is_empty());
    assert!(profile.mmdebstrap.keyring.is_empty());
    assert!(profile.mmdebstrap.aptopt.is_empty());
    assert!(profile.mmdebstrap.dpkgopt.is_empty());
    assert!(profile.mmdebstrap.setup_hook.is_empty());
    assert!(profile.mmdebstrap.extract_hook.is_empty());
    assert!(profile.mmdebstrap.essential_hook.is_empty());
    assert!(profile.mmdebstrap.customize_hook.is_empty());

    Ok(())
}

#[test]
fn test_load_profile_full() -> Result<()> {
    let mut file = NamedTempFile::new()?;
    // editorconfig-checker-disable
    writeln!(
        file,
        r#"---
dir: /tmp/debian-test
mmdebstrap:
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
    )?;
    // editorconfig-checker-enable

    let path = Utf8Path::from_path(file.path()).unwrap();
    let profile = load_profile(path)?;

    assert_eq!(profile.dir, "/tmp/debian-test");
    assert_eq!(profile.mmdebstrap.suite, "bookworm");
    assert_eq!(profile.mmdebstrap.target, "rootfs.tar.zst");
    assert_eq!(profile.mmdebstrap.mode, rsdebstrap::config::Mode::Auto);
    assert_eq!(profile.mmdebstrap.format, rsdebstrap::config::Format::Auto);
    assert_eq!(profile.mmdebstrap.variant, rsdebstrap::config::Variant::Debootstrap);
    assert_eq!(profile.mmdebstrap.components, vec!["main", "contrib"]);
    assert_eq!(profile.mmdebstrap.architectures, vec!["amd64"]);
    assert_eq!(profile.mmdebstrap.include, vec!["curl", "ca-certificates"]);
    assert_eq!(profile.mmdebstrap.keyring, vec!["/etc/apt/trusted.gpg"]);
    assert_eq!(profile.mmdebstrap.aptopt, vec!["Apt::Install-Recommends \"true\""]);
    assert_eq!(profile.mmdebstrap.dpkgopt, vec!["path-exclude=/usr/share/man/*"]);
    assert_eq!(profile.mmdebstrap.setup_hook, vec!["echo setup"]);
    assert_eq!(profile.mmdebstrap.extract_hook, vec!["echo extract"]);
    assert_eq!(profile.mmdebstrap.essential_hook, vec!["echo essential"]);
    assert_eq!(profile.mmdebstrap.customize_hook, vec!["echo customize"]);

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
    let mut file = NamedTempFile::new()?;
    // editorconfig-checker-disable
    writeln!(
        file,
        r#"---
invalid: yaml
  no_proper_structure
"#
    )?;
    // editorconfig-checker-enable

    let path = Utf8Path::from_path(file.path()).unwrap();
    let result = load_profile(path);
    assert!(result.is_err());

    Ok(())
}
