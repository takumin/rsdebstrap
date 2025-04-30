use anyhow::Result;
use rsdebstrap::config::load_profile;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_load_profile_basic() -> Result<()> {
    let mut file = NamedTempFile::new()?;
    writeln!(
        file,
        r#"---
dir: /tmp/test
mmdebstrap:
  suite: bookworm
  target: rootfs.tar.zst
"#
    )?;

    let profile = load_profile(file.path().to_str().unwrap())?;

    assert_eq!(profile.dir, "/tmp/test");
    assert_eq!(profile.mmdebstrap.suite, "bookworm");
    assert_eq!(profile.mmdebstrap.target, "rootfs.tar.zst");
    assert!(profile.mmdebstrap.components.is_empty());
    assert!(profile.mmdebstrap.architectures.is_empty());
    assert!(profile.mmdebstrap.include.is_empty());

    Ok(())
}

#[test]
fn test_load_profile_full() -> Result<()> {
    let mut file = NamedTempFile::new()?;
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
"#
    )?;

    let profile = load_profile(file.path().to_str().unwrap())?;

    assert_eq!(profile.dir, "/tmp/debian-test");
    assert_eq!(profile.mmdebstrap.suite, "bookworm");
    assert_eq!(profile.mmdebstrap.target, "rootfs.tar.zst");
    assert_eq!(profile.mmdebstrap.components, vec!["main", "contrib"]);
    assert_eq!(profile.mmdebstrap.architectures, vec!["amd64"]);
    assert_eq!(profile.mmdebstrap.include, vec!["curl", "ca-certificates"]);

    Ok(())
}

#[test]
fn test_load_profile_invalid_file() {
    let result = load_profile("/non/existent/file.yml");
    assert!(result.is_err());
}

#[test]
fn test_load_profile_invalid_yaml() -> Result<()> {
    let mut file = NamedTempFile::new()?;
    writeln!(
        file,
        r#"---
invalid: yaml
  no_proper_structure
"#
    )?;

    let result = load_profile(file.path().to_str().unwrap());
    assert!(result.is_err());

    Ok(())
}
