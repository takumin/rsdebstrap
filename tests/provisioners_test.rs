use rsdebstrap::provisioners::shell::ShellProvisioner;
use tempfile::tempdir;

fn default_shell() -> String {
    "/bin/sh".to_string()
}

#[test]
fn test_validate_no_script_or_content() {
    let provisioner = ShellProvisioner {
        script: None,
        content: None,
        shell: default_shell(),
    };
    assert!(provisioner.validate().is_err());
}

#[test]
fn test_validate_both_script_and_content() {
    let provisioner = ShellProvisioner {
        script: Some("test.sh".into()),
        content: Some("echo test".to_string()),
        shell: default_shell(),
    };
    assert!(provisioner.validate().is_err());
}

#[test]
fn test_validate_script_only() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let script_path = temp_dir.path().join("test.sh");
    std::fs::write(&script_path, "#!/bin/sh\necho test\n").expect("failed to write script");
    let provisioner = ShellProvisioner {
        script: Some(
            camino::Utf8PathBuf::from_path_buf(script_path)
                .expect("script path should be valid UTF-8"),
        ),
        content: None,
        shell: default_shell(),
    };
    assert!(provisioner.validate().is_ok());
}

#[test]
fn test_validate_content_only() {
    let provisioner = ShellProvisioner {
        script: None,
        content: Some("echo test".to_string()),
        shell: default_shell(),
    };
    assert!(provisioner.validate().is_ok());
}

#[test]
fn test_script_source_external() {
    let provisioner = ShellProvisioner {
        script: Some("test.sh".into()),
        content: None,
        shell: default_shell(),
    };
    assert_eq!(provisioner.script_source(), "test.sh");
}

#[test]
fn test_script_source_inline() {
    let provisioner = ShellProvisioner {
        script: None,
        content: Some("echo test".to_string()),
        shell: default_shell(),
    };
    assert_eq!(provisioner.script_source(), "<inline>");
}

// YAML parsing tests for global isolation configuration in Profile
mod yaml_parsing {
    use rsdebstrap::config::Profile;
    use rsdebstrap::isolation::{ChrootIsolation, IsolationConfig, Privilege};

    #[test]
    fn test_profile_default_isolation() {
        let yaml = r#"
dir: /tmp/rootfs
bootstrap:
  type: mmdebstrap
  suite: trixie
  target: rootfs
"#;
        let profile: Profile = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(
            profile.isolation,
            IsolationConfig::Chroot(ChrootIsolation {
                privilege: Privilege::None
            })
        ));
    }

    #[test]
    fn test_profile_chroot_isolation() {
        let yaml = r#"
dir: /tmp/rootfs
bootstrap:
  type: mmdebstrap
  suite: trixie
  target: rootfs
isolation:
  type: chroot
  privilege: sudo
"#;
        let profile: Profile = serde_yaml::from_str(yaml).unwrap();
        match profile.isolation {
            IsolationConfig::Chroot(chroot) => {
                assert_eq!(chroot.privilege, Privilege::Sudo);
            }
            _ => panic!("Expected ChrootIsolation"),
        }
    }

    #[test]
    fn test_profile_nspawn_isolation() {
        let yaml = r#"
dir: /tmp/rootfs
bootstrap:
  type: mmdebstrap
  suite: trixie
  target: rootfs
isolation:
  type: nspawn
  privilege: sudo
  quiet: true
  private_network: true
"#;
        let profile: Profile = serde_yaml::from_str(yaml).unwrap();
        match profile.isolation {
            IsolationConfig::Nspawn(nspawn) => {
                assert_eq!(nspawn.privilege, Privilege::Sudo);
                assert!(nspawn.quiet);
                assert!(nspawn.private_network);
            }
            _ => panic!("Expected NspawnIsolation"),
        }
    }

    #[test]
    fn test_profile_bwrap_isolation() {
        let yaml = r#"
dir: /tmp/rootfs
bootstrap:
  type: mmdebstrap
  suite: trixie
  target: rootfs
isolation:
  type: bwrap
  dev: /dev
  proc: /proc
  unshare_net: true
"#;
        let profile: Profile = serde_yaml::from_str(yaml).unwrap();
        match profile.isolation {
            IsolationConfig::Bwrap(bwrap) => {
                assert_eq!(bwrap.dev, Some("/dev".to_string()));
                assert_eq!(bwrap.proc, Some("/proc".to_string()));
                assert!(bwrap.unshare_net);
            }
            _ => panic!("Expected BwrapIsolation"),
        }
    }

    #[test]
    fn test_profile_with_provisioners_and_isolation() {
        let yaml = r#"
dir: /tmp/rootfs
bootstrap:
  type: mmdebstrap
  suite: trixie
  target: rootfs
isolation:
  type: nspawn
  privilege: sudo
provisioners:
  - type: shell
    content: "apt update"
  - type: shell
    content: "apt install nginx"
"#;
        let profile: Profile = serde_yaml::from_str(yaml).unwrap();
        // Isolation is at profile level
        assert!(matches!(profile.isolation, IsolationConfig::Nspawn(_)));
        // Provisioners don't have isolation field
        assert_eq!(profile.provisioners.len(), 2);
    }

    #[test]
    fn test_profile_backward_compatibility_without_isolation() {
        // Old format without isolation should still work (defaults to chroot)
        let yaml = r#"
dir: /tmp/rootfs
bootstrap:
  type: mmdebstrap
  suite: trixie
  target: rootfs
provisioners:
  - type: shell
    content: "echo hello"
"#;
        let profile: Profile = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(
            profile.isolation,
            IsolationConfig::Chroot(ChrootIsolation {
                privilege: Privilege::None
            })
        ));
        assert_eq!(profile.provisioners.len(), 1);
    }
}
