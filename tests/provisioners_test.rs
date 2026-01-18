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
