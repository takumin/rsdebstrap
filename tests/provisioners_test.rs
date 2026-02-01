use rsdebstrap::provisioners::shell::{ScriptSource, ShellProvisioner};
use tempfile::tempdir;

fn default_shell() -> String {
    "/bin/sh".to_string()
}

#[test]
fn test_validate_script_only() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let script_path = temp_dir.path().join("test.sh");
    std::fs::write(&script_path, "#!/bin/sh\necho test\n").expect("failed to write script");
    let provisioner = ShellProvisioner {
        source: ScriptSource::Script(
            camino::Utf8PathBuf::from_path_buf(script_path)
                .expect("script path should be valid UTF-8"),
        ),
        shell: default_shell(),
    };
    assert!(provisioner.validate().is_ok());
}

#[test]
fn test_validate_content_only() {
    let provisioner = ShellProvisioner {
        source: ScriptSource::Content("echo test".to_string()),
        shell: default_shell(),
    };
    assert!(provisioner.validate().is_ok());
}

#[test]
fn test_script_source_external() {
    let provisioner = ShellProvisioner {
        source: ScriptSource::Script("test.sh".into()),
        shell: default_shell(),
    };
    assert_eq!(provisioner.script_source(), "test.sh");
}

#[test]
fn test_script_source_inline() {
    let provisioner = ShellProvisioner {
        source: ScriptSource::Content("echo test".to_string()),
        shell: default_shell(),
    };
    assert_eq!(provisioner.script_source(), "<inline>");
}

#[test]
fn test_script_path_returns_some_for_script() {
    let provisioner = ShellProvisioner {
        source: ScriptSource::Script("test.sh".into()),
        shell: default_shell(),
    };
    assert_eq!(provisioner.script_path(), Some(&camino::Utf8PathBuf::from("test.sh")));
}

#[test]
fn test_script_path_returns_none_for_content() {
    let provisioner = ShellProvisioner {
        source: ScriptSource::Content("echo test".to_string()),
        shell: default_shell(),
    };
    assert_eq!(provisioner.script_path(), None);
}
