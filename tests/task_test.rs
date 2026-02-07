use rsdebstrap::task::{ScriptSource, ShellTask};
use tempfile::tempdir;

#[test]
fn test_validate_script_only() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let script_path = temp_dir.path().join("test.sh");
    std::fs::write(&script_path, "#!/bin/sh\necho test\n").expect("failed to write script");
    let task = ShellTask::new(ScriptSource::Script(
        camino::Utf8PathBuf::from_path_buf(script_path).expect("script path should be valid UTF-8"),
    ));
    assert!(task.validate().is_ok());
}

#[test]
fn test_validate_content_only() {
    let task = ShellTask::new(ScriptSource::Content("echo test".to_string()));
    assert!(task.validate().is_ok());
}

#[test]
fn test_script_source_external() {
    let task = ShellTask::new(ScriptSource::Script("test.sh".into()));
    assert_eq!(task.name(), "test.sh");
}

#[test]
fn test_script_source_inline() {
    let task = ShellTask::new(ScriptSource::Content("echo test".to_string()));
    assert_eq!(task.name(), "<inline>");
}

#[test]
fn test_script_path_returns_some_for_script() {
    let task = ShellTask::new(ScriptSource::Script("test.sh".into()));
    assert_eq!(task.script_path(), Some(&camino::Utf8PathBuf::from("test.sh")));
}

#[test]
fn test_script_path_returns_none_for_content() {
    let task = ShellTask::new(ScriptSource::Content("echo test".to_string()));
    assert_eq!(task.script_path(), None);
}

#[test]
fn test_validate_nonexistent_script() {
    let task = ShellTask::new(ScriptSource::Script("/nonexistent/path/to/script.sh".into()));
    let result = task.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("failed to read shell script metadata"));
}

#[test]
fn test_validate_script_is_directory() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let dir_path = temp_dir.path().join("not_a_script");
    std::fs::create_dir(&dir_path).expect("failed to create directory");
    let task = ShellTask::new(ScriptSource::Script(
        camino::Utf8PathBuf::from_path_buf(dir_path).expect("path should be valid UTF-8"),
    ));
    let result = task.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("shell script is not a file"));
}
