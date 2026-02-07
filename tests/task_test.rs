use camino::Utf8Path;
use rsdebstrap::RsdebstrapError;
use rsdebstrap::task::{ScriptSource, ShellTask, TaskDefinition};
use tempfile::tempdir;

#[test]
fn test_validate_rejects_empty_shell_path() {
    let task = ShellTask::with_shell(ScriptSource::Content("echo test".to_string()), "");
    let result = task.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("shell path must not be empty"),
        "Expected 'shell path must not be empty', got: {}",
        err_msg
    );
}

#[test]
fn test_validate_rejects_relative_shell_path() {
    let task = ShellTask::with_shell(ScriptSource::Content("echo test".to_string()), "bin/sh");
    let result = task.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("shell path must be absolute"),
        "Expected 'shell path must be absolute', got: {}",
        err_msg
    );
}

#[test]
fn test_validate_rejects_empty_inline_content() {
    let task = ShellTask::new(ScriptSource::Content("".to_string()));
    let result = task.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("inline script content must not be empty"),
        "Expected 'inline script content must not be empty', got: {}",
        err_msg
    );
}

#[test]
fn test_validate_rejects_whitespace_only_inline_content() {
    let task = ShellTask::new(ScriptSource::Content("   \n\t  ".to_string()));
    let result = task.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("inline script content must not be empty"),
        "Expected 'inline script content must not be empty', got: {}",
        err_msg
    );
}

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
    assert_eq!(task.script_path(), Some(camino::Utf8Path::new("test.sh")));
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

// =============================================================================
// T1: TaskDefinition::resolve_paths unit tests
// =============================================================================

#[test]
fn test_resolve_paths_joins_relative_script_with_base_dir() {
    let mut task =
        TaskDefinition::Shell(ShellTask::new(ScriptSource::Script("scripts/test.sh".into())));
    task.resolve_paths(Utf8Path::new("/home/user/project"));

    match &task {
        TaskDefinition::Shell(shell) => {
            assert_eq!(shell.script_path().unwrap().as_str(), "/home/user/project/scripts/test.sh");
        }
    }
}

#[test]
fn test_resolve_paths_preserves_absolute_script_path() {
    let mut task = TaskDefinition::Shell(ShellTask::new(ScriptSource::Script(
        "/absolute/path/test.sh".into(),
    )));
    task.resolve_paths(Utf8Path::new("/home/user/project"));

    match &task {
        TaskDefinition::Shell(shell) => {
            assert_eq!(shell.script_path().unwrap().as_str(), "/absolute/path/test.sh");
        }
    }
}

#[test]
fn test_resolve_paths_does_not_modify_content_source() {
    let mut task =
        TaskDefinition::Shell(ShellTask::new(ScriptSource::Content("echo hello".to_string())));
    task.resolve_paths(Utf8Path::new("/home/user/project"));

    match &task {
        TaskDefinition::Shell(shell) => {
            assert_eq!(shell.script_path(), None);
            assert_eq!(shell.source(), &ScriptSource::Content("echo hello".to_string()));
        }
    }
}

// =============================================================================
// T2: ShellTask direct deserialization tests
// =============================================================================

#[test]
fn test_shell_task_deserialize_script_only() {
    let yaml = r#"script: /path/to/test.sh
"#;
    let task: ShellTask = serde_yaml::from_str(yaml).expect("should parse script-only ShellTask");
    assert_eq!(task.source(), &ScriptSource::Script("/path/to/test.sh".into()));
    assert_eq!(task.shell(), "/bin/sh");
}

#[test]
fn test_shell_task_deserialize_content_only() {
    let yaml = r#"content: echo hello
"#;
    let task: ShellTask = serde_yaml::from_str(yaml).expect("should parse content-only ShellTask");
    assert_eq!(task.source(), &ScriptSource::Content("echo hello".to_string()));
    assert_eq!(task.shell(), "/bin/sh");
}

#[test]
fn test_shell_task_deserialize_with_custom_shell() {
    let yaml = r#"content: echo hello
shell: /bin/bash
"#;
    let task: ShellTask =
        serde_yaml::from_str(yaml).expect("should parse ShellTask with custom shell");
    assert_eq!(task.source(), &ScriptSource::Content("echo hello".to_string()));
    assert_eq!(task.shell(), "/bin/bash");
}

#[test]
fn test_shell_task_deserialize_rejects_both_script_and_content() {
    let yaml = r#"script: /path/to/test.sh
content: echo hello
"#;
    let result: std::result::Result<ShellTask, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("mutually exclusive"),
        "Expected 'mutually exclusive' error, got: {}",
        err_msg
    );
}

#[test]
fn test_shell_task_deserialize_rejects_neither_script_nor_content() {
    let yaml = r#"shell: /bin/bash
"#;
    let result: std::result::Result<ShellTask, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("either 'script' or 'content' must be specified"),
        "Expected 'either script or content' error, got: {}",
        err_msg
    );
}

// =============================================================================
// T3: TaskDefinition YAML deserialization tests
// =============================================================================

#[test]
fn test_task_definition_deserialize_rejects_unknown_type() {
    let yaml = r#"type: ansible
content: echo hello
"#;
    let result: std::result::Result<TaskDefinition, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("unknown variant"),
        "Expected 'unknown variant' error, got: {}",
        err_msg
    );
}

#[test]
fn test_task_definition_deserialize_rejects_missing_type() {
    let yaml = r#"content: echo hello
"#;
    let result: std::result::Result<TaskDefinition, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("missing field") || err_msg.contains("type"),
        "Expected error about missing 'type' field, got: {}",
        err_msg
    );
}

// =============================================================================
// Type-based error tests (RsdebstrapError variant matching)
// =============================================================================

#[test]
fn test_validate_empty_shell_returns_validation_error() {
    let task = ShellTask::with_shell(ScriptSource::Content("echo test".to_string()), "");
    let err = task.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected RsdebstrapError::Validation, got: {:?}",
        err
    );
}

#[test]
fn test_validate_relative_shell_returns_validation_error() {
    let task = ShellTask::with_shell(ScriptSource::Content("echo test".to_string()), "bin/sh");
    let err = task.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected RsdebstrapError::Validation, got: {:?}",
        err
    );
}

#[test]
fn test_validate_empty_content_returns_validation_error() {
    let task = ShellTask::new(ScriptSource::Content("".to_string()));
    let err = task.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected RsdebstrapError::Validation, got: {:?}",
        err
    );
}

#[test]
fn test_validate_path_traversal_returns_validation_error() {
    let task = ShellTask::new(ScriptSource::Script("../../../etc/passwd".into()));
    let err = task.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected RsdebstrapError::Validation, got: {:?}",
        err
    );
}

#[test]
fn test_validate_nonexistent_script_returns_io_error() {
    let script_path = "/nonexistent/path/to/script.sh";
    let task = ShellTask::new(ScriptSource::Script(script_path.into()));
    let err = task.validate().unwrap_err();
    match &err {
        RsdebstrapError::Io {
            context,
            message,
            source,
        } => {
            assert_eq!(
                source.kind(),
                std::io::ErrorKind::NotFound,
                "Expected NotFound IO error kind, got: {:?}",
                source.kind()
            );
            assert!(
                context.contains(script_path),
                "Expected context to contain script path '{}', got: {}",
                script_path,
                context
            );
            assert!(
                message.contains("I/O error"),
                "Expected message to contain 'I/O error', got: {}",
                message
            );
        }
        other => panic!("Expected RsdebstrapError::Io, got: {:?}", other),
    }
}

#[test]
fn test_validate_script_directory_returns_validation_error() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let dir_path = temp_dir.path().join("not_a_script");
    std::fs::create_dir(&dir_path).expect("failed to create directory");
    let task = ShellTask::new(ScriptSource::Script(
        camino::Utf8PathBuf::from_path_buf(dir_path).expect("path should be valid UTF-8"),
    ));
    let err = task.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected RsdebstrapError::Validation, got: {:?}",
        err
    );
}
