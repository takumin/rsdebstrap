use camino::Utf8Path;
use rsdebstrap::RsdebstrapError;
use rsdebstrap::task::{MitamaeTask, ScriptSource, ShellTask, TaskDefinition};
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
        err_msg.contains("inline shell script content must not be empty"),
        "Expected 'inline shell script content must not be empty', got: {}",
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
        err_msg.contains("inline shell script content must not be empty"),
        "Expected 'inline shell script content must not be empty', got: {}",
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
    assert!(err_msg.contains("failed to read shell script metadata:"));
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
    assert!(err_msg.contains("is not a file"));
}

#[cfg(unix)]
#[test]
fn test_validate_script_symlink_rejected() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let real_file = temp_dir.path().join("real_script.sh");
    std::fs::write(&real_file, "#!/bin/sh\necho test\n").expect("failed to write script");
    let symlink_path = temp_dir.path().join("symlink_script.sh");
    std::os::unix::fs::symlink(&real_file, &symlink_path).expect("failed to create symlink");
    let task = ShellTask::new(ScriptSource::Script(
        camino::Utf8PathBuf::from_path_buf(symlink_path).expect("path should be valid UTF-8"),
    ));
    let err = task.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected RsdebstrapError::Validation, got: {:?}",
        err
    );
    let msg = err.to_string();
    assert!(msg.contains("symlink"), "Expected 'symlink' in error, got: {}", msg);
    assert!(
        msg.contains("security reasons"),
        "Expected 'security reasons' in error, got: {}",
        msg
    );
}

#[cfg(unix)]
#[test]
fn test_validate_mitamae_binary_symlink_rejected() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let real_binary = temp_dir.path().join("real_mitamae");
    std::fs::write(&real_binary, "fake binary").expect("failed to write binary");
    let symlink_path = temp_dir.path().join("mitamae_link");
    std::os::unix::fs::symlink(&real_binary, &symlink_path).expect("failed to create symlink");
    let binary_utf8 =
        camino::Utf8PathBuf::from_path_buf(symlink_path).expect("path should be valid UTF-8");
    let task = MitamaeTask::new(ScriptSource::Content("package 'vim'".to_string()), binary_utf8);
    let err = task.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected RsdebstrapError::Validation, got: {:?}",
        err
    );
    let msg = err.to_string();
    assert!(msg.contains("symlink"), "Expected 'symlink' in error, got: {}", msg);
}

#[cfg(unix)]
#[test]
fn test_validate_mitamae_recipe_symlink_rejected() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let real_binary = temp_dir.path().join("mitamae");
    std::fs::write(&real_binary, "fake binary").expect("failed to write binary");
    let binary_utf8 =
        camino::Utf8PathBuf::from_path_buf(real_binary).expect("path should be valid UTF-8");
    let real_recipe = temp_dir.path().join("real_recipe.rb");
    std::fs::write(&real_recipe, "package 'vim'").expect("failed to write recipe");
    let symlink_recipe = temp_dir.path().join("recipe_link.rb");
    std::os::unix::fs::symlink(&real_recipe, &symlink_recipe).expect("failed to create symlink");
    let recipe_utf8 =
        camino::Utf8PathBuf::from_path_buf(symlink_recipe).expect("path should be valid UTF-8");
    let task = MitamaeTask::new(ScriptSource::Script(recipe_utf8), binary_utf8);
    let err = task.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected RsdebstrapError::Validation, got: {:?}",
        err
    );
    let msg = err.to_string();
    assert!(msg.contains("symlink"), "Expected 'symlink' in error, got: {}", msg);
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
        other => panic!("Expected Shell task, got: {:?}", other),
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
        other => panic!("Expected Shell task, got: {:?}", other),
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
        other => panic!("Expected Shell task, got: {:?}", other),
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
        RsdebstrapError::Io { context, source } => {
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
            // Display format includes io_error_kind_message
            let display = err.to_string();
            assert!(
                display.contains("I/O error"),
                "Expected display to contain 'I/O error', got: {}",
                display
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

// =============================================================================
// MitamaeTask deserialization tests
// =============================================================================

#[test]
fn test_task_definition_deserialize_mitamae_with_content() {
    // editorconfig-checker-disable
    let yaml = r#"type: mitamae
binary: /usr/local/bin/mitamae
content: |
  package 'vim' do
    action :install
  end
"#;
    // editorconfig-checker-enable
    let task: TaskDefinition =
        serde_yaml::from_str(yaml).expect("should parse mitamae with content");
    match &task {
        TaskDefinition::Mitamae(m) => {
            assert_eq!(m.binary().unwrap().as_str(), "/usr/local/bin/mitamae");
            assert!(matches!(m.source(), ScriptSource::Content(_)));
        }
        other => panic!("Expected Mitamae task, got: {:?}", other),
    }
}

#[test]
fn test_task_definition_deserialize_mitamae_with_script() {
    // editorconfig-checker-disable
    let yaml = r#"type: mitamae
binary: /usr/local/bin/mitamae
script: ./recipe.rb
"#;
    // editorconfig-checker-enable
    let task: TaskDefinition =
        serde_yaml::from_str(yaml).expect("should parse mitamae with script");
    match &task {
        TaskDefinition::Mitamae(m) => {
            assert_eq!(m.binary().unwrap().as_str(), "/usr/local/bin/mitamae");
            assert_eq!(m.script_path(), Some(Utf8Path::new("./recipe.rb")));
        }
        other => panic!("Expected Mitamae task, got: {:?}", other),
    }
}

#[test]
fn test_task_definition_deserialize_mitamae_without_binary() {
    // editorconfig-checker-disable
    let yaml = r#"type: mitamae
content: echo test
"#;
    // editorconfig-checker-enable
    let task: TaskDefinition =
        serde_yaml::from_str(yaml).expect("should parse mitamae without binary");
    match &task {
        TaskDefinition::Mitamae(m) => {
            assert_eq!(m.binary(), None, "binary should be None when not specified");
            assert!(matches!(m.source(), ScriptSource::Content(_)));
        }
        other => panic!("Expected Mitamae task, got: {:?}", other),
    }
}

#[test]
fn test_task_definition_deserialize_mitamae_rejects_both_script_and_content() {
    // editorconfig-checker-disable
    let yaml = r#"type: mitamae
binary: /usr/local/bin/mitamae
script: ./recipe.rb
content: echo test
"#;
    // editorconfig-checker-enable
    let result: std::result::Result<TaskDefinition, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("mutually exclusive"),
        "Expected 'mutually exclusive' error, got: {}",
        err_msg
    );
}

#[test]
fn test_task_definition_deserialize_mitamae_rejects_neither() {
    // editorconfig-checker-disable
    let yaml = r#"type: mitamae
binary: /usr/local/bin/mitamae
"#;
    // editorconfig-checker-enable
    let result: std::result::Result<TaskDefinition, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("either 'script' or 'content' must be specified"),
        "Expected 'either script or content' error, got: {}",
        err_msg
    );
}

// =============================================================================
// MitamaeTask validation and path tests
// =============================================================================

#[test]
fn test_mitamae_validate_valid_task() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let binary_path = temp_dir.path().join("mitamae");
    std::fs::write(&binary_path, "fake binary").expect("failed to write binary");
    let binary_utf8 =
        camino::Utf8PathBuf::from_path_buf(binary_path).expect("path should be valid UTF-8");

    let task = MitamaeTask::new(ScriptSource::Content("package 'vim'".to_string()), binary_utf8);
    assert!(task.validate().is_ok());
}

#[test]
fn test_mitamae_validate_rejects_empty_binary() {
    let task = MitamaeTask::new(ScriptSource::Content("package 'vim'".to_string()), "".into());
    let err = task.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected Validation error, got: {:?}",
        err
    );
    assert!(err.to_string().contains("must not be empty"));
}

#[test]
fn test_mitamae_validate_rejects_binary_path_traversal() {
    let task = MitamaeTask::new(
        ScriptSource::Content("package 'vim'".to_string()),
        "../../../usr/bin/mitamae".into(),
    );
    let err = task.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected Validation error, got: {:?}",
        err
    );
    assert!(err.to_string().contains(".."));
}

#[test]
fn test_mitamae_validate_rejects_nonexistent_binary() {
    let task = MitamaeTask::new(
        ScriptSource::Content("package 'vim'".to_string()),
        "/nonexistent/mitamae".into(),
    );
    let err = task.validate().unwrap_err();
    assert!(matches!(err, RsdebstrapError::Io { .. }), "Expected Io error, got: {:?}", err);
}

#[test]
fn test_mitamae_validate_rejects_binary_directory() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let dir_path = temp_dir.path().join("not_a_binary");
    std::fs::create_dir(&dir_path).expect("failed to create directory");
    let dir_utf8 =
        camino::Utf8PathBuf::from_path_buf(dir_path).expect("path should be valid UTF-8");

    let task = MitamaeTask::new(ScriptSource::Content("package 'vim'".to_string()), dir_utf8);
    let err = task.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected Validation error, got: {:?}",
        err
    );
    assert!(err.to_string().contains("not a file"));
}

#[test]
fn test_mitamae_validate_rejects_empty_content() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let binary_path = temp_dir.path().join("mitamae");
    std::fs::write(&binary_path, "fake binary").expect("failed to write binary");
    let binary_utf8 =
        camino::Utf8PathBuf::from_path_buf(binary_path).expect("path should be valid UTF-8");

    let task = MitamaeTask::new(ScriptSource::Content("".to_string()), binary_utf8);
    let err = task.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected Validation error, got: {:?}",
        err
    );
    assert!(
        err.to_string()
            .contains("inline mitamae recipe content must not be empty")
    );
}

#[test]
fn test_mitamae_validate_rejects_recipe_path_traversal() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let binary_path = temp_dir.path().join("mitamae");
    std::fs::write(&binary_path, "fake binary").expect("failed to write binary");
    let binary_utf8 =
        camino::Utf8PathBuf::from_path_buf(binary_path).expect("path should be valid UTF-8");

    let task = MitamaeTask::new(ScriptSource::Script("../../../etc/passwd".into()), binary_utf8);
    let err = task.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected Validation error, got: {:?}",
        err
    );
    assert!(err.to_string().contains("mitamae recipe path"));
}

#[test]
fn test_mitamae_validate_rejects_whitespace_only_content() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let binary_path = temp_dir.path().join("mitamae");
    std::fs::write(&binary_path, "fake binary").expect("failed to write binary");
    let binary_utf8 =
        camino::Utf8PathBuf::from_path_buf(binary_path).expect("path should be valid UTF-8");

    let task = MitamaeTask::new(ScriptSource::Content("   \n\t  ".to_string()), binary_utf8);
    let err = task.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected Validation error, got: {:?}",
        err
    );
    assert!(
        err.to_string()
            .contains("inline mitamae recipe content must not be empty")
    );
}

#[test]
fn test_mitamae_resolve_paths_resolves_binary_and_recipe() {
    let mut task =
        MitamaeTask::new(ScriptSource::Script("recipes/default.rb".into()), "bin/mitamae".into());
    task.resolve_paths(Utf8Path::new("/home/user/project"));
    assert_eq!(task.binary().unwrap().as_str(), "/home/user/project/bin/mitamae");
    assert_eq!(task.script_path().unwrap().as_str(), "/home/user/project/recipes/default.rb");
}

#[test]
fn test_mitamae_resolve_paths_preserves_absolute() {
    let mut task = MitamaeTask::new(
        ScriptSource::Script("/abs/recipe.rb".into()),
        "/usr/local/bin/mitamae".into(),
    );
    task.resolve_paths(Utf8Path::new("/home/user/project"));
    assert_eq!(task.binary().unwrap().as_str(), "/usr/local/bin/mitamae");
    assert_eq!(task.script_path().unwrap().as_str(), "/abs/recipe.rb");
}

#[test]
fn test_mitamae_name_inline() {
    let task = MitamaeTask::new(
        ScriptSource::Content("package 'vim'".to_string()),
        "/usr/local/bin/mitamae".into(),
    );
    assert_eq!(task.name(), "<inline>");
}

#[test]
fn test_mitamae_name_script() {
    let task = MitamaeTask::new(
        ScriptSource::Script("/path/to/recipe.rb".into()),
        "/usr/local/bin/mitamae".into(),
    );
    assert_eq!(task.name(), "/path/to/recipe.rb");
}

#[test]
fn test_task_definition_name_shell_prefix() {
    let task =
        TaskDefinition::Shell(ShellTask::new(ScriptSource::Content("echo test".to_string())));
    assert_eq!(task.name().as_ref(), "shell:<inline>");
}

#[test]
fn test_task_definition_name_mitamae_prefix() {
    let task = TaskDefinition::Mitamae(MitamaeTask::new(
        ScriptSource::Content("package 'vim'".to_string()),
        "/usr/local/bin/mitamae".into(),
    ));
    assert_eq!(task.name().as_ref(), "mitamae:<inline>");
}

#[test]
fn test_task_definition_binary_path_shell_none() {
    let task =
        TaskDefinition::Shell(ShellTask::new(ScriptSource::Content("echo test".to_string())));
    assert_eq!(task.binary_path(), None);
}

#[test]
fn test_task_definition_binary_path_mitamae_some() {
    let task = TaskDefinition::Mitamae(MitamaeTask::new(
        ScriptSource::Content("package 'vim'".to_string()),
        "/usr/local/bin/mitamae".into(),
    ));
    assert_eq!(task.binary_path(), Some(Utf8Path::new("/usr/local/bin/mitamae")));
}

// =============================================================================
// ScriptSource method tests
// =============================================================================

#[test]
fn test_script_source_name_returns_path_for_script() {
    let source = ScriptSource::Script("/path/to/script.sh".into());
    assert_eq!(source.name(), "/path/to/script.sh");
}

#[test]
fn test_script_source_name_returns_inline_for_content() {
    let source = ScriptSource::Content("echo test".to_string());
    assert_eq!(source.name(), "<inline>");
}

#[test]
fn test_script_source_script_path_returns_some_for_script() {
    let source = ScriptSource::Script("/path/to/script.sh".into());
    assert_eq!(source.script_path(), Some(Utf8Path::new("/path/to/script.sh")));
}

#[test]
fn test_script_source_script_path_returns_none_for_content() {
    let source = ScriptSource::Content("echo test".to_string());
    assert_eq!(source.script_path(), None);
}

#[test]
fn test_script_source_validate_rejects_path_traversal() {
    let source = ScriptSource::Script("../../../etc/passwd".into());
    let err = source.validate("test script").unwrap_err();
    assert!(matches!(err, RsdebstrapError::Validation(_)));
    let msg = err.to_string();
    assert!(msg.contains(".."), "Expected '..' in error, got: {}", msg);
    assert!(msg.contains("test script"), "Expected label in error, got: {}", msg);
}

#[test]
fn test_script_source_validate_rejects_empty_content() {
    let source = ScriptSource::Content("".to_string());
    let err = source.validate("test script").unwrap_err();
    assert!(matches!(err, RsdebstrapError::Validation(_)));
    let msg = err.to_string();
    assert!(
        msg.contains("must not be empty"),
        "Expected 'must not be empty' in error, got: {}",
        msg
    );
    assert!(msg.contains("test script"), "Expected label in error, got: {}", msg);
}

#[test]
fn test_script_source_validate_accepts_valid_script() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let script_path = temp_dir.path().join("valid.sh");
    std::fs::write(&script_path, "#!/bin/sh\necho ok\n").expect("failed to write script");
    let source = ScriptSource::Script(
        camino::Utf8PathBuf::from_path_buf(script_path).expect("path should be valid UTF-8"),
    );
    assert!(source.validate("test script").is_ok());
}

#[test]
fn test_script_source_validate_accepts_valid_content() {
    let source = ScriptSource::Content("echo test".to_string());
    assert!(source.validate("test script").is_ok());
}

// =============================================================================
// MitamaeTask binary Option tests
// =============================================================================

#[test]
fn test_mitamae_validate_rejects_none_binary() {
    let task = MitamaeTask::new_without_binary(ScriptSource::Content("package 'vim'".to_string()));
    let err = task.validate().unwrap_err();
    assert!(
        matches!(err, RsdebstrapError::Validation(_)),
        "Expected Validation error, got: {:?}",
        err
    );
    let msg = err.to_string();
    assert!(msg.contains("not specified"), "Expected 'not specified' in error, got: {}", msg);
    assert!(
        msg.contains(std::env::consts::ARCH),
        "Expected architecture '{}' in error, got: {}",
        std::env::consts::ARCH,
        msg
    );
}

#[test]
fn test_mitamae_set_binary_if_absent() {
    let mut task =
        MitamaeTask::new_without_binary(ScriptSource::Content("package 'vim'".to_string()));
    assert_eq!(task.binary(), None);
    task.set_binary_if_absent(Utf8Path::new("/usr/local/bin/mitamae"));
    assert_eq!(task.binary(), Some(Utf8Path::new("/usr/local/bin/mitamae")));
}

#[test]
fn test_mitamae_set_binary_if_absent_does_not_override() {
    let mut task = MitamaeTask::new(
        ScriptSource::Content("package 'vim'".to_string()),
        "/usr/local/bin/mitamae-task".into(),
    );
    task.set_binary_if_absent(Utf8Path::new("/usr/local/bin/mitamae-default"));
    assert_eq!(
        task.binary(),
        Some(Utf8Path::new("/usr/local/bin/mitamae-task")),
        "set_binary_if_absent should not override existing binary"
    );
}

#[test]
fn test_mitamae_resolve_paths_with_none_binary() {
    let mut task =
        MitamaeTask::new_without_binary(ScriptSource::Script("recipes/default.rb".into()));
    task.resolve_paths(Utf8Path::new("/home/user/project"));
    assert_eq!(task.binary(), None);
    assert_eq!(task.script_path().unwrap().as_str(), "/home/user/project/recipes/default.rb");
}

#[test]
fn test_task_definition_binary_path_mitamae_none_when_unset() {
    let task = TaskDefinition::Mitamae(MitamaeTask::new_without_binary(ScriptSource::Content(
        "package 'vim'".to_string(),
    )));
    assert_eq!(task.binary_path(), None);
}
