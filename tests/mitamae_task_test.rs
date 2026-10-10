// Execution tests for MitamaeTask.

mod helpers;

use rsdebstrap::RsdebstrapError;
use rsdebstrap::phase::provision::MitamaePlugin;
use rsdebstrap::phase::{MitamaeTask, ScriptSource};
use tempfile::tempdir;

use crate::helpers::MockContext;

fn setup_rootfs_with_tmp(temp_dir: &tempfile::TempDir) {
    let rootfs = temp_dir.path();
    std::fs::create_dir(rootfs.join("tmp")).expect("failed to create tmp dir");
}

fn create_fake_binary(temp_dir: &tempfile::TempDir) -> camino::Utf8PathBuf {
    let binary_path = temp_dir.path().join("mitamae");
    std::fs::write(&binary_path, "fake mitamae binary").expect("failed to write binary");
    camino::Utf8PathBuf::from_path_buf(binary_path).expect("path should be valid UTF-8")
}

#[test]
fn test_execute_inline_recipe_success() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);

    let task = MitamaeTask::new(
        ScriptSource::Content("package 'vim' do\n  action :install\nend\n".to_string()),
        binary,
    );

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context, None);

    assert!(result.is_ok(), "inline recipe should succeed, got: {:?}", result);

    let commands = context.executed_commands();
    assert_eq!(commands.len(), 1, "Expected exactly one command executed");
    assert_eq!(commands[0].len(), 3, "Expected 3 command elements");

    let binary_arg = &commands[0][0];
    assert!(
        binary_arg.starts_with("/tmp/mitamae-"),
        "Expected binary in /tmp/mitamae-*, got: {}",
        binary_arg
    );
    assert_eq!(commands[0][1], "local");
    let recipe_arg = &commands[0][2];
    assert!(
        recipe_arg.starts_with("/tmp/recipe-") && recipe_arg.ends_with(".rb"),
        "Expected recipe in /tmp/recipe-*.rb, got: {}",
        recipe_arg
    );
}

#[test]
fn test_execute_external_recipe_success() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);

    let recipe_path = temp_dir.path().join("default.rb");
    std::fs::write(&recipe_path, "package 'vim'\n").expect("failed to write recipe");
    let recipe_utf8 =
        camino::Utf8PathBuf::from_path_buf(recipe_path).expect("path should be valid UTF-8");

    let task = MitamaeTask::new(ScriptSource::Script(recipe_utf8), binary);

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context, None);

    assert!(result.is_ok(), "external recipe should succeed, got: {:?}", result);

    let commands = context.executed_commands();
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].len(), 3);
    assert_eq!(commands[0][1], "local");
}

#[test]
fn test_execute_dry_run_skips_file_operations() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    // Do NOT create /tmp - dry_run should skip validation
    let task = MitamaeTask::new(
        ScriptSource::Content("package 'vim'".to_string()),
        "/usr/local/bin/mitamae".into(),
    );

    let context = MockContext::new_dry_run(&rootfs);
    let result = task.execute(&context, None);

    assert!(result.is_ok(), "dry_run should skip validation, got: {:?}", result);

    let commands = context.executed_commands();
    assert_eq!(commands.len(), 1, "Expected exactly one command executed");
    assert_eq!(commands[0].len(), 3);
    let binary_arg = &commands[0][0];
    assert!(
        binary_arg.starts_with("/tmp/mitamae-"),
        "Expected binary path in /tmp, got: {}",
        binary_arg
    );
    assert_eq!(commands[0][1], "local");
}

#[test]
fn test_execute_failure_returns_error() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);

    let task = MitamaeTask::new(ScriptSource::Content("package 'vim'".to_string()), binary);

    let context = MockContext::with_failure(&rootfs, 1);
    let result = task.execute(&context, None);

    assert!(result.is_err());
    let anyhow_err = result.unwrap_err();
    let downcast = anyhow_err.downcast_ref::<RsdebstrapError>();
    assert!(
        downcast.is_some(),
        "Expected RsdebstrapError in error chain, got: {:#}",
        anyhow_err,
    );
    assert!(
        matches!(downcast.unwrap(), RsdebstrapError::Execution { .. }),
        "Expected RsdebstrapError::Execution, got: {:?}",
        downcast.unwrap(),
    );
}

#[test]
fn test_execute_cleans_up_files() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);

    let task = MitamaeTask::new(ScriptSource::Content("package 'vim'".to_string()), binary);

    let context = MockContext::new(&rootfs);
    task.execute(&context, None)
        .expect("execute should succeed");

    // Verify temp files were cleaned up by TempFileGuard (RAII)
    let tmp_dir = temp_dir.path().join("tmp");
    let remaining: Vec<_> = std::fs::read_dir(&tmp_dir)
        .expect("failed to read tmp dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_str().unwrap().to_string();
            name.starts_with("mitamae-") || name.starts_with("recipe-")
        })
        .collect();
    assert!(
        remaining.is_empty(),
        "Expected temp files to be cleaned up, but found: {:?}",
        remaining.iter().map(|e| e.file_name()).collect::<Vec<_>>()
    );
}

#[test]
fn test_execute_fails_when_context_execute_errors() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);

    let task = MitamaeTask::new(ScriptSource::Content("package 'vim'".to_string()), binary);

    let context = MockContext::with_error(&rootfs, "connection to isolation backend lost");
    let result = task.execute(&context, None);

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("connection to isolation backend lost"),
        "Expected error message to contain 'connection to isolation backend lost', got: {}",
        err_msg
    );
}

#[test]
fn test_execute_with_no_exit_status_returns_error() {
    // When a process returns no exit status in non-dry-run mode (e.g., killed by signal),
    // this should be treated as an error rather than silently succeeding.
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    setup_rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);

    let task = MitamaeTask::new(ScriptSource::Content("package 'vim'".to_string()), binary);

    let context = MockContext::with_no_status(&rootfs);
    let result = task.execute(&context, None);

    assert!(result.is_err(), "status: None should be treated as error");
    let anyhow_err = result.unwrap_err();
    let downcast = anyhow_err.downcast_ref::<RsdebstrapError>();
    assert!(
        downcast.is_some(),
        "Expected RsdebstrapError in error chain, got: {:#}",
        anyhow_err,
    );
    assert!(
        matches!(downcast.unwrap(), RsdebstrapError::Execution { .. }),
        "Expected RsdebstrapError::Execution, got: {:?}",
        downcast.unwrap(),
    );
    let err_msg = format!("{}", anyhow_err);
    assert!(
        err_msg.contains("process exited without status"),
        "Expected 'process exited without status' in error, got: {}",
        err_msg,
    );
}

#[test]
fn test_execute_without_tmp_directory() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf())
        .expect("path should be valid UTF-8");

    // Do NOT create /tmp
    let binary = create_fake_binary(&temp_dir);

    let task = MitamaeTask::new(ScriptSource::Content("package 'vim'".to_string()), binary);

    let context = MockContext::new(&rootfs);
    let result = task.execute(&context, None);

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("/tmp directory not found"),
        "Expected '/tmp directory not found' in error, got: {}",
        err_msg
    );
}

fn write_host_file(path: &std::path::Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).expect("failed to create parent dir");
    std::fs::write(path, content).expect("failed to write file");
}

fn utf8(path: std::path::PathBuf) -> camino::Utf8PathBuf {
    camino::Utf8PathBuf::from_path_buf(path).expect("path should be valid UTF-8")
}

// A resource plugin checkout, carrying the things a checkout has that mitamae never reads.
fn create_resource_plugin(temp_dir: &tempfile::TempDir) -> camino::Utf8PathBuf {
    let plugin = temp_dir
        .path()
        .join("plugins/mitamae-plugin-resource-sample");
    write_host_file(
        &plugin.join("mrblib/mitamae/plugin/resource/sample.rb"),
        "module MItamae; end\n",
    );
    write_host_file(&plugin.join(".git/HEAD"), "ref: refs/heads/main\n");
    write_host_file(&plugin.join("README.md"), "# sample\n");
    utf8(plugin)
}

// A recipe plugin under the `itamae-` prefix mitamae also accepts, with a template next to
// its recipe.
fn create_recipe_plugin(temp_dir: &tempfile::TempDir) -> camino::Utf8PathBuf {
    let plugin = temp_dir.path().join("plugins/itamae-plugin-recipe-thing");
    write_host_file(
        &plugin.join("mrblib/itamae/plugin/recipe/thing/default.rb"),
        "template '/etc/thing'\n",
    );
    write_host_file(
        &plugin.join("mrblib/itamae/plugin/recipe/thing/templates/etc/thing"),
        "thing\n",
    );
    utf8(plugin)
}

fn rootfs_with_tmp(temp_dir: &tempfile::TempDir) -> camino::Utf8PathBuf {
    let rootfs = temp_dir.path().join("rootfs");
    std::fs::create_dir_all(rootfs.join("tmp")).expect("failed to create tmp dir");
    utf8(rootfs)
}

fn tmp_entries(rootfs: &camino::Utf8Path) -> Vec<std::ffi::OsString> {
    std::fs::read_dir(rootfs.join("tmp"))
        .expect("failed to read tmp dir")
        .map(|e| e.unwrap().file_name())
        .collect()
}

// The tree the probe saw under the staged plugins directory, as (path, mode, content).
fn staged_plugins(context: &MockContext, plugins_arg: &str) -> Vec<(String, u32, Option<String>)> {
    let staged_name = plugins_arg
        .strip_prefix("--plugins=/tmp/")
        .unwrap_or_else(|| panic!("expected a --plugins=/tmp/... option, got: {}", plugins_arg));
    context.tree_probed()[0]
        .iter()
        .filter_map(|e| {
            let rel = e.path.strip_prefix(staged_name)?;
            let content = e
                .content
                .as_ref()
                .map(|c| String::from_utf8(c.clone()).unwrap());
            Some((rel.to_string(), e.mode, content))
        })
        .collect()
}

fn dir(path: &str) -> (String, u32, Option<String>) {
    (path.to_string(), 0o700, None)
}

fn file(path: &str, content: &str) -> (String, u32, Option<String>) {
    (path.to_string(), 0o600, Some(content.to_string()))
}

#[test]
fn test_execute_stages_path_plugins_and_passes_plugins_option() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);
    let resource = create_resource_plugin(&temp_dir);
    let recipe = create_recipe_plugin(&temp_dir);

    let task = MitamaeTask::new(ScriptSource::Content("include_recipe 'thing'".into()), binary)
        .with_plugins(vec![MitamaePlugin::path(resource), MitamaePlugin::path(recipe)]);
    task.validate().expect("plugins should validate");

    let context = MockContext::new(&rootfs).with_tree_probe("/tmp");
    task.execute(&context, None)
        .expect("execute should succeed");

    let commands = context.executed_commands();
    assert_eq!(commands.len(), 1);
    let command = &commands[0];
    assert_eq!(command.len(), 4, "expected binary, local, --plugins, recipe: {:?}", command);
    assert_eq!(command[1], "local");
    assert!(command[3].starts_with("/tmp/recipe-"), "recipe must stay last: {:?}", command);

    // Only each plugin's `mrblib`, under the plugin's own name: no `.git`, no README.
    assert_eq!(
        staged_plugins(&context, &command[2]),
        vec![
            dir(""),
            dir("/itamae-plugin-recipe-thing"),
            dir("/itamae-plugin-recipe-thing/mrblib"),
            dir("/itamae-plugin-recipe-thing/mrblib/itamae"),
            dir("/itamae-plugin-recipe-thing/mrblib/itamae/plugin"),
            dir("/itamae-plugin-recipe-thing/mrblib/itamae/plugin/recipe"),
            dir("/itamae-plugin-recipe-thing/mrblib/itamae/plugin/recipe/thing"),
            file(
                "/itamae-plugin-recipe-thing/mrblib/itamae/plugin/recipe/thing/default.rb",
                "template '/etc/thing'\n"
            ),
            dir("/itamae-plugin-recipe-thing/mrblib/itamae/plugin/recipe/thing/templates"),
            dir("/itamae-plugin-recipe-thing/mrblib/itamae/plugin/recipe/thing/templates/etc"),
            file(
                "/itamae-plugin-recipe-thing/mrblib/itamae/plugin/recipe/thing/templates/etc/thing",
                "thing\n"
            ),
            dir("/mitamae-plugin-resource-sample"),
            dir("/mitamae-plugin-resource-sample/mrblib"),
            dir("/mitamae-plugin-resource-sample/mrblib/mitamae"),
            dir("/mitamae-plugin-resource-sample/mrblib/mitamae/plugin"),
            dir("/mitamae-plugin-resource-sample/mrblib/mitamae/plugin/resource"),
            file(
                "/mitamae-plugin-resource-sample/mrblib/mitamae/plugin/resource/sample.rb",
                "module MItamae; end\n"
            ),
        ]
    );

    let remaining = tmp_entries(&rootfs);
    assert!(remaining.is_empty(), "staged files must be cleaned up, found: {:?}", remaining);
}

#[test]
fn test_execute_stages_plugin_under_its_declared_name() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);
    let resource = create_resource_plugin(&temp_dir);

    let task = MitamaeTask::new(ScriptSource::Content("x".into()), binary).with_plugins(vec![
        MitamaePlugin::path(resource).with_name("mitamae-plugin-resource-renamed"),
    ]);
    let context = MockContext::new(&rootfs).with_tree_probe("/tmp");
    task.execute(&context, None)
        .expect("execute should succeed");

    let staged = staged_plugins(&context, &context.executed_commands()[0][2]);
    assert_eq!(staged[1], dir("/mitamae-plugin-resource-renamed"), "{:?}", staged);
}

#[test]
fn test_execute_cleans_up_plugins_when_mitamae_fails() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);
    let resource = create_resource_plugin(&temp_dir);

    let task = MitamaeTask::new(ScriptSource::Content("package 'vim'".into()), binary)
        .with_plugins(vec![MitamaePlugin::path(resource)]);

    let context = MockContext::with_failure(&rootfs, 1).with_tree_probe("/tmp");
    assert!(task.execute(&context, None).is_err());

    assert!(
        context.tree_probed()[0]
            .iter()
            .any(|e| e.path.starts_with("mitamae-plugins-")),
        "plugins should have been staged while mitamae ran"
    );
    let remaining = tmp_entries(&rootfs);
    assert!(remaining.is_empty(), "staged files must be cleaned up, found: {:?}", remaining);
}

#[test]
fn test_execute_with_empty_plugin_list_passes_no_plugins_option() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);

    let task = MitamaeTask::new(ScriptSource::Content("x".into()), binary).with_plugins(vec![]);
    let context = MockContext::new(&rootfs);
    task.execute(&context, None)
        .expect("execute should succeed");

    assert_eq!(context.executed_commands()[0].len(), 3, "{:?}", context.executed_commands());
}

#[test]
fn test_execute_dry_run_passes_plugins_option_without_staging() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = utf8(temp_dir.path().to_path_buf());

    let task = MitamaeTask::new(
        ScriptSource::Content("package 'vim'".to_string()),
        "/usr/local/bin/mitamae".into(),
    )
    .with_plugins(vec![MitamaePlugin::path(
        "/nonexistent/mitamae-plugin-resource-x",
    )]);

    let context = MockContext::new_dry_run(&rootfs);
    task.execute(&context, None)
        .expect("dry run should not read the plugins");

    let commands = context.executed_commands();
    assert!(
        commands[0][2].starts_with("--plugins=/tmp/mitamae-plugins-"),
        "got: {:?}",
        commands[0]
    );
    assert!(!rootfs.join("tmp").exists(), "dry run must not stage anything");
}

fn git(repo: &std::path::Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "user.name=test", "-c", "user.email=test@example.com"])
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .output()
        .expect("git must be installed to run this test");
    assert!(
        output.status.success(),
        "git {:?}: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

// A local repository with two commits, the first of which is no longer a branch tip, so
// that fetching it exercises the fallback for servers that refuse a `want` by object ID.
//
// `validate` refuses a local path as a git URL -- `path:` is the way to name one -- so these
// tests go through `execute`, which stages what `validate` would have fetched. That is the
// same fetch, without standing up a server.
fn create_git_plugin(temp_dir: &tempfile::TempDir) -> (camino::Utf8PathBuf, String, String) {
    let repo = temp_dir.path().join("mitamae-plugin-resource-remote");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "--quiet"]);
    write_host_file(&repo.join("mrblib/remote.rb"), "first\n");
    write_host_file(&repo.join("spec/remote_spec.rb"), "spec\n");
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "--quiet", "-m", "first"]);
    let first = git(&repo, &["rev-parse", "HEAD"]);
    write_host_file(&repo.join("mrblib/remote.rb"), "second\n");
    git(&repo, &["commit", "--quiet", "-am", "second"]);
    let second = git(&repo, &["rev-parse", "HEAD"]);
    (utf8(repo), first, second)
}

#[test]
fn test_execute_stages_git_plugin_at_the_pinned_commit() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);
    let (repo, first, second) = create_git_plugin(&temp_dir);

    for (commit, content) in [(&second, "second\n"), (&first, "first\n")] {
        let task = MitamaeTask::new(ScriptSource::Content("x".into()), binary.clone())
            .with_plugins(vec![MitamaePlugin::git(repo.as_str(), commit.as_str())]);
        let context = MockContext::new(&rootfs).with_tree_probe("/tmp");
        task.execute(&context, None)
            .unwrap_or_else(|e| panic!("execute at {} should succeed: {:#}", commit, e));

        assert_eq!(
            staged_plugins(&context, &context.executed_commands()[0][2]),
            vec![
                dir(""),
                dir("/mitamae-plugin-resource-remote"),
                dir("/mitamae-plugin-resource-remote/mrblib"),
                file("/mitamae-plugin-resource-remote/mrblib/remote.rb", content),
            ],
            "at commit {}",
            commit
        );
    }
}

#[test]
fn test_execute_fails_for_git_commit_not_in_repository() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let rootfs = rootfs_with_tmp(&temp_dir);
    let binary = create_fake_binary(&temp_dir);
    let (repo, _, _) = create_git_plugin(&temp_dir);

    let task = MitamaeTask::new(ScriptSource::Content("x".into()), binary).with_plugins(vec![
        MitamaePlugin::git(repo.as_str(), "0123456789abcdef0123456789abcdef01234567"),
    ]);
    let context = MockContext::new(&rootfs);
    let err = format!("{:#}", task.execute(&context, None).unwrap_err());
    assert!(err.contains("commit not found"), "got: {}", err);
    assert!(context.executed_commands().is_empty(), "mitamae must not run");
    let remaining = tmp_entries(&rootfs);
    assert!(remaining.is_empty(), "staged files must be cleaned up, found: {:?}", remaining);
}

fn validation_message(task: &MitamaeTask) -> String {
    match task.validate().unwrap_err() {
        RsdebstrapError::Validation(message) => message,
        other => panic!("expected a validation error, got: {:?}", other),
    }
}

fn task_with(temp_dir: &tempfile::TempDir, plugins: Vec<MitamaePlugin>) -> MitamaeTask {
    MitamaeTask::new(ScriptSource::Content("x".into()), create_fake_binary(temp_dir))
        .with_plugins(plugins)
}

#[test]
fn test_validate_rejects_symlink_inside_plugin() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let resource = create_resource_plugin(&temp_dir);
    std::os::unix::fs::symlink("/etc/passwd", resource.join("mrblib/passwd.rb"))
        .expect("failed to create symlink");

    let message = validation_message(&task_with(&temp_dir, vec![MitamaePlugin::path(resource)]));
    assert!(message.contains("passwd.rb") && message.contains("symlink"), "got: {}", message);
}

#[test]
fn test_validate_rejects_symlinked_plugin_directory() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let resource = create_resource_plugin(&temp_dir);
    let linked = resource.with_file_name("mitamae-plugin-resource-linked");
    std::os::unix::fs::symlink(&resource, &linked).expect("failed to create symlink");

    let message = validation_message(&task_with(&temp_dir, vec![MitamaePlugin::path(linked)]));
    assert!(message.contains("symlink"), "got: {}", message);
}

#[test]
fn test_validate_rejects_plugin_without_mrblib() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let plugin = temp_dir.path().join("mitamae-plugin-resource-empty");
    write_host_file(&plugin.join("README.md"), "# empty\n");

    let message =
        validation_message(&task_with(&temp_dir, vec![MitamaePlugin::path(utf8(plugin))]));
    assert!(message.contains("mrblib"), "got: {}", message);
}

#[test]
fn test_validate_rejects_missing_or_non_directory_plugin() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let missing = utf8(temp_dir.path().join("mitamae-plugin-resource-missing"));
    assert!(
        task_with(&temp_dir, vec![MitamaePlugin::path(missing)])
            .validate()
            .is_err()
    );

    let not_dir = temp_dir.path().join("mitamae-plugin-resource-file");
    write_host_file(&not_dir, "not a directory\n");
    let message =
        validation_message(&task_with(&temp_dir, vec![MitamaePlugin::path(utf8(not_dir))]));
    assert!(message.contains("not a directory"), "got: {}", message);
}

#[test]
fn test_validate_rejects_names_mitamae_would_not_load() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let resource = create_resource_plugin(&temp_dir);

    let message = validation_message(&task_with(
        &temp_dir,
        vec![MitamaePlugin::path(resource).with_name("docker")],
    ));
    assert!(message.contains("'docker'"), "got: {}", message);
}

#[test]
fn test_validate_rejects_duplicate_plugin_names() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let resource = create_resource_plugin(&temp_dir);

    let message = validation_message(&task_with(
        &temp_dir,
        vec![
            MitamaePlugin::path(resource.clone()),
            MitamaePlugin::path(resource),
        ],
    ));
    assert!(message.contains("more than once"), "got: {}", message);
}

#[test]
fn test_validate_rejects_unpinned_or_local_git_sources() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let cases = [
        ("https://example.com/mitamae-plugin-resource-x.git", "0123abc", "full commit ID"),
        ("/srv/git/mitamae-plugin-resource-x.git", commit, "git URL"),
        ("file:///srv/git/mitamae-plugin-resource-x.git", commit, "git URL"),
        ("ext::sh -c touch% /tmp/pwned", commit, "git URL"),
        ("-uhttps://example.com/mitamae-plugin-resource-x", commit, "git URL"),
    ];
    for (url, commit, expected) in cases {
        let task = task_with(
            &temp_dir,
            vec![MitamaePlugin::git(url, commit).with_name("mitamae-plugin-resource-x")],
        );
        let message = validation_message(&task);
        assert!(message.contains(expected), "{}: got: {}", url, message);
    }
}

#[test]
fn test_validate_rejects_non_https_or_malformed_archive_sources() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let sha256 = "0".repeat(64);
    let cases = [
        ("http://example.com/mitamae-plugin-resource-x.tar.gz", sha256.as_str(), "https"),
        ("https://example.com/mitamae-plugin-resource-x.tar.gz", "abc", "64 hex digits"),
    ];
    for (url, sha256, expected) in cases {
        let message =
            validation_message(&task_with(&temp_dir, vec![MitamaePlugin::archive(url, sha256)]));
        assert!(message.contains(expected), "{}: got: {}", url, message);
    }
}

#[test]
fn test_plugin_names_are_derived_from_their_source() {
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let sha256 = "0".repeat(64);
    let cases = [
        (
            MitamaePlugin::path("./plugins/mitamae-plugin-recipe-docker"),
            "mitamae-plugin-recipe-docker",
        ),
        (
            MitamaePlugin::git(
                "https://github.com/takumin/mitamae-plugin-resource-apt_repository.git",
                commit,
            ),
            "mitamae-plugin-resource-apt_repository",
        ),
        (
            MitamaePlugin::git("git@github.com:takumin/mitamae-plugin-resource-x.git", commit),
            "mitamae-plugin-resource-x",
        ),
        (
            MitamaePlugin::archive(
                concat!(
                    "https://github.com/takumin/mitamae-plugin-resource-apt_keyring",
                    "/archive/5217372e85df6c94f0a1dec05c7739114b35d570.tar.gz",
                ),
                &sha256,
            ),
            "mitamae-plugin-resource-apt_keyring",
        ),
        (
            MitamaePlugin::archive(
                concat!(
                    "https://gitlab.com/group/mitamae-plugin-recipe-y",
                    "/-/archive/v1/mitamae-plugin-recipe-y-v1.tar.gz",
                ),
                &sha256,
            ),
            "mitamae-plugin-recipe-y",
        ),
        (
            MitamaePlugin::archive("https://example.com/dl/mitamae-plugin-resource-z.tgz", &sha256),
            "mitamae-plugin-resource-z",
        ),
    ];
    for (plugin, expected) in cases {
        assert_eq!(plugin.name().expect("name should derive"), expected, "{:?}", plugin);
    }
}
