// Tests for the provision-phase apt task (`type: apt`).

mod helpers;

use camino::Utf8Path;
use rsdebstrap::phase::{AptGetTask, ProvisionTask};
use rsdebstrap::privilege::PrivilegeMethod;
use tempfile::tempdir;

use crate::helpers::MockContext;

const APT_GET: [&str; 7] = [
    "/usr/bin/env",
    "DEBIAN_FRONTEND=noninteractive",
    "apt-get",
    "-o",
    "Dpkg::Options::=--force-confdef",
    "-o",
    "Dpkg::Options::=--force-confold",
];

fn apt_get(args: &[&str]) -> Vec<String> {
    APT_GET.iter().chain(args).map(|s| s.to_string()).collect()
}

fn packages(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| s.to_string()).collect()
}

fn parse(yaml: &str) -> AptGetTask {
    match yaml_serde::from_str::<ProvisionTask>(yaml).expect("should parse") {
        ProvisionTask::Apt(task) => task,
        other => panic!("expected apt task, got: {other:?}"),
    }
}

#[test]
fn update_defaults_to_false_and_recommends_to_false() {
    let task = parse("type: apt\ninstall: [curl]\n");
    assert!(!task.update());
    assert!(!task.recommends());
    assert_eq!(task.install(), ["curl"]);
}

#[test]
fn deserialize_rejects_unknown_fields_and_non_string_packages() {
    assert!(yaml_serde::from_str::<ProvisionTask>("type: apt\ninstal: [curl]\n").is_err());
    assert!(yaml_serde::from_str::<ProvisionTask>("type: apt\ninstall: [42]\n").is_err());
}

#[test]
fn update_and_install_run_in_that_order() {
    let temp_dir = tempdir().unwrap();
    let rootfs = Utf8Path::from_path(temp_dir.path()).unwrap();
    let context = MockContext::new(rootfs);

    AptGetTask::new(true, packages(&["docker-ce", "containerd.io"]))
        .execute(&context, Some(PrivilegeMethod::Sudo))
        .expect("should succeed");

    assert_eq!(
        context.executed_commands(),
        [
            apt_get(&["update"]),
            apt_get(&[
                "install",
                "-y",
                "--no-install-recommends",
                "docker-ce",
                "containerd.io"
            ]),
        ]
    );
    assert_eq!(
        context.executed_privileges(),
        [Some(PrivilegeMethod::Sudo), Some(PrivilegeMethod::Sudo)]
    );
}

#[test]
fn install_without_update_does_not_refresh_the_lists() {
    let temp_dir = tempdir().unwrap();
    let rootfs = Utf8Path::from_path(temp_dir.path()).unwrap();
    let context = MockContext::new(rootfs);

    AptGetTask::new(false, packages(&["curl"]))
        .with_recommends(true)
        .execute(&context, None)
        .expect("should succeed");

    assert_eq!(context.executed_commands(), [apt_get(&["install", "-y", "curl"])]);
}

#[test]
fn update_alone_runs_no_install() {
    let temp_dir = tempdir().unwrap();
    let rootfs = Utf8Path::from_path(temp_dir.path()).unwrap();
    let context = MockContext::new(rootfs);

    AptGetTask::new(true, Vec::new())
        .execute(&context, None)
        .expect("should succeed");

    assert_eq!(context.executed_commands(), [apt_get(&["update"])]);
}

// The hint is there for the one mistake the `update: false` default invites: installing
// from a rootfs whose package lists nothing has populated yet.
#[test]
fn a_failed_install_without_update_points_at_the_package_lists() {
    let temp_dir = tempdir().unwrap();
    let rootfs = Utf8Path::from_path(temp_dir.path()).unwrap();
    let context = MockContext::with_failure(rootfs, 100);

    let err = AptGetTask::new(false, packages(&["curl"]))
        .execute(&context, None)
        .unwrap_err();

    let message = format!("{err:#}");
    assert!(message.contains("update: true"), "missing hint: {message}");
    assert!(message.contains("exit status: 100"), "missing cause: {message}");
    assert!(
        err.chain()
            .any(|e| e.downcast_ref::<rsdebstrap::RsdebstrapError>().is_some()),
        "the typed error should survive the hint: {err:?}"
    );
}

#[test]
fn a_failed_update_stops_before_install_and_carries_no_hint() {
    let temp_dir = tempdir().unwrap();
    let rootfs = Utf8Path::from_path(temp_dir.path()).unwrap();
    let context = MockContext::with_failure(rootfs, 100);

    let err = AptGetTask::new(true, packages(&["curl"]))
        .execute(&context, None)
        .unwrap_err();

    assert_eq!(context.executed_commands(), [apt_get(&["update"])]);
    assert!(!format!("{err:#}").contains("update: true"));
}

#[test]
fn dry_run_still_hands_the_commands_to_the_executor() {
    let temp_dir = tempdir().unwrap();
    let rootfs = Utf8Path::from_path(temp_dir.path()).unwrap();
    let context = MockContext::new_dry_run(rootfs);

    AptGetTask::new(true, packages(&["curl"]))
        .execute(&context, None)
        .expect("should succeed");

    assert_eq!(context.executed_commands().len(), 2);
}

#[test]
fn validate_rejects_a_task_that_does_nothing() {
    let err = AptGetTask::new(false, Vec::new()).validate().unwrap_err();
    assert!(err.to_string().contains("update: true"), "{err}");
}

#[test]
fn validate_rejects_an_option_smuggled_in_as_a_package() {
    let err = AptGetTask::new(true, packages(&["curl", "--allow-unauthenticated"]))
        .validate()
        .unwrap_err();
    assert!(err.to_string().contains("--allow-unauthenticated"), "{err}");
}

#[test]
fn validate_rejects_isolation_false() {
    let task = parse("type: apt\nupdate: true\nisolation: false\nprivilege: false\n");
    let err = task.validate().unwrap_err();
    assert!(err.to_string().contains("isolation: false"), "{err}");
}

#[test]
fn profile_with_an_apt_task_loads_and_validates() -> anyhow::Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml(crate::yaml!(
        r#"---
dir: /tmp/test
defaults:
  privilege:
    method: sudo
bootstrap:
  type: mmdebstrap
  suite: trixie
  target: rootfs
  format: directory
provision:
  - type: apt
    update: true
    install: [docker-ce]
    privilege: true
  - type: apt
    install: [containerd.io]
    recommends: true
    privilege: true
"#
    ))?;
    // editorconfig-checker-enable

    profile.validate()?;
    let names: Vec<_> = profile
        .provision
        .iter()
        .map(|t| t.name().into_owned())
        .collect();
    assert_eq!(names, ["apt:update+install", "apt:install"]);
    Ok(())
}
