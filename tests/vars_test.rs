mod helpers;

use std::collections::BTreeMap;

use anyhow::Result;
use rsdebstrap::RsdebstrapError;
use rsdebstrap::bootstrap::mmdebstrap::Variant;
use rsdebstrap::phase::assemble::AssetSource;
use rsdebstrap::phase::{ProvisionTask, ScriptSource};
use rsdebstrap::vars::VarOverrides;

fn overrides(env: &[(&str, &str)], cli: &[(&str, &str)]) -> VarOverrides {
    let owned = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    };
    VarOverrides::new(owned(env), owned(cli)).expect("well-formed overrides")
}

fn config_error(err: RsdebstrapError) -> String {
    match err {
        RsdebstrapError::Config(msg) => msg,
        other => panic!("expected a config error, got {other:?}"),
    }
}

// editorconfig-checker-disable
const PROFILE: &str = r#"---
vars:
  distrib: debian
  suite: trixie
  arch: amd64
  variant: apt
dir: /tmp/${{ vars.distrib }}-${{ vars.suite }}-${{ vars.arch }}
bootstrap:
  type: mmdebstrap
  suite: ${{ vars.suite }}
  target: rootfs
  variant: ${{ vars.variant }}
  architectures: ['${{ vars.arch }}']
  include: [ca-certificates, 'linux-image-${{ vars.arch }}']
prepare:
  apt:
    repositories:
    - name: ${{ vars.distrib }}
      sources:
      - uris: [https://deb.debian.org/debian]
        suites: ['${{ vars.suite }}', '${{ vars.suite }}-updates']
        components: [main]
assemble:
  output:
    assets:
    - file: build-info
      content: "${{ vars.distrib }} ${{ vars.suite }}\n"
"#;
// editorconfig-checker-enable

#[test]
fn references_are_substituted_throughout_the_profile() -> Result<()> {
    let profile = helpers::load_profile_from_yaml_with_vars(PROFILE, &VarOverrides::default())?;

    assert_eq!(profile.dir, "/tmp/debian-trixie-amd64");
    let cfg = helpers::get_mmdebstrap_config(&profile).expect("expected mmdebstrap config");
    assert_eq!(cfg.suite, "trixie");
    // An enum-valued field is spelled by a string in YAML, so it can be a reference too.
    assert_eq!(cfg.variant, Variant::Apt);
    assert_eq!(cfg.architectures, ["amd64"]);
    assert_eq!(cfg.include, ["ca-certificates", "linux-image-amd64"]);

    let apt = profile.prepare.apt.as_ref().expect("prepare.apt");
    assert_eq!(apt.repositories[0].name, "debian");
    assert_eq!(apt.repositories[0].sources[0].suites, ["trixie", "trixie-updates"]);

    // An asset's inline content is a file, not a script, so it is substituted.
    match &profile.assemble.output.assets[0].source {
        AssetSource::Content(content) => assert_eq!(content, "debian trixie\n"),
        other => panic!("expected a content asset, got {other:?}"),
    }
    Ok(())
}

#[test]
fn overrides_replace_declared_values_before_substitution() -> Result<()> {
    let profile = helpers::load_profile_from_yaml_with_vars(
        PROFILE,
        &overrides(
            &[
                ("RSDEBSTRAP_VAR_SUITE", "forky"),
                ("RSDEBSTRAP_VAR_ARCH", "arm64"),
            ],
            &[("arch", "riscv64")],
        ),
    )?;

    assert_eq!(profile.dir, "/tmp/debian-forky-riscv64");
    let cfg = helpers::get_mmdebstrap_config(&profile).expect("expected mmdebstrap config");
    assert_eq!(cfg.include, ["ca-certificates", "linux-image-riscv64"]);

    let expected: BTreeMap<String, String> = [
        ("arch", "riscv64"),
        ("distrib", "debian"),
        ("suite", "forky"),
        ("variant", "apt"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    assert_eq!(profile.vars, expected);
    Ok(())
}

#[test]
fn overriding_an_undeclared_variable_fails_the_load() {
    let err = helpers::load_profile_from_yaml_with_vars(
        PROFILE,
        &overrides(&[("RSDEBSTRAP_VAR_ROLE", "server")], &[]),
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("RSDEBSTRAP_VAR_ROLE"), "{msg}");
    assert!(msg.contains("declared: arch, distrib, suite, variant"), "{msg}");
}

#[test]
fn a_provision_tasks_inline_content_is_left_verbatim() -> Result<()> {
    // The script references the variable through the same syntax on purpose: it must reach
    // the rootfs unchanged, while the sibling `shell` key is still substituted.
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml_with_vars(
        crate::yaml!(
            r#"---
vars:
  shell: /bin/bash
dir: /tmp/rootfs
bootstrap:
  type: mmdebstrap
  suite: trixie
  target: rootfs
provision:
- type: shell
  shell: ${{ vars.shell }}
  content: |
    echo "${{ vars.shell }}"
"#
        ),
        &VarOverrides::default(),
    )?;
    // editorconfig-checker-enable

    match profile.provision.as_slice() {
        [ProvisionTask::Shell(shell)] => {
            assert_eq!(shell.shell(), "/bin/bash");
            match shell.source() {
                ScriptSource::Content(content) => {
                    assert_eq!(content, "echo \"${{ vars.shell }}\"\n")
                }
                other => panic!("expected inline content, got {other:?}"),
            }
        }
        other => panic!("expected one shell task, got {other:?}"),
    }
    Ok(())
}

#[test]
fn a_provision_tasks_script_path_is_substituted() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml_with_vars(
        crate::yaml!(
            r#"---
vars:
  role: server
dir: /tmp/rootfs
bootstrap:
  type: mmdebstrap
  suite: trixie
  target: rootfs
provision:
- type: shell
  script: /srv/roles/${{ vars.role }}.sh
"#
        ),
        &overrides(&[], &[("role", "desktop")]),
    )?;
    // editorconfig-checker-enable

    match profile.provision.as_slice() {
        [ProvisionTask::Shell(shell)] => {
            assert_eq!(shell.script_path().unwrap(), "/srv/roles/desktop.sh")
        }
        other => panic!("expected one shell task, got {other:?}"),
    }
    Ok(())
}

#[test]
fn declared_values_are_not_expanded_against_each_other() -> Result<()> {
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml_with_vars(
        crate::yaml!(
            r#"---
vars:
  a: x
  b: ${{ vars.a }}
dir: /tmp/${{ vars.b }}
bootstrap:
  type: mmdebstrap
  suite: trixie
  target: rootfs
"#
        ),
        &VarOverrides::default(),
    )?;
    // editorconfig-checker-enable

    assert_eq!(profile.dir, "/tmp/${{ vars.a }}");
    Ok(())
}

#[test]
fn an_undefined_reference_reports_the_field_and_line() {
    // editorconfig-checker-disable
    let err = helpers::load_profile_from_yaml_with_vars(
        crate::yaml!(
            r#"---
vars:
  suite: trixie
dir: /tmp/rootfs
bootstrap:
  type: mmdebstrap
  suite: ${{ vars.suit }}
  target: rootfs
"#
        ),
        &VarOverrides::default(),
    )
    .unwrap_err();
    // editorconfig-checker-enable

    let msg = config_error(err);
    assert!(msg.contains("undefined variable `suit`"), "{msg}");
    assert!(msg.contains("declared: suite"), "{msg}");
    assert!(msg.contains("line 7"), "{msg}");
}

#[test]
fn a_reference_in_a_profile_without_vars_is_an_error() {
    // editorconfig-checker-disable
    let err = helpers::load_profile_from_yaml_with_vars(
        crate::yaml!(
            r#"---
dir: /tmp/${{ vars.suite }}
bootstrap:
  type: mmdebstrap
  suite: trixie
  target: rootfs
"#
        ),
        &VarOverrides::default(),
    )
    .unwrap_err();
    // editorconfig-checker-enable

    let msg = config_error(err);
    assert!(msg.contains("it declares none"), "{msg}");
    assert!(msg.contains("at `dir`"), "{msg}");
}

const MINIMAL_BODY: &str =
    "dir: /tmp/rootfs\nbootstrap:\n  type: mmdebstrap\n  suite: trixie\n  target: rootfs\n";

#[test]
fn variable_declarations_are_checked() {
    for (vars, needle) in [
        ("  Suite: trixie", "invalid variable name \"Suite\""),
        ("  kernel-flavor: amd64", "invalid variable name \"kernel-flavor\""),
        // Quoting keeps a version a string; a bare number is rejected like any other
        // string field.
        ("  version: 13", "expected a string"),
    ] {
        let yaml = format!("vars:\n{vars}\n{MINIMAL_BODY}");
        let msg = config_error(
            helpers::load_profile_from_yaml_with_vars(yaml, &VarOverrides::default()).unwrap_err(),
        );
        assert!(msg.contains(needle), "{needle}: {msg}");
        assert!(msg.contains("vars"), "{msg}");
    }
}

#[test]
fn an_empty_vars_section_is_allowed() -> Result<()> {
    for vars in ["vars:", "vars: null", "vars: {}"] {
        let yaml = format!("{vars}\n{MINIMAL_BODY}");
        let profile = helpers::load_profile_from_yaml_with_vars(yaml, &VarOverrides::default())?;
        assert!(profile.vars.is_empty());
    }
    Ok(())
}

#[test]
fn a_provision_tasks_condition_is_not_substituted() -> Result<()> {
    // `when:` is CEL that reads `vars` itself; substituting into it first would splice a
    // value into the expression's source.
    // editorconfig-checker-disable
    let profile = helpers::load_profile_from_yaml_with_vars(
        crate::yaml!(
            r#"---
vars:
  suite: trixie
dir: /tmp/rootfs
bootstrap:
  type: mmdebstrap
  suite: trixie
  target: rootfs
provision:
- type: apt
  when: vars.suite == 'trixie'
  install: [curl]
"#
        ),
        &VarOverrides::default(),
    )?;
    // editorconfig-checker-enable

    let condition = profile.provision[0].when().expect("a condition");
    assert_eq!(condition.source(), "vars.suite == 'trixie'");
    Ok(())
}

fn apt_task_with_condition(when: &str) -> String {
    format!(
        "vars:\n  suite: trixie\n{MINIMAL_BODY}\
        provision:\n- type: apt\n  when: {when}\n  install: [curl]\n"
    )
}

#[test]
fn a_malformed_condition_reports_the_task_and_line() {
    // serde buffers an internally tagged enum, so the error is located at the task rather
    // than at its `when:` key.
    for (when, needle) in [
        ("vars.suite ==", "not a valid CEL expression"),
        ("${{ vars.suite }} == 'trixie'", "without the braces"),
    ] {
        let yaml = apt_task_with_condition(&format!("\"{when}\""));
        let msg = config_error(
            helpers::load_profile_from_yaml_with_vars(yaml, &VarOverrides::default()).unwrap_err(),
        );
        assert!(msg.contains(needle), "{when}: {msg}");
        assert!(msg.contains("`provision[0]`"), "{when}: {msg}");
        assert!(msg.contains("line 9"), "{when}: {msg}");
    }
}

#[test]
fn a_condition_on_an_undeclared_variable_fails_the_load() {
    // A misspelled name must not read as `false` and quietly skip the task.
    let yaml = apt_task_with_condition("vars.sutie == 'trixie'");
    let err =
        helpers::load_profile_from_yaml_with_vars(yaml, &VarOverrides::default()).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("apt:install"), "{msg}");
    assert!(msg.contains("failed to evaluate"), "{msg}");
}
