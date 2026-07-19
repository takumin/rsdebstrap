//! Property-based drift guard for the generated JSON Schema.
//!
//! `tests/schema_test.rs` spot-checks the schema against a curated table. This file stresses
//! the same contract with randomly generated documents so drift cannot hide in a shape nobody
//! thought to enumerate.
//!
//! The property asserted is the *critical safety invariant*: whenever the structural
//! deserializer accepts a document, the generated schema must also accept it. A violation means
//! editor/CI tooling would flag a config that `apply`/`validate` happily parse — the exact
//! failure mode the schema exists to avoid.
//!
//! Both sides operate on the same `serde_json::Value`: acceptance is `serde_json::from_value::
//! <Profile>` (runs `Deserialize`, including the custom `Privilege`/`TaskIsolation`/`ShellTask`/
//! `MitamaeTask` dispatch, but not the semantic `Profile::validate`), and the schema verdict
//! comes from the compiled validator. This is precisely the layer where schema generation could
//! diverge from serde.

use std::sync::LazyLock;

use jsonschema::Validator;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use rsdebstrap::config::Profile;
use serde_json::{Map, Value, json};

static VALIDATOR: LazyLock<Validator> = LazyLock::new(|| {
    let schema = rsdebstrap::profile_json_schema();
    jsonschema::validator_for(&schema).expect("generated schema must be a valid JSON Schema")
});

/// Asserts the safety invariant for a single document.
fn assert_no_false_reject(doc: &Value) -> Result<(), TestCaseError> {
    let deser_ok = serde_json::from_value::<Profile>(doc.clone()).is_ok();
    let schema_ok = VALIDATOR.is_valid(doc);
    prop_assert!(
        !deser_ok || schema_ok,
        "SCHEMA FALSE-REJECT: deserializer accepts but schema rejects\n{}",
        serde_json::to_string_pretty(doc).unwrap()
    );
    Ok(())
}

/// An optional field: `None` omits the key entirely; `Some(v)` sets it to `v` (possibly null or
/// a deliberately wrong type). Covers absent / explicit-null / string / non-string.
fn opt_string_field() -> impl Strategy<Value = Option<Value>> {
    prop_oneof![
        Just(None),
        Just(Some(Value::Null)),
        "[a-z][a-z0-9_./-]{0,8}".prop_map(|s| Some(Value::String(s))),
        any::<i64>().prop_map(|n| Some(json!(n))),
    ]
}

/// Random `privilege` field spanning every accepted and near-miss shape.
fn privilege_field() -> impl Strategy<Value = Option<Value>> {
    prop_oneof![
        Just(None),
        Just(Some(Value::Null)),
        any::<bool>().prop_map(|b| Some(json!(b))),
        prop_oneof![Just("sudo"), Just("doas"), Just("bogus")]
            .prop_map(|m| Some(json!({ "method": m }))),
        Just(Some(json!({ "methd": "sudo" }))), // typo'd key
        Just(Some(json!({ "method": "sudo", "extra": 1 }))), // unknown extra key
    ]
}

/// Random `isolation` field spanning every accepted and near-miss shape.
fn isolation_field() -> impl Strategy<Value = Option<Value>> {
    prop_oneof![
        Just(None),
        Just(Some(Value::Null)),
        any::<bool>().prop_map(|b| Some(json!(b))),
        prop_oneof![Just("chroot"), Just("bogus")].prop_map(|t| Some(json!({ "type": t }))),
        Just(Some(json!({ "typ": "chroot" }))), // typo'd key
    ]
}

/// A single provision task with randomized (and frequently invalid) fields.
fn task_strategy() -> impl Strategy<Value = Value> {
    (
        prop_oneof![Just("shell"), Just("mitamae"), Just("bogus")],
        opt_string_field(), // script
        opt_string_field(), // content
        privilege_field(),
        isolation_field(),
        any::<bool>(), // inject an unknown key
    )
        .prop_map(|(ty, script, content, priv_, iso, unknown)| {
            let mut m = Map::new();
            m.insert("type".into(), json!(ty));
            if let Some(v) = script {
                m.insert("script".into(), v);
            }
            if let Some(v) = content {
                m.insert("content".into(), v);
            }
            if let Some(v) = priv_ {
                m.insert("privilege".into(), v);
            }
            if let Some(v) = iso {
                m.insert("isolation".into(), v);
            }
            if unknown {
                m.insert("surprise".into(), json!(1));
            }
            Value::Object(m)
        })
}

/// Random `bootstrap` block: valid backend base plus optional known/unknown keys.
fn bootstrap_strategy() -> impl Strategy<Value = Value> {
    (
        prop_oneof![Just("mmdebstrap"), Just("debootstrap")],
        // Include the empty string: the default variants once carried
        // `#[serde(alias = "")]` (deserializer-accepted but never emitted into the schema — a
        // false-reject). The alias was removed, so `""` must now be rejected by both sides.
        proptest::option::of(prop_oneof![Just("minbase"), Just("bogus"), Just("")]),
        any::<bool>(), // inject an unknown key
    )
        .prop_map(|(ty, variant, unknown)| {
            let mut m = Map::new();
            m.insert("type".into(), json!(ty));
            m.insert("suite".into(), json!("trixie"));
            m.insert("target".into(), json!("rootfs"));
            if let Some(v) = variant {
                m.insert("variant".into(), json!(v));
            }
            if unknown {
                m.insert("customise_hook".into(), json!(["x"])); // British-spelling typo
            }
            Value::Object(m)
        })
}

/// A field value spanning absent / null / string / bool / int / empty-array / string-array.
/// Wider than `opt_string_field` so it also probes the list-typed fields in the prepare/assemble
/// surface (`options`, `name_servers`, `search`) and deliberately wrong scalar/array shapes.
fn opt_any_field() -> impl Strategy<Value = Option<Value>> {
    prop_oneof![
        Just(None),
        Just(Some(Value::Null)),
        "[a-z0-9/._-]{0,8}".prop_map(|s| Some(Value::String(s))),
        any::<bool>().prop_map(|b| Some(json!(b))),
        any::<i64>().prop_map(|n| Some(json!(n))),
        Just(Some(json!([]))),
        prop::collection::vec("[a-z0-9/._-]{0,6}", 0..3).prop_map(|v| Some(json!(v))),
    ]
}

/// Random mount entry: known keys with arbitrary (often wrong-typed) values, plus an optional
/// unknown key to exercise `MountEntry`'s `deny_unknown_fields` / `additionalProperties: false`.
fn mount_entry_strategy() -> impl Strategy<Value = Value> {
    (opt_any_field(), opt_any_field(), opt_any_field(), any::<bool>()).prop_map(
        |(source, target, options, unknown)| {
            let mut m = Map::new();
            if let Some(v) = source {
                m.insert("source".into(), v);
            }
            if let Some(v) = target {
                m.insert("target".into(), v);
            }
            if let Some(v) = options {
                m.insert("options".into(), v);
            }
            if unknown {
                m.insert("surprise".into(), json!(1));
            }
            Value::Object(m)
        },
    )
}

/// Random `resolv_conf` map. Emits the union of the prepare (`copy`) and assemble
/// (`link`/`privilege`) field sets, so each phase's `deny_unknown_fields` is exercised (a key
/// unknown to one phase is rejected by both the deserializer and the schema there). `None` on the
/// whole strategy omits the key entirely.
fn resolv_conf_strategy() -> impl Strategy<Value = Option<Value>> {
    let map = (
        opt_any_field(),   // copy      (prepare only)
        opt_any_field(),   // name_servers
        opt_any_field(),   // search
        opt_any_field(),   // link      (assemble only)
        privilege_field(), // privilege (assemble only)
        any::<bool>(),     // inject an unknown key
    )
        .prop_map(|(copy, ns, search, link, privilege, unknown)| {
            let mut m = Map::new();
            if let Some(v) = copy {
                m.insert("copy".into(), v);
            }
            if let Some(v) = ns {
                m.insert("name_servers".into(), v);
            }
            if let Some(v) = search {
                m.insert("search".into(), v);
            }
            if let Some(v) = link {
                m.insert("link".into(), v);
            }
            if let Some(v) = privilege {
                m.insert("privilege".into(), v);
            }
            if unknown {
                m.insert("surprise".into(), json!(1));
            }
            Value::Object(m)
        });
    proptest::option::of(map)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Randomized provision tasks must never be false-rejected by the schema.
    #[test]
    fn provision_tasks_never_false_rejected(tasks in prop::collection::vec(task_strategy(), 0..4)) {
        let doc = json!({
            "dir": "/out",
            "bootstrap": { "type": "mmdebstrap", "suite": "trixie", "target": "rootfs" },
            "defaults": { "isolation": { "type": "chroot" }, "privilege": { "method": "sudo" } },
            "provision": tasks,
        });
        assert_no_false_reject(&doc)?;
    }

    /// Randomized bootstrap + defaults blocks must never be false-rejected by the schema.
    #[test]
    fn bootstrap_and_defaults_never_false_rejected(
        bootstrap in bootstrap_strategy(),
        priv_ in privilege_field(),
        iso in isolation_field(),
    ) {
        let mut defaults = Map::new();
        if let Some(v) = priv_ {
            defaults.insert("privilege".into(), v);
        }
        if let Some(v) = iso {
            defaults.insert("isolation".into(), v);
        }
        let doc = json!({
            "dir": "/out",
            "bootstrap": bootstrap,
            "defaults": Value::Object(defaults),
        });
        assert_no_false_reject(&doc)?;
    }

    /// Randomized `prepare` (mount / resolv_conf) and `assemble` (resolv_conf) blocks must never
    /// be false-rejected by the schema. These named-field structs are `deny_unknown_fields` with
    /// nested path/list fields, so they are exactly the kind of surface where schema generation
    /// could silently diverge from serde — yet the curated table only spot-checks one mount case.
    #[test]
    fn prepare_and_assemble_never_false_rejected(
        preset in proptest::option::of(prop_oneof![Just("recommends"), Just("bogus")]),
        entries in prop::collection::vec(mount_entry_strategy(), 0..3),
        mount_unknown in any::<bool>(),
        prepare_resolv in resolv_conf_strategy(),
        assemble_resolv in resolv_conf_strategy(),
    ) {
        let mut mount = Map::new();
        if let Some(p) = preset {
            mount.insert("preset".into(), json!(p));
        }
        mount.insert("mounts".into(), json!(entries));
        if mount_unknown {
            mount.insert("surprise".into(), json!(1));
        }

        let mut prepare = Map::new();
        prepare.insert("mount".into(), Value::Object(mount));
        if let Some(v) = prepare_resolv {
            prepare.insert("resolv_conf".into(), v);
        }

        let mut assemble = Map::new();
        if let Some(v) = assemble_resolv {
            assemble.insert("resolv_conf".into(), v);
        }

        let doc = json!({
            "dir": "/out",
            "bootstrap": { "type": "mmdebstrap", "suite": "trixie", "target": "rootfs" },
            "defaults": { "isolation": { "type": "chroot" }, "privilege": { "method": "sudo" } },
            "prepare": Value::Object(prepare),
            "assemble": Value::Object(assemble),
        });
        assert_no_false_reject(&doc)?;
    }
}
