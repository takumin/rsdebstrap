//! Regression tests for the generated JSON Schema (`rsdebstrap schema`).
//!
//! The schema is derived from the Rust config types via `schemars`. Its whole value is that it
//! keeps matching what `apply`/`validate` accept. These tests guard that contract so schema
//! drift cannot slip through unnoticed:
//!
//! 1. The schema generates without panicking and has the expected top-level shape.
//! 2. The shipped example profile validates against it.
//! 3. Differential check: for a table of YAML documents, the schema's verdict is compared with
//!    the *structural* deserializer's verdict (`serde_yaml::from_str::<Profile>`). The critical
//!    safety invariant is that the schema must never reject a document the deserializer accepts
//!    (a false rejection would make editor tooling flag valid configs). Semantic-only checks
//!    (e.g. mitamae binary resolution, mount/privilege cross-checks) live in `Profile::validate`
//!    and are intentionally out of scope here — JSON Schema cannot express them.

use jsonschema::Validator;
use rsdebstrap::config::Profile;
use serde_json::Value;

/// Builds a validator from the crate's generated schema.
fn validator() -> Validator {
    let schema = rsdebstrap::profile_json_schema();
    jsonschema::validator_for(&schema).expect("generated schema must be a valid JSON Schema")
}

/// True if `yaml` satisfies the generated JSON Schema.
fn schema_accepts(v: &Validator, yaml: &str) -> bool {
    let instance: Value =
        serde_yaml::from_str(yaml).expect("test YAML must deserialize into a JSON value");
    v.is_valid(&instance)
}

/// True if `yaml` deserializes structurally into a `Profile` (no semantic validation).
fn deser_accepts(yaml: &str) -> bool {
    serde_yaml::from_str::<Profile>(yaml).is_ok()
}

/// Minimal valid profile prefix; append a `provision:` block (or nothing) per case.
const BASE: &str = "\
dir: /out
bootstrap: {type: mmdebstrap, suite: trixie, target: rootfs}
defaults: {isolation: {type: chroot}, privilege: {method: sudo}}
";

fn with_provision(task: &str) -> String {
    format!("{BASE}provision:\n  - {task}\n")
}

#[test]
fn schema_generates_and_has_expected_shape() {
    let schema = rsdebstrap::profile_json_schema();
    assert!(schema.get("$defs").is_some(), "schema must expose $defs");
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .expect("root schema must list required fields");
    assert!(required.iter().any(|v| v == "dir"));
    assert!(required.iter().any(|v| v == "bootstrap"));

    let defs = &schema["$defs"];
    // #4: the two per-backend `Variant` enums get distinct, self-describing names.
    assert!(defs.get("MmdebstrapVariant").is_some());
    assert!(defs.get("DebootstrapVariant").is_some());
    assert!(defs.get("Variant2").is_none(), "auto-suffixed `Variant2` must not appear");

    // #3: an explicit null is a valid form again (mirrors field absence -> Inherit).
    for name in ["Privilege", "TaskIsolation"] {
        let any_of = defs[name]["anyOf"]
            .as_array()
            .unwrap_or_else(|| panic!("{name} must be an anyOf"));
        assert!(
            any_of
                .iter()
                .any(|s| s.get("type") == Some(&Value::from("null"))),
            "{name} anyOf must include a null form"
        );
    }
}

#[test]
fn example_profile_validates_against_schema() {
    let example = include_str!("../examples/debian_trixie_mmdebstrap.yml");
    let v = validator();
    assert!(
        schema_accepts(&v, example),
        "shipped example must validate against the generated schema"
    );
    assert!(deser_accepts(example), "shipped example must also parse into a Profile");
}

#[test]
fn schema_matches_structural_deserializer() {
    let v = validator();

    // Multi-line YAML docs (kept as bindings so no source line exceeds the 100-column limit).
    let debootstrap = concat!(
        "dir: /o\n",
        "bootstrap: {type: debootstrap, suite: trixie, target: rootfs, variant: minbase}\n",
    )
    .to_string();
    let unknown_defaults = concat!(
        "dir: /o\n",
        "bootstrap: {type: mmdebstrap, suite: t, target: r}\n",
        "defaults: {isolatio: {type: chroot}}\n",
    )
    .to_string();
    let mount_unknown_field = format!(
        "{BASE}{}",
        concat!(
            "prepare:\n",
            "  mount:\n",
            "    mounts:\n",
            "      - {source: /dev, target: /dev, options: [bind], bogus: 1}\n",
        )
    );

    // (label, yaml, expected verdict). Expectation is shared: for these structural cases the
    // schema and the *structural* deserializer must agree exactly.
    let cases: &[(&str, String, bool)] = &[
        // Explicit null on `privilege`/`isolation` resolves to Inherit (#3).
        (
            "null privilege",
            with_provision("{type: shell, content: hi, privilege: null}"),
            true,
        ),
        (
            "null isolation",
            with_provision("{type: shell, content: hi, isolation: null}"),
            true,
        ),
        (
            "bool privilege",
            with_provision("{type: shell, content: hi, privilege: true}"),
            true,
        ),
        (
            "method map privilege",
            with_provision("{type: shell, content: hi, privilege: {method: doas}}"),
            true,
        ),
        ("mitamae content-only", with_provision("{type: mitamae, content: 'x'}"), true),
        ("debootstrap backend", debootstrap, true),
        // script/content mutual exclusion (#2): both set or neither -> rejected by both.
        (
            "shell both script+content",
            with_provision("{type: shell, content: hi, script: ./x.sh}"),
            false,
        ),
        ("shell neither source", with_provision("{type: shell, shell: /bin/sh}"), false),
        (
            "mitamae both script+content",
            with_provision("{type: mitamae, content: x, script: ./r.rb}"),
            false,
        ),
        // Null-valued source properties: serde treats `null` on an Option as absent (#2 null
        // modeling). The schema must agree via the per-branch string constraint.
        (
            "null script, content set",
            with_provision("{type: shell, script: null, content: hi}"),
            true,
        ),
        ("null script only", with_provision("{type: shell, script: null}"), false),
        (
            "both sources null",
            with_provision("{type: shell, script: null, content: null}"),
            false,
        ),
        // Bad enum values.
        (
            "bad privilege method",
            with_provision("{type: shell, content: hi, privilege: {method: bogus}}"),
            false,
        ),
        (
            "bad isolation type",
            with_provision("{type: shell, content: hi, isolation: {type: bogus}}"),
            false,
        ),
        // Unknown/typo'd keys rejected by deny_unknown_fields (#5) / additionalProperties:false.
        (
            "typo'd privilege key",
            with_provision("{type: shell, content: hi, privilege: {methd: sudo}}"),
            false,
        ),
        (
            "typo'd shell field",
            with_provision("{type: shell, content: hi, privilage: true}"),
            false,
        ),
        ("unknown top-level key", format!("{BASE}wat: 1\n"), false),
        ("unknown defaults key", unknown_defaults, false),
        ("unknown mount entry field", mount_unknown_field, false),
    ];

    for (label, yaml, expected) in cases {
        let s = schema_accepts(&v, yaml);
        let d = deser_accepts(yaml);
        // Critical safety invariant (deserializer-accepts implies schema-accepts): the schema
        // must never reject what the deserializer accepts.
        assert!(
            !d || s,
            "SCHEMA FALSE-REJECT for `{label}`: deserializer accepts but schema rejects\n{yaml}"
        );
        assert_eq!(s, *expected, "schema verdict mismatch for `{label}`\n{yaml}");
        assert_eq!(d, *expected, "deserializer verdict mismatch for `{label}`\n{yaml}");
    }
}
