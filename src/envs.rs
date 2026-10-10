//! `envs:`: environment variables handed to the bootstrap backend and to every provision
//! task.
//!
//! A map from each name to its value, where an empty value passes the variable through from
//! the environment rsdebstrap runs in. The point is the escalated programs: `sudo` and `doas`
//! reset the environment, so a proxy set on the host never reaches `mmdebstrap` or an
//! `apt-get` inside the chroot without being named here.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer};

use crate::error::RsdebstrapError;

const REDACTED: &str = "<redacted>";

/// One `envs:` value.
#[derive(Clone, PartialEq, Eq)]
pub struct EnvVar {
    // `None` passes the variable through from the environment rsdebstrap runs in.
    value: Option<String>,
    sensitive: bool,
}

impl EnvVar {
    /// The value set by the profile, or `None` for a variable passed through.
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    pub fn sensitive(&self) -> bool {
        self.sensitive
    }
}

// Hand-written so that `{:#?}` of a profile — logged at `debug` on load and at `info` by
// `validate` — does not print a sensitive value.
impl fmt::Debug for EnvVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match (&self.value, self.sensitive) {
            (Some(_), true) => Some(REDACTED),
            (value, _) => value.as_deref(),
        };
        f.debug_struct("EnvVar")
            .field("value", &value)
            .field("sensitive", &self.sensitive)
            .finish()
    }
}

// The accepted YAML shapes: a string, an empty value or `null` (pass through), or a map with
// an optional `value` and `sensitive`. One type drives both deserialization and the schema,
// as with `TaskIsolationWire`.
#[derive(Deserialize, JsonSchema)]
#[serde(untagged)]
enum EnvVarWire {
    Value(#[serde(deserialize_with = "crate::de::string")] String),
    Config(EnvVarConfig),
    Inherit,
}

// A derived struct also deserializes from a sequence, which would take `A: [x]` as
// `value: x`; this accepts the map form only, and so does the schema.
struct EnvVarConfig(EnvVarConfigFields);

impl<'de> Deserialize<'de> for EnvVarConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MapOnly;

        impl<'de> serde::de::Visitor<'de> for MapOnly {
            type Value = EnvVarConfig;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with `value` and/or `sensitive`")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<Self::Value, A::Error> {
                EnvVarConfigFields::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    .map(EnvVarConfig)
            }
        }

        deserializer.deserialize_map(MapOnly)
    }
}

impl JsonSchema for EnvVarConfig {
    fn schema_name() -> Cow<'static, str> {
        EnvVarConfigFields::schema_name()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        EnvVarConfigFields::json_schema(generator)
    }
}

/// An environment variable with options.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(rename = "EnvVarConfig")]
struct EnvVarConfigFields {
    /// The value to set. Omit it to pass the variable through from the environment
    /// rsdebstrap runs in.
    #[serde(default, deserialize_with = "crate::de::opt_string")]
    value: Option<String>,
    /// Keep the value out of rsdebstrap's logs.
    #[serde(default)]
    sensitive: bool,
}

impl<'de> Deserialize<'de> for EnvVar {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match EnvVarWire::deserialize(deserializer)? {
            EnvVarWire::Value(value) => Self {
                value: Some(value),
                sensitive: false,
            },
            EnvVarWire::Config(EnvVarConfig(config)) => Self {
                value: config.value,
                sensitive: config.sensitive,
            },
            EnvVarWire::Inherit => Self {
                value: None,
                sensitive: false,
            },
        })
    }
}

impl JsonSchema for EnvVar {
    fn schema_name() -> Cow<'static, str> {
        "EnvVar".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        EnvVarWire::json_schema(generator)
    }
}

const NAME_PATTERN: &str = "^[A-Za-z_][A-Za-z0-9_]*$";

fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Deserializes the `envs:` map: `null` means empty, names are `[A-Za-z_][A-Za-z0-9_]*`, and
/// a value cannot contain a NUL byte, which no environment can carry.
pub(crate) fn env_map<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, EnvVar>, D::Error> {
    let map = Option::<BTreeMap<String, EnvVar>>::deserialize(deserializer)?.unwrap_or_default();
    for (name, var) in &map {
        if !is_valid_name(name) {
            return Err(serde::de::Error::custom(format!(
                "invalid environment variable name {name:?}: must match [A-Za-z_][A-Za-z0-9_]*"
            )));
        }
        if var.value().is_some_and(|v| v.contains('\0')) {
            return Err(serde::de::Error::custom(format!(
                "environment variable {name} must not contain a NUL byte"
            )));
        }
    }
    Ok(map)
}

/// Schema proxy for the `envs:` map, carrying the name rule [`env_map`] enforces.
pub(crate) struct EnvsSchema;

impl JsonSchema for EnvsSchema {
    fn schema_name() -> Cow<'static, str> {
        "Envs".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "object",
            "propertyNames": { "pattern": NAME_PATTERN },
            "additionalProperties": generator.subschema_for::<EnvVar>()
        })
    }
}

/// An environment variable with its value settled.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedEnv {
    name: String,
    value: String,
    sensitive: bool,
}

impl ResolvedEnv {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The `(name, value)` pair to set.
    pub fn pair(&self) -> (String, String) {
        (self.name.clone(), self.value.clone())
    }
}

/// `NAME=value`, or `NAME=<redacted>` for a sensitive variable.
impl fmt::Display for ResolvedEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = if self.sensitive {
            REDACTED
        } else {
            &self.value
        };
        write!(f, "{}={}", self.name, value)
    }
}

impl fmt::Debug for ResolvedEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// Resolves `envs`, looking a passed-through name up with `lookup`.
///
/// A passed-through variable that is not set is left out rather than set empty: a profile
/// lists `HTTP_PROXY` so that a proxy *if there is one* reaches the build, and an empty
/// value is not the same as none to every program that reads it.
///
/// # Errors
///
/// Returns `RsdebstrapError::Validation` if a passed-through variable is not valid UTF-8.
pub fn resolve_with(
    envs: &BTreeMap<String, EnvVar>,
    lookup: impl Fn(&str) -> Option<OsString>,
) -> Result<Vec<ResolvedEnv>, RsdebstrapError> {
    let mut resolved = Vec::with_capacity(envs.len());
    for (name, var) in envs {
        let value = match var.value() {
            Some(value) => value.to_owned(),
            None => match lookup(name) {
                Some(value) => value.into_string().map_err(|_| {
                    RsdebstrapError::Validation(format!("environment variable {name} is not UTF-8"))
                })?,
                None => {
                    tracing::debug!("environment variable {} is not set; not passed", name);
                    continue;
                }
            },
        };
        resolved.push(ResolvedEnv {
            name: name.clone(),
            value,
            sensitive: var.sensitive(),
        });
    }
    Ok(resolved)
}

/// [`resolve_with`] against the environment of this process.
///
/// # Errors
///
/// As [`resolve_with`].
pub fn resolve(envs: &BTreeMap<String, EnvVar>) -> Result<Vec<ResolvedEnv>, RsdebstrapError> {
    resolve_with(envs, |name| std::env::var_os(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Wrapper {
        #[serde(default, deserialize_with = "env_map")]
        envs: BTreeMap<String, EnvVar>,
    }

    fn parse(yaml: &str) -> Result<BTreeMap<String, EnvVar>, yaml_serde::Error> {
        yaml_serde::from_str::<Wrapper>(yaml).map(|w| w.envs)
    }

    fn var(value: Option<&str>, sensitive: bool) -> EnvVar {
        EnvVar {
            value: value.map(str::to_owned),
            sensitive,
        }
    }

    #[test]
    fn accepts_each_value_shape() {
        let envs = parse(
            "envs:\n\
            \x20 EMPTY:\n\
            \x20 NULL: ~\n\
            \x20 PLAIN: 127.0.0.1,localhost\n\
            \x20 BLANK: ''\n\
            \x20 MAP_VALUE: { value: x }\n\
            \x20 MAP_SECRET: { value: x, sensitive: true }\n\
            \x20 MAP_INHERIT: { sensitive: true }\n\
            \x20 MAP_EMPTY: {}\n",
        )
        .unwrap();
        let expected = [
            ("EMPTY", var(None, false)),
            ("NULL", var(None, false)),
            ("PLAIN", var(Some("127.0.0.1,localhost"), false)),
            ("BLANK", var(Some(""), false)),
            ("MAP_VALUE", var(Some("x"), false)),
            ("MAP_SECRET", var(Some("x"), true)),
            ("MAP_INHERIT", var(None, true)),
            ("MAP_EMPTY", var(None, false)),
        ];
        assert_eq!(envs.len(), expected.len());
        for (name, expected) in expected {
            assert_eq!(envs[name], expected, "{name}");
        }
    }

    #[test]
    fn rejects_invalid_names_values_and_keys() {
        for yaml in [
            "envs: { 1A: x }",
            "envs: { A-B: x }",
            "envs: { 'A B': x }",
            "envs: { A: 42 }",
            "envs: { A: true }",
            "envs: { A: [x] }",
            "envs: { A: \"x\\0y\" }",
            "envs: { A: { value: 42 } }",
            "envs: { A: { valu: x } }",
            "envs: { A: { sensitive: maybe } }",
            "envs: [A]",
        ] {
            assert!(parse(yaml).is_err(), "{yaml:?} was accepted");
        }
    }

    #[test]
    fn debug_and_display_redact_sensitive_values() {
        let envs = parse("envs: { A: { value: s3cret, sensitive: true }, B: visible }").unwrap();
        let debug = format!("{envs:#?}");
        assert!(!debug.contains("s3cret"), "{debug}");
        assert!(debug.contains("visible"), "{debug}");

        let resolved = resolve_with(&envs, |_| None).unwrap();
        let shown: Vec<String> = resolved.iter().map(ToString::to_string).collect();
        assert_eq!(shown, ["A=<redacted>", "B=visible"]);
        assert!(!format!("{resolved:?}").contains("s3cret"));
        assert_eq!(resolved[0].pair(), ("A".to_owned(), "s3cret".to_owned()));
    }

    #[test]
    fn resolve_passes_through_set_variables_and_skips_unset_ones() {
        let envs = parse("envs: { HTTP_PROXY: , HTTPS_PROXY: , NO_PROXY: localhost }").unwrap();
        let resolved = resolve_with(&envs, |name| {
            (name == "HTTP_PROXY").then(|| OsString::from("http://proxy:3128"))
        })
        .unwrap();
        let pairs: Vec<_> = resolved.iter().map(ResolvedEnv::pair).collect();
        assert_eq!(
            pairs,
            [
                ("HTTP_PROXY".to_owned(), "http://proxy:3128".to_owned()),
                ("NO_PROXY".to_owned(), "localhost".to_owned()),
            ]
        );
    }

    #[test]
    fn resolve_rejects_a_non_utf8_value() {
        use std::os::unix::ffi::OsStringExt;

        let envs = parse("envs: { A: }").unwrap();
        let err = resolve_with(&envs, |_| Some(OsString::from_vec(vec![0xff]))).unwrap_err();
        assert!(err.to_string().contains("not UTF-8"), "{err}");
    }
}
