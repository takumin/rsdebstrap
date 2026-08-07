//! Privilege escalation configuration.
//!
//! This module provides types for configuring privilege escalation (`sudo`, `doas`)
//! on a per-command basis. Tasks and bootstrap backends can declare their own
//! privilege settings, inheriting from profile-level defaults when unspecified.

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};

use crate::error::RsdebstrapError;

/// Privilege escalation method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PrivilegeMethod {
    /// Use `sudo` for privilege escalation.
    Sudo,
    /// Use `doas` for privilege escalation.
    Doas,
}

impl PrivilegeMethod {
    /// Returns the command name for this privilege method.
    pub fn command_name(&self) -> &'static str {
        match self {
            Self::Sudo => "sudo",
            Self::Doas => "doas",
        }
    }
}

impl std::fmt::Display for PrivilegeMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.command_name())
    }
}

/// Default privilege settings for the profile.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivilegeDefaults {
    /// The default privilege escalation method.
    pub method: PrivilegeMethod,
}

/// Privilege escalation setting for a task or bootstrap backend.
///
/// This type supports the following YAML representations:
/// - Absent (field not specified) → `Inherit` (use defaults if available)
/// - `privilege: true` → `UseDefault` (require defaults, error if missing)
/// - `privilege: false` → `Disabled` (no privilege escalation)
/// - `privilege: { method: sudo }` → `Method(Sudo)` (explicit method)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Privilege {
    /// YAML field not specified — inherit from defaults if available.
    #[default]
    Inherit,
    /// `privilege: true` — use the default method (error if no defaults configured).
    UseDefault,
    /// `privilege: false` — no privilege escalation.
    Disabled,
    /// `privilege: { method: <method> }` — use the specified method.
    Method(PrivilegeMethod),
}

impl Privilege {
    /// Resolves the privilege setting against the profile defaults.
    ///
    /// Returns `Some(method)` if privilege escalation should be applied,
    /// or `None` if no escalation is needed.
    ///
    /// # Errors
    ///
    /// Returns `RsdebstrapError::Validation` if `UseDefault` is specified
    /// but no defaults are configured.
    pub fn resolve(
        &self,
        defaults: Option<&PrivilegeDefaults>,
    ) -> Result<Option<PrivilegeMethod>, RsdebstrapError> {
        match self {
            Self::Inherit => Ok(defaults.map(|d| d.method)),
            Self::UseDefault => match defaults {
                Some(d) => Ok(Some(d.method)),
                None => Err(RsdebstrapError::Validation(
                    "privilege: true requires defaults.privilege.method to be configured"
                        .to_string(),
                )),
            },
            Self::Disabled => Ok(None),
            Self::Method(method) => Ok(Some(*method)),
        }
    }
}

// The schemars rename keeps this private type's Rust name out of the published schema
// contract (`$defs/PrivilegeConfig`, symmetric with the isolation branch).
/// Explicit privilege escalation configuration for a task or bootstrap backend.
#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(rename = "PrivilegeConfig")]
#[serde(deny_unknown_fields)]
struct PrivilegeMethodMap {
    /// The privilege escalation method to use.
    method: PrivilegeMethod,
}

// The accepted YAML shapes: `true`/`false`, `{ method: ... }`, or an explicit null (which
// — like field absence — resolves to `Inherit`). This one type drives both deserialization
// and schema generation, so the two cannot describe different acceptance sets.
//
// Untagged rather than a hand-written visitor: the visitor's `expecting` string is a nicer
// message than untagged's "did not match any variant", but keeping it meant maintaining a
// second enum for schemars and a parity test to pin them together. `load_profile` wraps
// deserialization in `serde_path_to_error`, so the field path recovers the lost context.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
enum PrivilegeWire {
    Toggle(bool),
    Method(PrivilegeMethodMap),
    // Unit variant → `{ "type": "null" }` in the generated `anyOf`.
    Inherit,
}

impl From<PrivilegeWire> for Privilege {
    fn from(wire: PrivilegeWire) -> Self {
        match wire {
            PrivilegeWire::Toggle(true) => Self::UseDefault,
            PrivilegeWire::Toggle(false) => Self::Disabled,
            PrivilegeWire::Method(m) => Self::Method(m.method),
            PrivilegeWire::Inherit => Self::Inherit,
        }
    }
}

impl<'de> Deserialize<'de> for Privilege {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        PrivilegeWire::deserialize(deserializer).map(Into::into)
    }
}

impl JsonSchema for Privilege {
    fn schema_name() -> Cow<'static, str> {
        "Privilege".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        PrivilegeWire::json_schema(generator)
    }
}

impl Serialize for Privilege {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Inherit => serializer.serialize_none(),
            Self::UseDefault => serializer.serialize_bool(true),
            Self::Disabled => serializer.serialize_bool(false),
            Self::Method(method) => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("method", method)?;
                map.end()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privilege_method_command_name() {
        // `Display` delegates to `command_name()`, so both are pinned together here.
        assert_eq!(PrivilegeMethod::Sudo.command_name(), "sudo");
        assert_eq!(PrivilegeMethod::Sudo.to_string(), "sudo");
        assert_eq!(PrivilegeMethod::Doas.command_name(), "doas");
        assert_eq!(PrivilegeMethod::Doas.to_string(), "doas");
    }

    #[test]
    fn privilege_method_deserialize() {
        let sudo: PrivilegeMethod = yaml_serde::from_str("sudo").unwrap();
        assert_eq!(sudo, PrivilegeMethod::Sudo);

        let doas: PrivilegeMethod = yaml_serde::from_str("doas").unwrap();
        assert_eq!(doas, PrivilegeMethod::Doas);
    }

    #[test]
    fn privilege_deserialize_true() {
        let p: Privilege = yaml_serde::from_str("true").unwrap();
        assert_eq!(p, Privilege::UseDefault);
    }

    #[test]
    fn privilege_deserialize_false() {
        let p: Privilege = yaml_serde::from_str("false").unwrap();
        assert_eq!(p, Privilege::Disabled);
    }

    #[test]
    fn privilege_deserialize_method_sudo() {
        let p: Privilege = yaml_serde::from_str("method: sudo").unwrap();
        assert_eq!(p, Privilege::Method(PrivilegeMethod::Sudo));
    }

    #[test]
    fn privilege_deserialize_unknown_field_rejected() {
        let result: Result<Privilege, _> = yaml_serde::from_str("method: sudo\nextra: bad");
        assert!(result.is_err());
    }

    #[test]
    fn privilege_default_is_inherit() {
        assert_eq!(Privilege::default(), Privilege::Inherit);
    }

    #[test]
    fn resolve_inherit_with_defaults() {
        let defaults = PrivilegeDefaults {
            method: PrivilegeMethod::Sudo,
        };
        let result = Privilege::Inherit.resolve(Some(&defaults)).unwrap();
        assert_eq!(result, Some(PrivilegeMethod::Sudo));
    }

    #[test]
    fn resolve_inherit_without_defaults() {
        let result = Privilege::Inherit.resolve(None).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn resolve_use_default_with_defaults() {
        let defaults = PrivilegeDefaults {
            method: PrivilegeMethod::Doas,
        };
        let result = Privilege::UseDefault.resolve(Some(&defaults)).unwrap();
        assert_eq!(result, Some(PrivilegeMethod::Doas));
    }

    #[test]
    fn resolve_use_default_without_defaults_errors() {
        let result = Privilege::UseDefault.resolve(None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("defaults.privilege.method"));
    }

    #[test]
    fn resolve_disabled() {
        let defaults = PrivilegeDefaults {
            method: PrivilegeMethod::Sudo,
        };
        let result = Privilege::Disabled.resolve(Some(&defaults)).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn resolve_disabled_without_defaults() {
        let result = Privilege::Disabled.resolve(None).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn resolve_method_overrides_defaults() {
        let defaults = PrivilegeDefaults {
            method: PrivilegeMethod::Sudo,
        };
        let result = Privilege::Method(PrivilegeMethod::Doas)
            .resolve(Some(&defaults))
            .unwrap();
        assert_eq!(result, Some(PrivilegeMethod::Doas));
    }

    #[test]
    fn resolve_method_without_defaults() {
        let result = Privilege::Method(PrivilegeMethod::Sudo)
            .resolve(None)
            .unwrap();
        assert_eq!(result, Some(PrivilegeMethod::Sudo));
    }

    #[test]
    fn privilege_method_rejects_invalid_value() {
        let result: Result<PrivilegeMethod, _> = yaml_serde::from_str("pkexec");
        assert!(result.is_err(), "pkexec should not be a valid PrivilegeMethod");
    }

    #[test]
    fn privilege_rejects_numeric_value() {
        let result: Result<Privilege, _> = yaml_serde::from_str("42");
        assert!(result.is_err(), "numeric value should not be valid for Privilege");
    }

    #[test]
    fn privilege_rejects_plain_string() {
        let result: Result<Privilege, _> = yaml_serde::from_str("\"sudo\"");
        assert!(result.is_err(), "plain string should not be valid for Privilege");
    }

    #[test]
    fn privilege_rejects_invalid_method_in_map() {
        let result: Result<Privilege, _> = yaml_serde::from_str("method: pkexec");
        assert!(result.is_err(), "pkexec should not be valid in privilege map");
    }

    #[test]
    fn privilege_deserialize_null_returns_inherit() {
        // An explicit null is accepted as Inherit (mirrors field absence).
        let p: Privilege = yaml_serde::from_str("~").unwrap();
        assert_eq!(p, Privilege::Inherit);
    }

    fn roundtrip(original: &Privilege) -> Privilege {
        let yaml = yaml_serde::to_string(original).unwrap();
        yaml_serde::from_str(&yaml).unwrap()
    }

    // `Serialize` is hand-written to mirror the visitor, so every variant must
    // survive a round trip — including `Inherit`, which serializes to null.
    #[test]
    fn serialize_roundtrip_every_variant() {
        for original in [
            Privilege::Inherit,
            Privilege::UseDefault,
            Privilege::Disabled,
            Privilege::Method(PrivilegeMethod::Sudo),
            Privilege::Method(PrivilegeMethod::Doas),
        ] {
            assert_eq!(roundtrip(&original), original, "roundtrip changed {original:?}");
        }
    }

    // The acceptance set is now a property of one type, so this pins the boundary itself
    // rather than the agreement between two definitions.
    #[test]
    fn privilege_acceptance_set() {
        for (yaml, accepted) in [
            ("~", true),
            ("true", true),
            ("false", true),
            ("method: sudo", true),
            ("method: doas", true),
            ("method: pkexec", false),
            ("methd: sudo", false),
            ("{method: sudo, extra: 1}", false),
            ("{}", false),
            ("sudo", false),
            ("[]", false),
            ("42", false),
            ("42.5", false),
        ] {
            let got = yaml_serde::from_str::<Privilege>(yaml).is_ok();
            assert_eq!(got, accepted, "{yaml:?}: accepted = {got}, expected {accepted}");
        }
    }
}
