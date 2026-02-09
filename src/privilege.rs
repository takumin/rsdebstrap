//! Privilege escalation configuration.
//!
//! This module provides types for configuring privilege escalation (`sudo`, `doas`)
//! on a per-command basis. Tasks and bootstrap backends can declare their own
//! privilege settings, inheriting from profile-level defaults when unspecified.

use serde::{Deserialize, Serialize};

use crate::error::RsdebstrapError;

/// Privilege escalation method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
    /// Returns the resolved privilege method.
    ///
    /// Should only be called after [`resolve()`](Self::resolve) or
    /// [`resolve_in_place()`](Self::resolve_in_place) has been used to
    /// collapse the privilege setting into `Method` or `Disabled`.
    ///
    /// Returns `Some(method)` for `Method`, `None` for `Disabled` and `Inherit`.
    /// If called on `UseDefault`, logs a warning and returns `None` as a safe fallback.
    pub fn resolved_method(&self) -> Option<PrivilegeMethod> {
        match self {
            Self::Method(m) => Some(*m),
            Self::Disabled | Self::Inherit => None,
            Self::UseDefault => {
                tracing::warn!(
                    "resolved_method() called on UseDefault; this likely indicates \
                    resolve() was not called. Returning None as fallback."
                );
                None
            }
        }
    }

    /// Resolves the privilege setting in place, replacing `self` with the
    /// resolved variant (`Method` or `Disabled`).
    ///
    /// This is a convenience wrapper around [`resolve()`](Self::resolve)
    /// that mutates `self` directly.
    ///
    /// # Errors
    ///
    /// Returns `RsdebstrapError::Validation` if `UseDefault` is specified
    /// but no defaults are configured.
    pub fn resolve_in_place(
        &mut self,
        defaults: Option<&PrivilegeDefaults>,
    ) -> Result<(), RsdebstrapError> {
        let resolved = self.resolve(defaults)?;
        *self = match resolved {
            Some(method) => Self::Method(method),
            None => Self::Disabled,
        };
        Ok(())
    }

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

impl<'de> Deserialize<'de> for Privilege {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;

        struct PrivilegeVisitor;

        impl<'de> de::Visitor<'de> for PrivilegeVisitor {
            type Value = Privilege;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a boolean or a map with a 'method' field")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Privilege::Inherit)
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v {
                    Ok(Privilege::UseDefault)
                } else {
                    Ok(Privilege::Disabled)
                }
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct PrivilegeMap {
                    method: PrivilegeMethod,
                }
                let pm = PrivilegeMap::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(Privilege::Method(pm.method))
            }
        }

        deserializer.deserialize_any(PrivilegeVisitor)
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

    // =========================================================================
    // PrivilegeMethod tests
    // =========================================================================

    #[test]
    fn privilege_method_command_name() {
        assert_eq!(PrivilegeMethod::Sudo.command_name(), "sudo");
        assert_eq!(PrivilegeMethod::Doas.command_name(), "doas");
    }

    #[test]
    fn privilege_method_display() {
        assert_eq!(PrivilegeMethod::Sudo.to_string(), "sudo");
        assert_eq!(PrivilegeMethod::Doas.to_string(), "doas");
    }

    #[test]
    fn privilege_method_deserialize() {
        let sudo: PrivilegeMethod = serde_yaml::from_str("sudo").unwrap();
        assert_eq!(sudo, PrivilegeMethod::Sudo);

        let doas: PrivilegeMethod = serde_yaml::from_str("doas").unwrap();
        assert_eq!(doas, PrivilegeMethod::Doas);
    }

    // =========================================================================
    // Privilege deserialization tests
    // =========================================================================

    #[test]
    fn privilege_deserialize_true() {
        let p: Privilege = serde_yaml::from_str("true").unwrap();
        assert_eq!(p, Privilege::UseDefault);
    }

    #[test]
    fn privilege_deserialize_false() {
        let p: Privilege = serde_yaml::from_str("false").unwrap();
        assert_eq!(p, Privilege::Disabled);
    }

    #[test]
    fn privilege_deserialize_method_sudo() {
        let p: Privilege = serde_yaml::from_str("method: sudo").unwrap();
        assert_eq!(p, Privilege::Method(PrivilegeMethod::Sudo));
    }

    #[test]
    fn privilege_deserialize_method_doas() {
        let p: Privilege = serde_yaml::from_str("method: doas").unwrap();
        assert_eq!(p, Privilege::Method(PrivilegeMethod::Doas));
    }

    #[test]
    fn privilege_deserialize_unknown_field_rejected() {
        let result: Result<Privilege, _> = serde_yaml::from_str("method: sudo\nextra: bad");
        assert!(result.is_err());
    }

    #[test]
    fn privilege_default_is_inherit() {
        assert_eq!(Privilege::default(), Privilege::Inherit);
    }

    // =========================================================================
    // Privilege::resolve tests
    // =========================================================================

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

    // =========================================================================
    // Privilege::resolve_in_place tests
    // =========================================================================

    #[test]
    fn resolve_in_place_inherit_with_defaults() {
        let defaults = PrivilegeDefaults {
            method: PrivilegeMethod::Sudo,
        };
        let mut p = Privilege::Inherit;
        p.resolve_in_place(Some(&defaults)).unwrap();
        assert_eq!(p, Privilege::Method(PrivilegeMethod::Sudo));
    }

    #[test]
    fn resolve_in_place_inherit_without_defaults() {
        let mut p = Privilege::Inherit;
        p.resolve_in_place(None).unwrap();
        assert_eq!(p, Privilege::Disabled);
    }

    #[test]
    fn resolve_in_place_use_default_without_defaults_errors() {
        let mut p = Privilege::UseDefault;
        let result = p.resolve_in_place(None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
    }

    // =========================================================================
    // Privilege::resolved_method tests
    // =========================================================================

    #[test]
    fn resolved_method_returns_some_for_method() {
        assert_eq!(
            Privilege::Method(PrivilegeMethod::Sudo).resolved_method(),
            Some(PrivilegeMethod::Sudo)
        );
        assert_eq!(
            Privilege::Method(PrivilegeMethod::Doas).resolved_method(),
            Some(PrivilegeMethod::Doas)
        );
    }

    #[test]
    fn resolved_method_returns_none_for_disabled() {
        assert_eq!(Privilege::Disabled.resolved_method(), None);
    }

    // =========================================================================
    // Deserialization negative tests
    // =========================================================================

    #[test]
    fn privilege_method_rejects_invalid_value() {
        let result: Result<PrivilegeMethod, _> = serde_yaml::from_str("pkexec");
        assert!(result.is_err(), "pkexec should not be a valid PrivilegeMethod");
    }

    #[test]
    fn privilege_rejects_numeric_value() {
        let result: Result<Privilege, _> = serde_yaml::from_str("42");
        assert!(result.is_err(), "numeric value should not be valid for Privilege");
    }

    #[test]
    fn privilege_rejects_plain_string() {
        let result: Result<Privilege, _> = serde_yaml::from_str("\"sudo\"");
        assert!(result.is_err(), "plain string should not be valid for Privilege");
    }

    #[test]
    fn privilege_rejects_invalid_method_in_map() {
        let result: Result<Privilege, _> = serde_yaml::from_str("method: pkexec");
        assert!(result.is_err(), "pkexec should not be valid in privilege map");
    }

    // =========================================================================
    // visit_unit test
    // =========================================================================

    #[test]
    fn privilege_deserialize_null_returns_inherit() {
        let p: Privilege = serde_yaml::from_str("~").unwrap();
        assert_eq!(p, Privilege::Inherit);
    }

    // =========================================================================
    // Serialize → Deserialize roundtrip tests
    // =========================================================================

    fn roundtrip(original: &Privilege) -> Privilege {
        let yaml = serde_yaml::to_string(original).unwrap();
        serde_yaml::from_str(&yaml).unwrap()
    }

    #[test]
    fn serialize_roundtrip_inherit() {
        assert_eq!(roundtrip(&Privilege::Inherit), Privilege::Inherit);
    }

    #[test]
    fn serialize_roundtrip_use_default() {
        assert_eq!(roundtrip(&Privilege::UseDefault), Privilege::UseDefault);
    }

    #[test]
    fn serialize_roundtrip_disabled() {
        assert_eq!(roundtrip(&Privilege::Disabled), Privilege::Disabled);
    }

    #[test]
    fn serialize_roundtrip_method_sudo() {
        assert_eq!(
            roundtrip(&Privilege::Method(PrivilegeMethod::Sudo)),
            Privilege::Method(PrivilegeMethod::Sudo)
        );
    }

    #[test]
    fn serialize_roundtrip_method_doas() {
        assert_eq!(
            roundtrip(&Privilege::Method(PrivilegeMethod::Doas)),
            Privilege::Method(PrivilegeMethod::Doas)
        );
    }
}
