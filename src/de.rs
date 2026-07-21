//! Strict deserialization helpers for the YAML profile surface.
//!
//! `yaml_serde`'s text deserializer coerces *any* plain scalar into its raw text when a
//! field asks for a string: `dir: null` used to parse as the literal path `"null"`,
//! `source: 5` as `"5"`. The generated JSON Schema (and the JSON data model it
//! validates) types these fields as strings, so the coercion made the deserializer
//! accept documents the schema rejects — the false-reject class the schema tests
//! forbid. Worse, the coercion only applied outside internally tagged enums (serde's
//! tagged-content buffering resolves scalars first), so `target: 42` was accepted
//! under `prepare:` but rejected under `bootstrap:`.
//!
//! The helpers here route string-typed fields through `deserialize_any`, which surfaces
//! the *resolved* scalar type (a number arrives as `visit_u64`, `null` as `visit_unit`,
//! ...), so non-string scalars are rejected uniformly in every context — under both the
//! `yaml_serde` text deserializer and `serde_json` values, which keeps the parser and
//! the generated schema in agreement by construction.

use std::collections::HashMap;
use std::fmt;

use camino::Utf8PathBuf;
use serde::Deserialize;
use serde::de::{Deserializer, Error, Visitor};

/// Visitor accepting only genuine strings (no scalar-to-string coercion).
struct StrictStringVisitor;

impl Visitor<'_> for StrictStringVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string")
    }

    fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(v.to_owned())
    }
}

/// A `String` that deserializes strictly (used inside `Option` and collections).
struct StrictString(String);

impl<'de> Deserialize<'de> for StrictString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_any(StrictStringVisitor)
            .map(StrictString)
    }
}

/// Deserializes a `String` field, rejecting non-string scalars.
pub(crate) fn string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    deserializer.deserialize_any(StrictStringVisitor)
}

/// Deserializes a `Utf8PathBuf` field, rejecting non-string scalars.
pub(crate) fn path<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Utf8PathBuf, D::Error> {
    deserializer
        .deserialize_any(StrictStringVisitor)
        .map(Utf8PathBuf::from)
}

/// Deserializes an `Option<String>` field, rejecting non-string scalars.
///
/// `null` (and an empty value) still deserializes to `None`, matching plain
/// `Option<String>` semantics.
pub(crate) fn opt_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<StrictString>::deserialize(deserializer).map(|opt| opt.map(|s| s.0))
}

/// A `Utf8PathBuf` that deserializes strictly (used for map values).
struct StrictPath(Utf8PathBuf);

impl<'de> Deserialize<'de> for StrictPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_any(StrictStringVisitor)
            .map(|s| StrictPath(Utf8PathBuf::from(s)))
    }
}

/// Deserializes a defaulted field, mapping an explicit `null` to `T::default()`.
///
/// `yaml_serde` already deserializes an *empty* value into the default for container
/// fields (a section whose entries are all commented out stays valid), but an explicit
/// `null` used to be rejected. Mapping `null` to the default makes `null`, the empty
/// form, and an omitted key all mean the same thing — which is also how the generated
/// schema models these fields (nullable), since an empty YAML value *is* `null` in the
/// JSON data model.
pub(crate) fn null_to_default<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: Deserialize<'de> + Default,
    D: Deserializer<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// Deserializes a `Vec<String>` field: `null` means empty, elements are strict strings.
pub(crate) fn string_list<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    Ok(Option::<Vec<StrictString>>::deserialize(deserializer)?
        .map(|items| items.into_iter().map(|s| s.0).collect())
        .unwrap_or_default())
}

/// Deserializes a `HashMap<String, Utf8PathBuf>` field: `null` means empty, values are
/// strict paths.
pub(crate) fn path_map<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<HashMap<String, Utf8PathBuf>, D::Error> {
    Ok(Option::<HashMap<String, StrictPath>>::deserialize(deserializer)?
        .map(|map| map.into_iter().map(|(key, value)| (key, value.0)).collect())
        .unwrap_or_default())
}
