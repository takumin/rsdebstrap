//! Strict deserialization helpers for the YAML profile surface.
//!
//! `serde_yaml`'s text deserializer coerces *any* plain scalar into its raw text when a
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
//! `serde_yaml` text deserializer and `serde_json` values, which keeps the parser and
//! the generated schema in agreement by construction.

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
