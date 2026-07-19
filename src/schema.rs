//! JSON Schema helpers.
//!
//! This module hosts schema-only proxy types that let `#[derive(schemars::JsonSchema)]`
//! work for fields whose real types do not implement [`JsonSchema`] themselves.
//!
//! The canonical case is [`camino::Utf8PathBuf`]: `schemars` has no camino support and
//! the orphan rule forbids implementing `JsonSchema` for it in this crate. Instead of
//! hand-writing schema JSON at each path field, every path field points at
//! [`Utf8PathSchema`] via `#[schemars(with = "...")]`, so the "path is a string"
//! definition lives in exactly one place.

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator};

/// Schema proxy for camino path types (`Utf8PathBuf` / `Utf8Path`).
///
/// Paths serialize as plain strings in YAML/JSON, so this proxy reuses [`String`]'s
/// schema. Reference it from path fields with
/// `#[schemars(with = "crate::schema::Utf8PathSchema")]`.
///
/// Forgetting the attribute on a new `Utf8PathBuf` field is a compile error (the derive
/// requires `Utf8PathBuf: JsonSchema`, which does not hold), so schema drift cannot happen
/// silently. If paths ever need a richer schema (e.g. `format: "path"`), change it here once.
pub(crate) struct Utf8PathSchema;

impl JsonSchema for Utf8PathSchema {
    fn inline_schema() -> bool {
        // Trivial (string) schema — inline it rather than emitting a named `$ref`.
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "Utf8Path".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        String::json_schema(generator)
    }
}
