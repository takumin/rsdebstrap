//! Profile variables: the `vars:` section and `${{ vars.<name> }}` substitution.
//!
//! A profile declares its variables with their default values under `vars:`. Each one may
//! be overridden by the environment (`RSDEBSTRAP_VAR_<NAME>`) and then by the command
//! line (`--var name=value`), and every string in the profile may reference one.
//!
//! Substitution happens inside deserialization rather than on the YAML text or on a parsed
//! value tree; `docs/ARCHITECTURE.md` (Profile variables) records why, and which strings it
//! deliberately leaves alone.

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;

use serde::de::{
    DeserializeSeed, Deserializer, EnumAccess, Error, MapAccess, SeqAccess, VariantAccess, Visitor,
};

use crate::error::RsdebstrapError;

/// Prefix of the environment variables that override a profile variable.
pub const ENV_PREFIX: &str = "RSDEBSTRAP_VAR_";

const OPEN: &str = "${{";
const CLOSE: &str = "}}";
const REFERENCE_PREFIX: &str = "vars.";

/// Whether `name` is usable as a variable name.
///
/// Lowercase only, so that the environment variable spelling (`RSDEBSTRAP_VAR_` plus the
/// name in uppercase) maps back to exactly one variable.
pub(crate) fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Parses a `NAME=VALUE` command-line assignment.
pub fn parse_assignment(arg: &str) -> Result<(String, String), String> {
    let (name, value) = arg
        .split_once('=')
        .ok_or_else(|| format!("expected NAME=VALUE, got {arg:?}"))?;
    if !is_valid_name(name) {
        return Err(format!("invalid variable name {name:?}: must match [a-z][a-z0-9_]*"));
    }
    Ok((name.to_owned(), value.to_owned()))
}

/// Values that override the defaults a profile declares under `vars:`.
#[derive(Debug, Clone, Default)]
pub struct VarOverrides {
    env: Vec<(String, String)>,
    cli: Vec<(String, String)>,
}

impl VarOverrides {
    /// Builds overrides from `RSDEBSTRAP_VAR_*` environment entries and command-line
    /// assignments. Command-line values take precedence.
    ///
    /// `env` takes `(environment variable name, value)` pairs; entries without the
    /// prefix are ignored, so the whole process environment may be passed.
    ///
    /// # Errors
    ///
    /// Returns `RsdebstrapError::Validation` if a prefixed environment variable does not
    /// spell a valid variable name in uppercase.
    pub fn new(
        env: impl IntoIterator<Item = (String, String)>,
        cli: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, RsdebstrapError> {
        let mut parsed = Vec::new();
        for (key, value) in env {
            let Some(suffix) = key.strip_prefix(ENV_PREFIX) else {
                continue;
            };
            let name = suffix.to_ascii_lowercase();
            if suffix != name.to_ascii_uppercase() || !is_valid_name(&name) {
                return Err(RsdebstrapError::Validation(format!(
                    "environment variable {key} does not name a profile variable: \
                    expected {ENV_PREFIX} followed by [A-Z][A-Z0-9_]*"
                )));
            }
            parsed.push((name, value));
        }
        // The environment's iteration order is unspecified; sorting keeps the log output
        // and the error for the first undeclared variable stable.
        parsed.sort();
        Ok(Self {
            env: parsed,
            cli: cli.into_iter().collect(),
        })
    }

    /// Like [`new`](Self::new), reading the environment of this process.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new), and also if a `RSDEBSTRAP_VAR_*` value is not valid UTF-8.
    pub fn from_process_env(
        cli: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, RsdebstrapError> {
        let mut env = Vec::new();
        for (key, value) in std::env::vars_os() {
            let Some(key) = key.to_str().filter(|k| k.starts_with(ENV_PREFIX)) else {
                continue;
            };
            let value = value.into_string().map_err(|_| {
                RsdebstrapError::Validation(format!("environment variable {key} is not UTF-8"))
            })?;
            env.push((key.to_owned(), value));
        }
        Self::new(env, cli)
    }

    /// Applies the overrides to the variables a profile declared.
    ///
    /// Only declared variables can be overridden: a value for any other name is an error,
    /// so a misspelled matrix key fails the build instead of silently building the default.
    pub(crate) fn apply(
        &self,
        mut vars: BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, String>, RsdebstrapError> {
        let env = self
            .env
            .iter()
            .map(|(name, value)| (name, value, format!("{ENV_PREFIX}{}", name.to_uppercase())));
        let cli = self
            .cli
            .iter()
            .map(|(name, value)| (name, value, format!("--var {name}")));
        for (name, value, origin) in env.chain(cli) {
            let Some(slot) = vars.get_mut(name) else {
                return Err(RsdebstrapError::Validation(format!(
                    "{origin} sets variable `{name}`, which the profile does not declare \
                    under `vars:`{}",
                    declared_list(&vars)
                )));
            };
            tracing::info!("vars.{name} = {value:?} (from {origin})");
            value.clone_into(slot);
        }
        if !vars.is_empty() {
            let resolved: Vec<String> = vars.iter().map(|(k, v)| format!("{k}={v:?}")).collect();
            tracing::info!("profile vars: {}", resolved.join(", "));
        }
        Ok(vars)
    }
}

fn declared_list(vars: &BTreeMap<String, String>) -> String {
    if vars.is_empty() {
        return " (it declares none)".to_owned();
    }
    let names: Vec<&str> = vars.keys().map(String::as_str).collect();
    format!(" (declared: {})", names.join(", "))
}

/// Replaces every `${{ vars.<name> }}` in `input` with the variable's value.
///
/// Values are inserted as they are; a value that itself contains `${{` is not expanded
/// again.
pub(crate) fn substitute<'s>(
    input: &'s str,
    vars: &BTreeMap<String, String>,
) -> Result<Cow<'s, str>, String> {
    if !input.contains(OPEN) {
        return Ok(Cow::Borrowed(input));
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find(OPEN) {
        out.push_str(&rest[..start]);
        let after_open = &rest[start + OPEN.len()..];
        let end = after_open
            .find(CLOSE)
            .ok_or_else(|| format!("unterminated `{OPEN}` in {input:?}"))?;
        let expr = after_open[..end].trim();
        let name = expr
            .strip_prefix(REFERENCE_PREFIX)
            .filter(|name| is_valid_name(name))
            .ok_or_else(|| {
                format!(
                    "unsupported expression `{OPEN} {expr} {CLOSE}` in {input:?}: \
                    only `{OPEN} vars.<name> {CLOSE}` is supported"
                )
            })?;
        let value = vars.get(name).ok_or_else(|| {
            format!("undefined variable `{name}` in {input:?}{}", declared_list(vars))
        })?;
        out.push_str(value);
        rest = &after_open[end + CLOSE.len()..];
    }
    out.push_str(rest);
    Ok(Cow::Owned(out))
}

/// Where in the profile a value sits, as far as substitution cares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    Root,
    Provision,
    ProvisionTask,
    Substitute,
    // `vars:` itself (values are literal, not expressions over each other) and a provision
    // task's inline `content` (a script; see `docs/ARCHITECTURE.md`).
    Verbatim,
}

impl Scope {
    fn value_of(self, key: Option<&str>) -> Self {
        match (self, key) {
            (Self::Verbatim, _) => Self::Verbatim,
            (Self::Root, Some("vars")) => Self::Verbatim,
            (Self::Root, Some("provision")) => Self::Provision,
            (Self::ProvisionTask, Some("content")) => Self::Verbatim,
            _ => Self::Substitute,
        }
    }

    fn element(self) -> Self {
        match self {
            Self::Verbatim => Self::Verbatim,
            Self::Provision => Self::ProvisionTask,
            _ => Self::Substitute,
        }
    }
}

#[derive(Clone, Copy)]
struct Ctx<'a> {
    vars: &'a BTreeMap<String, String>,
    scope: Scope,
    // Set while a map key is being deserialized: the key is recorded here, unchanged, so
    // that the map can pick the scope of the value that follows.
    key: Option<&'a Cell<Option<String>>>,
}

impl<'a> Ctx<'a> {
    fn with_scope(self, scope: Scope) -> Ctx<'a> {
        Ctx {
            vars: self.vars,
            scope,
            key: None,
        }
    }
}

/// A deserializer that substitutes `${{ vars.<name> }}` in the strings `inner` produces.
///
/// Every request is forwarded to `inner` with the same method, so the wrapped
/// deserializer's own scalar handling — and its error locations — are unchanged.
pub(crate) struct Substituting<'a, D> {
    inner: D,
    ctx: Ctx<'a>,
}

impl<'a, D> Substituting<'a, D> {
    pub(crate) fn new(inner: D, vars: &'a BTreeMap<String, String>) -> Self {
        Self {
            inner,
            ctx: Ctx {
                vars,
                scope: Scope::Root,
                key: None,
            },
        }
    }
}

macro_rules! forward_deserialize {
    ($($method:ident($($arg:ident: $ty:ty),*);)*) => {
        $(
            fn $method<V: Visitor<'de>>(
                self,
                $($arg: $ty,)*
                visitor: V,
            ) -> Result<V::Value, Self::Error> {
                self.inner.$method($($arg,)* Visit { inner: visitor, ctx: self.ctx })
            }
        )*
    };
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Substituting<'_, D> {
    type Error = D::Error;

    forward_deserialize! {
        deserialize_any();
        deserialize_bool();
        deserialize_i8();
        deserialize_i16();
        deserialize_i32();
        deserialize_i64();
        deserialize_i128();
        deserialize_u8();
        deserialize_u16();
        deserialize_u32();
        deserialize_u64();
        deserialize_u128();
        deserialize_f32();
        deserialize_f64();
        deserialize_char();
        deserialize_str();
        deserialize_string();
        deserialize_bytes();
        deserialize_byte_buf();
        deserialize_option();
        deserialize_unit();
        deserialize_unit_struct(name: &'static str);
        deserialize_newtype_struct(name: &'static str);
        deserialize_seq();
        deserialize_tuple(len: usize);
        deserialize_tuple_struct(name: &'static str, len: usize);
        deserialize_map();
        deserialize_struct(name: &'static str, fields: &'static [&'static str]);
        deserialize_enum(name: &'static str, variants: &'static [&'static str]);
        deserialize_identifier();
        deserialize_ignored_any();
    }

    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

struct Visit<'a, V> {
    inner: V,
    ctx: Ctx<'a>,
}

impl<V> Visit<'_, V> {
    fn substitute<'s, E: Error>(&self, v: &'s str) -> Result<Cow<'s, str>, E> {
        if let Some(slot) = self.ctx.key {
            slot.set(Some(v.to_owned()));
            return Ok(Cow::Borrowed(v));
        }
        if self.ctx.scope == Scope::Verbatim {
            return Ok(Cow::Borrowed(v));
        }
        substitute(v, self.ctx.vars).map_err(E::custom)
    }
}

macro_rules! forward_visit {
    ($($method:ident($ty:ty);)*) => {
        $(
            fn $method<E: Error>(self, v: $ty) -> Result<Self::Value, E> {
                self.inner.$method(v)
            }
        )*
    };
}

impl<'de, V: Visitor<'de>> Visitor<'de> for Visit<'_, V> {
    type Value = V::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.inner.expecting(formatter)
    }

    forward_visit! {
        visit_bool(bool);
        visit_i8(i8);
        visit_i16(i16);
        visit_i32(i32);
        visit_i64(i64);
        visit_i128(i128);
        visit_u8(u8);
        visit_u16(u16);
        visit_u32(u32);
        visit_u64(u64);
        visit_u128(u128);
        visit_f32(f32);
        visit_f64(f64);
        visit_char(char);
        visit_bytes(&[u8]);
        visit_borrowed_bytes(&'de [u8]);
        visit_byte_buf(Vec<u8>);
    }

    fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
        match self.substitute(v)? {
            Cow::Borrowed(v) => self.inner.visit_str(v),
            Cow::Owned(s) => self.inner.visit_string(s),
        }
    }

    fn visit_borrowed_str<E: Error>(self, v: &'de str) -> Result<Self::Value, E> {
        match self.substitute(v)? {
            Cow::Borrowed(v) => self.inner.visit_borrowed_str(v),
            Cow::Owned(s) => self.inner.visit_string(s),
        }
    }

    fn visit_string<E: Error>(self, v: String) -> Result<Self::Value, E> {
        match self.substitute(&v)? {
            Cow::Borrowed(_) => self.inner.visit_string(v),
            Cow::Owned(s) => self.inner.visit_string(s),
        }
    }

    fn visit_none<E: Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_none()
    }

    fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_unit()
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        self.inner.visit_some(Substituting {
            inner: deserializer,
            ctx: self.ctx,
        })
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        self.inner.visit_newtype_struct(Substituting {
            inner: deserializer,
            ctx: self.ctx,
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_seq(Seq {
            inner: seq,
            ctx: self.ctx.with_scope(self.ctx.scope.element()),
        })
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_map(Map {
            inner: map,
            ctx: self.ctx.with_scope(self.ctx.scope),
            key: Cell::new(None),
        })
    }

    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_enum(Enum {
            inner: data,
            ctx: self.ctx.with_scope(self.ctx.scope.value_of(None)),
        })
    }
}

struct Seed<'a, S> {
    inner: S,
    ctx: Ctx<'a>,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Seed<'_, S> {
    type Value = S::Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<S::Value, D::Error> {
        self.inner.deserialize(Substituting {
            inner: deserializer,
            ctx: self.ctx,
        })
    }
}

struct Seq<'a, A> {
    inner: A,
    ctx: Ctx<'a>,
}

impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for Seq<'_, A> {
    type Error = A::Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, A::Error> {
        self.inner.next_element_seed(Seed {
            inner: seed,
            ctx: self.ctx,
        })
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

struct Map<'a, A> {
    inner: A,
    ctx: Ctx<'a>,
    key: Cell<Option<String>>,
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for Map<'_, A> {
    type Error = A::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, A::Error> {
        self.key.set(None);
        self.inner.next_key_seed(Seed {
            inner: seed,
            ctx: Ctx {
                vars: self.ctx.vars,
                scope: Scope::Verbatim,
                key: Some(&self.key),
            },
        })
    }

    fn next_value_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<T::Value, A::Error> {
        let key = self.key.take();
        self.inner.next_value_seed(Seed {
            inner: seed,
            ctx: self.ctx.with_scope(self.ctx.scope.value_of(key.as_deref())),
        })
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

struct Enum<'a, A> {
    inner: A,
    ctx: Ctx<'a>,
}

impl<'a, 'de, A: EnumAccess<'de>> EnumAccess<'de> for Enum<'a, A> {
    type Error = A::Error;
    type Variant = Variant<'a, A::Variant>;

    fn variant_seed<T: DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<(T::Value, Self::Variant), A::Error> {
        let (value, variant) = self.inner.variant_seed(Seed {
            inner: seed,
            ctx: self.ctx,
        })?;
        Ok((
            value,
            Variant {
                inner: variant,
                ctx: self.ctx,
            },
        ))
    }
}

struct Variant<'a, A> {
    inner: A,
    ctx: Ctx<'a>,
}

impl<'de, A: VariantAccess<'de>> VariantAccess<'de> for Variant<'_, A> {
    type Error = A::Error;

    fn unit_variant(self) -> Result<(), A::Error> {
        self.inner.unit_variant()
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, A::Error> {
        self.inner.newtype_variant_seed(Seed {
            inner: seed,
            ctx: self.ctx,
        })
    }

    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, A::Error> {
        self.inner.tuple_variant(
            len,
            Visit {
                inner: visitor,
                ctx: self.ctx,
            },
        )
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, A::Error> {
        self.inner.struct_variant(
            fields,
            Visit {
                inner: visitor,
                ctx: self.ctx,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn substitute_replaces_every_reference() {
        let vars = vars(&[("suite", "trixie"), ("arch", "amd64")]);
        assert_eq!(
            substitute("/tmp/${{ vars.suite }}-${{vars.arch}}", &vars).unwrap(),
            "/tmp/trixie-amd64"
        );
    }

    #[test]
    fn substitute_borrows_when_there_is_no_reference() {
        let vars = vars(&[]);
        assert!(matches!(substitute("plain $HOME {{x}}", &vars), Ok(Cow::Borrowed(_))));
    }

    #[test]
    fn substitute_does_not_expand_a_value_again() {
        let vars = vars(&[("a", "${{ vars.b }}"), ("b", "x")]);
        assert_eq!(substitute("${{ vars.a }}", &vars).unwrap(), "${{ vars.b }}");
    }

    #[test]
    fn substitute_rejects_malformed_references() {
        let vars = vars(&[("suite", "trixie")]);
        for (input, needle) in [
            ("${{ vars.suite", "unterminated"),
            ("${{ env.HOME }}", "unsupported expression"),
            ("${{ vars.Suite }}", "unsupported expression"),
            ("${{ vars.kernel }}", "undefined variable `kernel`"),
        ] {
            let err = substitute(input, &vars).unwrap_err();
            assert!(err.contains(needle), "{input}: {err}");
        }
    }

    #[test]
    fn variable_names_are_lowercase_identifiers() {
        for name in ["suite", "a", "kernel_flavor", "v2"] {
            assert!(is_valid_name(name), "{name}");
        }
        for name in ["", "Suite", "2v", "_x", "a-b", "a.b"] {
            assert!(!is_valid_name(name), "{name}");
        }
    }

    #[test]
    fn parse_assignment_splits_at_the_first_equals_sign() {
        assert_eq!(
            parse_assignment("include=a=b").unwrap(),
            ("include".to_owned(), "a=b".to_owned())
        );
        assert_eq!(parse_assignment("suite=").unwrap(), ("suite".to_owned(), String::new()));
        assert!(parse_assignment("suite").is_err());
        assert!(parse_assignment("SUITE=x").is_err());
    }

    #[test]
    fn command_line_overrides_take_precedence_over_the_environment() {
        let overrides = VarOverrides::new(
            [
                ("RSDEBSTRAP_VAR_SUITE".to_owned(), "bookworm".to_owned()),
                ("RSDEBSTRAP_VAR_ARCH".to_owned(), "arm64".to_owned()),
                // Unprefixed entries belong to someone else.
                ("PATH".to_owned(), "/usr/bin".to_owned()),
            ],
            [("suite".to_owned(), "sid".to_owned())],
        )
        .unwrap();
        let resolved = overrides
            .apply(vars(&[("suite", "trixie"), ("arch", "amd64"), ("role", "server")]))
            .unwrap();
        assert_eq!(resolved, vars(&[("suite", "sid"), ("arch", "arm64"), ("role", "server")]));
    }

    #[test]
    fn overriding_an_undeclared_variable_is_an_error() {
        let from_env =
            VarOverrides::new([("RSDEBSTRAP_VAR_SUTIE".to_owned(), "sid".to_owned())], []).unwrap();
        let err = from_env.apply(vars(&[("suite", "trixie")])).unwrap_err();
        assert!(err.to_string().contains("RSDEBSTRAP_VAR_SUTIE"), "{err}");
        assert!(err.to_string().contains("declared: suite"), "{err}");

        let from_cli = VarOverrides::new([], [("arch".to_owned(), "arm64".to_owned())]).unwrap();
        let err = from_cli.apply(vars(&[])).unwrap_err();
        assert!(err.to_string().contains("--var arch"), "{err}");
    }

    #[test]
    fn environment_names_must_be_uppercase_identifiers() {
        for key in [
            "RSDEBSTRAP_VAR_suite",
            "RSDEBSTRAP_VAR_",
            "RSDEBSTRAP_VAR_A-B",
        ] {
            let err = VarOverrides::new([(key.to_owned(), "x".to_owned())], []).unwrap_err();
            assert!(err.to_string().contains(key), "{err}");
        }
    }
}
