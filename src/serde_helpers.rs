//! Shared serde helpers for `Inherit`/`UseDefault`/`Disabled`/explicit enum patterns.

/// Implements `Deserialize` and `Serialize` for enums with the
/// `Inherit` / `UseDefault` / `Disabled` / explicit-variant pattern.
///
/// The enum must have exactly four variants:
/// - `Inherit` — maps to YAML `null`/absent
/// - `UseDefault` — maps to YAML `true`
/// - `Disabled` — maps to YAML `false`
/// - An explicit variant — maps to a YAML map
///
/// # Parameters
///
/// - `$type`: The enum type name
/// - `$explicit`: The name of the explicit variant (e.g., `Method`, `Config`)
/// - `$expecting`: A human-readable description for error messages
/// - `$map_ident`: Identifier bound to the `MapAccess` in `visit_map`
/// - `$deser_body`: Expression block for `visit_map` that returns `Result<$type, A::Error>`
/// - `$val_ident`: Identifier bound to the inner value of the explicit variant during serialization
/// - `$ser_ident`: Identifier bound to the `Serializer`
/// - `$ser_body`: Expression block for serializing the explicit variant
macro_rules! impl_inherit_or_explicit_serde {
    (
        $type:ident,
        explicit: $explicit:ident,
        expecting: $expecting:expr,
        deserialize_map($map_ident:ident) $deser_body:block,
        serialize_explicit($val_ident:ident, $ser_ident:ident) $ser_body:block
    ) => {
        impl<'de> ::serde::Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                use ::serde::de;

                struct InheritVisitor;

                impl<'de> de::Visitor<'de> for InheritVisitor {
                    type Value = $type;

                    fn expecting(
                        &self,
                        formatter: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        formatter.write_str($expecting)
                    }

                    fn visit_unit<E>(self) -> ::std::result::Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        Ok($type::Inherit)
                    }

                    fn visit_bool<E>(self, v: bool) -> ::std::result::Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        if v {
                            Ok($type::UseDefault)
                        } else {
                            Ok($type::Disabled)
                        }
                    }

                    fn visit_map<A>(
                        self,
                        $map_ident: A,
                    ) -> ::std::result::Result<Self::Value, A::Error>
                    where
                        A: de::MapAccess<'de>,
                    {
                        $deser_body
                    }
                }

                deserializer.deserialize_any(InheritVisitor)
            }
        }

        impl ::serde::Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                match self {
                    Self::Inherit => serializer.serialize_none(),
                    Self::UseDefault => serializer.serialize_bool(true),
                    Self::Disabled => serializer.serialize_bool(false),
                    Self::$explicit($val_ident) => {
                        let $ser_ident = serializer;
                        $ser_body
                    }
                }
            }
        }
    };
}

pub(crate) use impl_inherit_or_explicit_serde;
