//! `when:` conditions: CEL expressions over the profile's variables.
//!
//! A condition is parsed when the profile is, so a syntax error is reported with the
//! field and line, and evaluated once the variables are final (after overrides). The
//! expression sees one variable, `vars`, a map from each declared name to its value.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::fmt;

use cel::{Context, Program, Value};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer};

/// A CEL expression that decides whether a task runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    source: String,
}

impl Condition {
    /// Parses `source` as a CEL expression.
    ///
    /// # Errors
    ///
    /// Returns a message describing the problem if `source` is not a CEL expression.
    pub fn new(source: impl Into<String>) -> Result<Self, String> {
        let source = source.into();
        // `${{ … }}` is the substitution syntax everywhere else in a profile, so it is the
        // likeliest mistake here; CEL's own error for it ("mismatched input '$'") would not
        // say what to write instead.
        if source.contains("${{") {
            return Err(format!(
                "`when: {source}` is a CEL expression, not a `${{{{ … }}}}` reference: \
                write it without the braces, e.g. `when: vars.suite == 'trixie'`"
            ));
        }
        Program::compile(&source)
            .map_err(|e| format!("`when: {source}` is not a valid CEL expression: {e}"))?;
        Ok(Self { source })
    }

    /// The expression as written in the profile.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Evaluates the expression with `vars` bound to the profile's variables.
    ///
    /// # Errors
    ///
    /// Returns a message if evaluation fails — for instance on a variable the profile
    /// does not declare — or if the result is not a `bool`.
    pub fn evaluate(&self, vars: &BTreeMap<String, String>) -> Result<bool, String> {
        let program = Program::compile(&self.source)
            .map_err(|e| format!("`when: {}` is not a valid CEL expression: {e}", self.source))?;
        let vars: HashMap<String, String> =
            vars.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let mut context = Context::default();
        context.add_variable_from_value("vars", vars);
        match program.execute(&context) {
            Ok(Value::Bool(b)) => Ok(b),
            Ok(other) => Err(format!(
                "`when: {}` must evaluate to a bool, but evaluated to {other:?}",
                self.source
            )),
            Err(e) => Err(format!("`when: {}` failed to evaluate: {e}", self.source)),
        }
    }
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

impl<'de> Deserialize<'de> for Condition {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let source = String::deserialize(deserializer)?;
        Self::new(source).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for Condition {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "Condition".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({ "type": "string", "minLength": 1 })
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
    fn evaluates_against_the_variables() {
        let vars = vars(&[
            ("distrib", "debian"),
            ("suite", "trixie"),
            ("version", "13"),
        ]);
        for (source, expected) in [
            ("vars.distrib == 'debian'", true),
            ("vars.distrib == 'ubuntu'", false),
            ("vars.suite in ['bookworm', 'trixie']", true),
            ("vars.distrib == 'debian' && vars.suite != 'trixie'", false),
            ("vars.suite.startsWith('tri')", true),
            ("'kernel' in vars", false),
            ("int(vars.version) >= 13", true),
        ] {
            let condition = Condition::new(source).unwrap();
            assert_eq!(condition.evaluate(&vars), Ok(expected), "{source}");
        }
    }

    #[test]
    fn rejects_malformed_expressions_when_parsed() {
        for (source, needle) in [
            ("vars.suite ==", "not a valid CEL expression"),
            ("${{ vars.suite }} == 'trixie'", "without the braces"),
        ] {
            let err = Condition::new(source).unwrap_err();
            assert!(err.contains(needle), "{source}: {err}");
        }
    }

    #[test]
    fn evaluation_errors_are_reported_rather_than_read_as_false() {
        let vars = vars(&[("suite", "trixie")]);
        for (source, needle) in [
            // A misspelled variable must not quietly skip the task.
            ("vars.sutie == 'trixie'", "failed to evaluate"),
            ("suite == 'trixie'", "failed to evaluate"),
            ("vars.suite", "must evaluate to a bool"),
        ] {
            let err = Condition::new(source).unwrap().evaluate(&vars).unwrap_err();
            assert!(err.contains(needle), "{source}: {err}");
        }
    }
}
