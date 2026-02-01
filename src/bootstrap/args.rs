//! Shared command argument builder utilities for bootstrap backends.

use std::ffi::OsString;
use std::fmt::Display;

/// Defines how a flag and its value are rendered in command arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagValueStyle {
    /// Render flag and value as separate arguments: `--flag value`.
    Separate,
    /// Render flag and value as a single argument with equals: `--flag=value`.
    Equals,
}

/// Builder for assembling command arguments consistently across bootstrap backends.
#[derive(Debug, Default)]
pub struct CommandArgsBuilder {
    args: Vec<OsString>,
}

impl CommandArgsBuilder {
    /// Create a new, empty builder.
    pub fn new() -> Self {
        Self { args: Vec::new() }
    }

    /// Append a raw argument to the builder.
    pub fn push_arg<S: Into<OsString>>(&mut self, arg: S) {
        self.args.push(arg.into());
    }

    /// Append a flag with no value.
    pub fn push_flag(&mut self, flag: &str) {
        self.args.push(flag.into());
    }

    /// Append a flag with value if the value is not empty.
    pub fn push_flag_value(&mut self, flag: &str, value: &str, style: FlagValueStyle) {
        if value.is_empty() {
            return;
        }

        match style {
            FlagValueStyle::Separate => {
                self.args.push(flag.into());
                self.args.push(value.into());
            }
            FlagValueStyle::Equals => {
                self.args.push(format!("{}={}", flag, value).into());
            }
        }
    }

    /// Append a flag for each non-empty value in `values`.
    pub fn push_flag_values(&mut self, flag: &str, values: &[String], style: FlagValueStyle) {
        for value in values {
            self.push_flag_value(flag, value, style);
        }
    }

    /// Append a flag with value if the value differs from its default.
    ///
    /// This is useful for enum types that implement `Default`, `PartialEq`, and `Display`,
    /// where you only want to add the flag when the value is non-default.
    pub fn push_if_not_default<T>(&mut self, flag: &str, value: &T, style: FlagValueStyle)
    where
        T: Default + PartialEq + Display,
    {
        if *value != T::default() {
            self.push_flag_value(flag, &value.to_string(), style);
        }
    }

    /// Return the collected arguments.
    pub fn into_args(self) -> Vec<OsString> {
        self.args
    }
}
