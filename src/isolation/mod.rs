//! Isolation module for executing commands in isolated environments.
//!
//! This module provides the trait and implementations for different
//! isolation backends (chroot, bwrap, systemd-nspawn, etc.) that can be used
//! to execute commands within a rootfs.
//!
//! ## Architecture
//!
//! The module uses a Provider/Context pattern:
//!
//! - [`IsolationProvider`]: Factory for creating isolation contexts. Stateless and shareable.
//! - [`IsolationContext`]: Represents an active isolation session with setup/teardown lifecycle.
//!
//! This pattern enables proper resource management for backends like bwrap or systemd-nspawn
//! that require mounting/unmounting operations.

use anyhow::Result;
use camino::Utf8Path;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock};

use crate::config::IsolationConfig;
use crate::executor::{CommandExecutor, ExecutionResult};
use crate::privilege::PrivilegeMethod;

/// Fallback isolation config for unresolved states.
/// Used by `resolved_config()` to fail-closed (use isolation) rather than
/// fail-open (bypass isolation) when called before resolution.
static DEFAULT_ISOLATION_CONFIG: LazyLock<IsolationConfig> =
    LazyLock::new(IsolationConfig::default);

pub mod chroot;
pub mod direct;
pub mod mount;
pub mod resolv_conf;

pub use chroot::{ChrootContext, ChrootProvider};
pub use direct::{DirectContext, DirectProvider};

/// Provider trait for creating isolation contexts.
///
/// Each isolation type (chroot, bwrap, systemd-nspawn, etc.) implements this trait
/// to provide the factory method for creating isolation contexts.
///
/// Providers are stateless and can be shared across threads.
pub trait IsolationProvider: Send + Sync {
    /// Returns the name of this isolation backend.
    fn name(&self) -> &'static str;

    /// Sets up the isolation environment and returns an active context.
    ///
    /// # Arguments
    /// * `rootfs` - The path to the rootfs directory
    /// * `executor` - The command executor for running commands
    /// * `dry_run` - If true, skip actual setup operations
    ///
    /// # Returns
    /// Result containing the active isolation context or an error.
    fn setup(
        &self,
        rootfs: &Utf8Path,
        executor: Arc<dyn CommandExecutor>,
        dry_run: bool,
    ) -> Result<Box<dyn IsolationContext>>;
}

/// Active isolation context with command execution capability.
///
/// Represents an active isolation session. Commands can be executed within
/// this context, and resources are cleaned up when [`teardown`](Self::teardown)
/// is called or the context is dropped.
///
/// Contexts are not thread-safe by design - they represent a single
/// isolation session that should be used sequentially.
pub trait IsolationContext: Send {
    /// Returns the name of this isolation backend.
    fn name(&self) -> &'static str;

    /// Returns the path to the rootfs directory.
    fn rootfs(&self) -> &Utf8Path;

    /// Returns whether this context is in dry-run mode.
    ///
    /// When true, tasks should skip file I/O operations (script copy,
    /// permission changes, rootfs validation) while still constructing
    /// and passing commands to the executor, which handles dry-run
    /// semantics at its own level.
    fn dry_run(&self) -> bool;

    /// Executes a command within the isolated environment.
    ///
    /// # Arguments
    /// * `command` - The command and arguments to execute
    /// * `privilege` - Optional privilege escalation method to wrap the command
    ///
    /// # Returns
    /// Result containing the execution result or an error.
    fn execute(
        &self,
        command: &[String],
        privilege: Option<PrivilegeMethod>,
    ) -> Result<ExecutionResult>;

    /// Tears down the isolation environment and releases resources.
    ///
    /// This method is idempotent - calling it multiple times has no effect
    /// after the first successful teardown.
    ///
    /// Implementations should also call this in their `Drop` impl for safety,
    /// but calling it explicitly allows for error handling. Note that `Drop`
    /// cannot propagate errors, so implementations should log failures as
    /// warnings in their `Drop` impl.
    fn teardown(&mut self) -> Result<()>;
}

/// Task-level isolation setting.
///
/// This type supports the following YAML representations:
/// - Absent (field not specified) → `Inherit` (use defaults)
/// - `isolation: true` → `UseDefault` (use defaults explicitly)
/// - `isolation: false` → `Disabled` (no isolation, direct execution)
/// - `isolation: { type: chroot }` → `Config(IsolationConfig::chroot())` (explicit)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum TaskIsolation {
    /// YAML field not specified — inherit from defaults.
    #[default]
    Inherit,
    /// `isolation: true` — use the default isolation config.
    UseDefault,
    /// `isolation: false` — no isolation (direct execution on host).
    Disabled,
    /// `isolation: { type: chroot }` — use the specified isolation config.
    Config(IsolationConfig),
}

impl TaskIsolation {
    /// Returns the resolved isolation config.
    ///
    /// Should only be called after [`resolve_in_place()`](Self::resolve_in_place).
    ///
    /// Returns `Some(&config)` for `Config`, `None` for `Disabled`.
    /// If called on `Inherit` or `UseDefault`, logs a warning and returns
    /// the default isolation config as a safe fallback (fail-closed).
    pub fn resolved_config(&self) -> Option<&IsolationConfig> {
        debug_assert!(
            !matches!(self, Self::Inherit | Self::UseDefault),
            "resolved_config() called on an unresolved TaskIsolation state. This is a logic error."
        );
        match self {
            Self::Config(c) => Some(c),
            Self::Disabled => None,
            unresolved @ (Self::Inherit | Self::UseDefault) => {
                tracing::warn!(
                    "resolved_config() called on unresolved state ({:?}); this likely indicates \
                    a logic error where resolve was not called. \
                    Falling back to default isolation config (fail-closed).",
                    unresolved
                );
                Some(&*DEFAULT_ISOLATION_CONFIG)
            }
        }
    }

    /// Resolves the isolation setting in place, replacing `self` with the
    /// resolved variant (`Config` or `Disabled`).
    pub fn resolve_in_place(&mut self, defaults: &IsolationConfig) {
        let resolved = self.resolve(defaults);
        *self = match resolved {
            Some(config) => Self::Config(config),
            None => Self::Disabled,
        };
    }

    /// Resolves the isolation setting against the profile defaults.
    ///
    /// Returns `Some(config)` if isolation should be applied,
    /// or `None` if isolation is disabled.
    ///
    /// Unlike `Privilege::resolve()`, this never returns an error because
    /// `IsolationConfig` always has a default value (`Chroot`).
    pub fn resolve(&self, defaults: &IsolationConfig) -> Option<IsolationConfig> {
        match self {
            Self::Inherit => Some(defaults.clone()),
            Self::UseDefault => Some(defaults.clone()),
            Self::Disabled => None,
            Self::Config(c) => Some(c.clone()),
        }
    }
}

impl<'de> Deserialize<'de> for TaskIsolation {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;

        struct TaskIsolationVisitor;

        impl<'de> de::Visitor<'de> for TaskIsolationVisitor {
            type Value = TaskIsolation;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a boolean or a map with a 'type' field")
            }

            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(TaskIsolation::Inherit)
            }

            fn visit_bool<E>(self, v: bool) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v {
                    Ok(TaskIsolation::UseDefault)
                } else {
                    Ok(TaskIsolation::Disabled)
                }
            }

            fn visit_map<A>(self, map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let config =
                    IsolationConfig::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(TaskIsolation::Config(config))
            }
        }

        deserializer.deserialize_any(TaskIsolationVisitor)
    }
}

impl Serialize for TaskIsolation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Inherit => serializer.serialize_none(),
            Self::UseDefault => serializer.serialize_bool(true),
            Self::Disabled => serializer.serialize_bool(false),
            Self::Config(c) => c.serialize(serializer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // TaskIsolation deserialization tests
    // =========================================================================

    #[test]
    fn task_isolation_deserialize_true() {
        let p: TaskIsolation = serde_yaml::from_str("true").unwrap();
        assert_eq!(p, TaskIsolation::UseDefault);
    }

    #[test]
    fn task_isolation_deserialize_false() {
        let p: TaskIsolation = serde_yaml::from_str("false").unwrap();
        assert_eq!(p, TaskIsolation::Disabled);
    }

    #[test]
    fn task_isolation_deserialize_chroot_map() {
        let p: TaskIsolation = serde_yaml::from_str("type: chroot").unwrap();
        assert_eq!(p, TaskIsolation::Config(IsolationConfig::chroot()));
    }

    #[test]
    fn task_isolation_deserialize_null_returns_inherit() {
        let p: TaskIsolation = serde_yaml::from_str("~").unwrap();
        assert_eq!(p, TaskIsolation::Inherit);
    }

    #[test]
    fn task_isolation_default_is_inherit() {
        assert_eq!(TaskIsolation::default(), TaskIsolation::Inherit);
    }

    #[test]
    fn task_isolation_rejects_numeric_value() {
        let result: std::result::Result<TaskIsolation, _> = serde_yaml::from_str("42");
        assert!(result.is_err());
    }

    #[test]
    fn task_isolation_rejects_plain_string() {
        let result: std::result::Result<TaskIsolation, _> = serde_yaml::from_str("\"chroot\"");
        assert!(result.is_err());
    }

    #[test]
    fn task_isolation_rejects_unknown_type() {
        let result: std::result::Result<TaskIsolation, _> =
            serde_yaml::from_str("type: nonexistent");
        assert!(result.is_err());
    }

    // =========================================================================
    // TaskIsolation::resolve tests
    // =========================================================================

    #[test]
    fn resolve_inherit_uses_defaults() {
        let defaults = IsolationConfig::chroot();
        let result = TaskIsolation::Inherit.resolve(&defaults);
        assert_eq!(result, Some(IsolationConfig::chroot()));
    }

    #[test]
    fn resolve_use_default_uses_defaults() {
        let defaults = IsolationConfig::chroot();
        let result = TaskIsolation::UseDefault.resolve(&defaults);
        assert_eq!(result, Some(IsolationConfig::chroot()));
    }

    #[test]
    fn resolve_disabled_returns_none() {
        let defaults = IsolationConfig::chroot();
        let result = TaskIsolation::Disabled.resolve(&defaults);
        assert_eq!(result, None);
    }

    #[test]
    fn resolve_config_uses_explicit() {
        let defaults = IsolationConfig::chroot();
        let result = TaskIsolation::Config(IsolationConfig::chroot()).resolve(&defaults);
        assert_eq!(result, Some(IsolationConfig::chroot()));
    }

    // =========================================================================
    // TaskIsolation::resolve_in_place tests
    // =========================================================================

    #[test]
    fn resolve_in_place_inherit() {
        let mut iso = TaskIsolation::Inherit;
        iso.resolve_in_place(&IsolationConfig::chroot());
        assert_eq!(iso, TaskIsolation::Config(IsolationConfig::chroot()));
    }

    #[test]
    fn resolve_in_place_disabled() {
        let mut iso = TaskIsolation::Disabled;
        iso.resolve_in_place(&IsolationConfig::chroot());
        assert_eq!(iso, TaskIsolation::Disabled);
    }

    #[test]
    fn resolve_in_place_use_default() {
        let mut iso = TaskIsolation::UseDefault;
        iso.resolve_in_place(&IsolationConfig::chroot());
        assert_eq!(iso, TaskIsolation::Config(IsolationConfig::chroot()));
    }

    // =========================================================================
    // TaskIsolation::resolved_config tests
    // =========================================================================

    #[test]
    fn resolved_config_returns_some_for_config() {
        let iso = TaskIsolation::Config(IsolationConfig::chroot());
        assert_eq!(iso.resolved_config(), Some(&IsolationConfig::chroot()));
    }

    #[test]
    fn resolved_config_returns_none_for_disabled() {
        let iso = TaskIsolation::Disabled;
        assert_eq!(iso.resolved_config(), None);
    }

    // =========================================================================
    // Serialize → Deserialize roundtrip tests
    // =========================================================================

    fn roundtrip(original: &TaskIsolation) -> TaskIsolation {
        let yaml = serde_yaml::to_string(original).unwrap();
        serde_yaml::from_str(&yaml).unwrap()
    }

    #[test]
    fn serialize_roundtrip_inherit() {
        assert_eq!(roundtrip(&TaskIsolation::Inherit), TaskIsolation::Inherit);
    }

    #[test]
    fn serialize_roundtrip_use_default() {
        assert_eq!(roundtrip(&TaskIsolation::UseDefault), TaskIsolation::UseDefault);
    }

    #[test]
    fn serialize_roundtrip_disabled() {
        assert_eq!(roundtrip(&TaskIsolation::Disabled), TaskIsolation::Disabled);
    }

    #[test]
    fn serialize_roundtrip_config_chroot() {
        assert_eq!(
            roundtrip(&TaskIsolation::Config(IsolationConfig::chroot())),
            TaskIsolation::Config(IsolationConfig::chroot())
        );
    }
}
