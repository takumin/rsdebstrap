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
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::sync::Arc;

use crate::config::IsolationConfig;
use crate::executor::{CommandExecutor, ExecutionResult};
use crate::privilege::PrivilegeMethod;
use crate::rootfs::RootfsOps;

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
        ops: Arc<dyn RootfsOps>,
        dry_run: bool,
    ) -> Result<Box<dyn IsolationContext>>;
}

/// Read-only view of the rootfs plus the operations that may mutate it.
///
/// This is the whole capability an assemble task gets. It deliberately has no
/// way to run a program: assemble writes the final state of the rootfs, and
/// every such write goes through [`rootfs_ops`](Self::rootfs_ops), which cannot
/// be redirected by a planted symlink. Anything that needs to run a program is
/// a provision task and gets an [`IsolationContext`] instead.
pub trait RootfsContext {
    /// Returns the path to the rootfs directory.
    fn rootfs(&self) -> &Utf8Path;

    /// Returns whether this context is in dry-run mode.
    ///
    /// When true, tasks should skip file I/O operations (script copy,
    /// permission changes, rootfs validation) while still constructing
    /// and passing commands to the executor, which handles dry-run
    /// semantics at its own level.
    fn dry_run(&self) -> bool;

    /// Returns the descriptor-anchored filesystem operations for this rootfs.
    ///
    /// Tasks that modify the rootfs use these rather than running `cp`/`mv`/`ln`
    /// through the executor: the operations here cannot be redirected by a
    /// symlink, and they escalate through one helper rather than once per
    /// command.
    fn rootfs_ops(&self) -> &dyn RootfsOps;
}

/// Active isolation context with command execution capability.
///
/// Represents an active isolation session. Commands can be executed within
/// this context, and resources are cleaned up when [`teardown`](Self::teardown)
/// is called or the context is dropped.
///
/// Contexts are not thread-safe by design - they represent a single
/// isolation session that should be used sequentially.
pub trait IsolationContext: RootfsContext + Send {
    /// Returns the name of this isolation backend.
    fn name(&self) -> &'static str;

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

/// A [`RootfsContext`] built from the values the pipeline already holds.
///
/// The assemble phase used to go through an [`IsolationProvider`], which always
/// resolved to [`DirectProvider`] and whose only used capability was
/// `rootfs_ops`. This replaces that setup/teardown round trip.
pub struct PlainRootfsContext {
    rootfs: camino::Utf8PathBuf,
    ops: Arc<dyn RootfsOps>,
    dry_run: bool,
}

impl PlainRootfsContext {
    pub fn new(rootfs: &Utf8Path, ops: Arc<dyn RootfsOps>, dry_run: bool) -> Self {
        Self {
            rootfs: rootfs.to_owned(),
            ops,
            dry_run,
        }
    }
}

impl RootfsContext for PlainRootfsContext {
    fn rootfs(&self) -> &Utf8Path {
        &self.rootfs
    }

    fn dry_run(&self) -> bool {
        self.dry_run
    }

    fn rootfs_ops(&self) -> &dyn RootfsOps {
        &*self.ops
    }
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
    /// Resolves the isolation setting against the profile defaults.
    ///
    /// Returns `Some(config)` if isolation should be applied,
    /// or `None` if isolation is disabled.
    ///
    /// Unlike `Privilege::resolve()`, this never returns an error because
    /// `IsolationConfig` always has a default (chroot).
    pub fn resolve(&self, defaults: &IsolationConfig) -> Option<IsolationConfig> {
        match self {
            Self::Inherit => Some(defaults.clone()),
            Self::UseDefault => Some(defaults.clone()),
            Self::Disabled => None,
            Self::Config(c) => Some(c.clone()),
        }
    }
}

// The accepted YAML shapes: `true`/`false`, `{ type: ... }`, or an explicit null (which —
// like field absence — resolves to `Inherit`). This one type drives both deserialization
// and schema generation, so the two cannot describe different acceptance sets. The map
// form reuses `IsolationConfig`, whose per-variant payload structs are
// `deny_unknown_fields` (the `type` tag is consumed before the payload sees the map).
//
// Plain `//` (not `///`) so this note does not leak into the schema's `description`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
enum TaskIsolationWire {
    Toggle(bool),
    Config(IsolationConfig),
    // Unit variant → `{ "type": "null" }` in the generated `anyOf`.
    Inherit,
}

impl From<TaskIsolationWire> for TaskIsolation {
    fn from(wire: TaskIsolationWire) -> Self {
        match wire {
            TaskIsolationWire::Toggle(true) => Self::UseDefault,
            TaskIsolationWire::Toggle(false) => Self::Disabled,
            TaskIsolationWire::Config(c) => Self::Config(c),
            TaskIsolationWire::Inherit => Self::Inherit,
        }
    }
}

impl<'de> Deserialize<'de> for TaskIsolation {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        TaskIsolationWire::deserialize(deserializer).map(Into::into)
    }
}

impl JsonSchema for TaskIsolation {
    fn schema_name() -> Cow<'static, str> {
        "TaskIsolation".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        TaskIsolationWire::json_schema(generator)
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

    #[test]
    fn task_isolation_deserialize_true() {
        let p: TaskIsolation = yaml_serde::from_str("true").unwrap();
        assert_eq!(p, TaskIsolation::UseDefault);
    }

    #[test]
    fn task_isolation_deserialize_false() {
        let p: TaskIsolation = yaml_serde::from_str("false").unwrap();
        assert_eq!(p, TaskIsolation::Disabled);
    }

    #[test]
    fn task_isolation_deserialize_chroot_map() {
        let p: TaskIsolation = yaml_serde::from_str("type: chroot").unwrap();
        assert_eq!(p, TaskIsolation::Config(IsolationConfig::chroot()));
    }

    #[test]
    fn task_isolation_deserialize_null_returns_inherit() {
        // An explicit null is accepted as Inherit (mirrors field absence).
        let p: TaskIsolation = yaml_serde::from_str("~").unwrap();
        assert_eq!(p, TaskIsolation::Inherit);
    }

    #[test]
    fn task_isolation_default_is_inherit() {
        assert_eq!(TaskIsolation::default(), TaskIsolation::Inherit);
    }

    #[test]
    fn task_isolation_rejects_numeric_value() {
        let result: std::result::Result<TaskIsolation, _> = yaml_serde::from_str("42");
        assert!(result.is_err());
    }

    #[test]
    fn task_isolation_rejects_plain_string() {
        let result: std::result::Result<TaskIsolation, _> = yaml_serde::from_str("\"chroot\"");
        assert!(result.is_err());
    }

    #[test]
    fn task_isolation_rejects_unknown_type() {
        let result: std::result::Result<TaskIsolation, _> =
            yaml_serde::from_str("type: nonexistent");
        assert!(result.is_err());
    }

    // `IsolationConfig` has a single variant, so `Inherit`, `UseDefault` and
    // `Config` all resolve to the same value and no assertion can tell those
    // three arms apart. Cover them as one case; `Disabled` below is the arm
    // that genuinely differs.
    #[test]
    fn resolve_non_disabled_arms_yield_the_default_config() {
        let defaults = IsolationConfig::chroot();
        for iso in [
            TaskIsolation::Inherit,
            TaskIsolation::UseDefault,
            TaskIsolation::Config(IsolationConfig::chroot()),
        ] {
            assert_eq!(iso.resolve(&defaults), Some(IsolationConfig::chroot()));
        }
    }

    #[test]
    fn resolve_disabled_returns_none() {
        let defaults = IsolationConfig::chroot();
        let result = TaskIsolation::Disabled.resolve(&defaults);
        assert_eq!(result, None);
    }

    fn roundtrip(original: &TaskIsolation) -> TaskIsolation {
        let yaml = yaml_serde::to_string(original).unwrap();
        yaml_serde::from_str(&yaml).unwrap()
    }

    // `Serialize` is hand-written to mirror the visitor, so every variant must
    // survive a round trip — including `Inherit`, which serializes to null.
    #[test]
    fn serialize_roundtrip_every_variant() {
        for original in [
            TaskIsolation::Inherit,
            TaskIsolation::UseDefault,
            TaskIsolation::Disabled,
            TaskIsolation::Config(IsolationConfig::chroot()),
        ] {
            assert_eq!(roundtrip(&original), original, "roundtrip changed {original:?}");
        }
    }

    // The acceptance set is now a property of one type, so this pins the boundary itself
    // rather than the agreement between two definitions.
    #[test]
    fn task_isolation_acceptance_set() {
        for (yaml, accepted) in [
            ("~", true),
            ("true", true),
            ("false", true),
            ("type: chroot", true),
            ("type: bogus", false),
            ("typ: chroot", false),
            ("{type: chroot, extra: 1}", false),
            ("{}", false),
            ("chroot", false),
            ("[]", false),
            ("42", false),
            ("42.5", false),
        ] {
            let got = yaml_serde::from_str::<TaskIsolation>(yaml).is_ok();
            assert_eq!(got, accepted, "{yaml:?}: accepted = {got}, expected {accepted}");
        }
    }
}
