//! Assemble phase module for post-provisioning tasks.
//!
//! This module provides the `AssembleTask` enum for tasks that run after
//! the main provisioning phase. Currently supports:
//! - [`ResolvConf`](AssembleTask::ResolvConf) — writes a permanent `/etc/resolv.conf`

pub mod resolv_conf;

use std::borrow::Cow;

use serde::Deserialize;

pub use resolv_conf::AssembleResolvConfTask;

use crate::config::IsolationConfig;
use crate::error::RsdebstrapError;
use crate::phase::PhaseItem;

/// Assemble phase task definition.
///
/// The `#[non_exhaustive]` attribute ensures that adding variants in the
/// future does not break downstream code.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
#[non_exhaustive]
pub enum AssembleTask {
    /// resolv_conf task for writing a permanent `/etc/resolv.conf`
    #[serde(rename = "resolv_conf")]
    ResolvConf(AssembleResolvConfTask),
}

impl AssembleTask {
    /// Returns a reference to the inner `AssembleResolvConfTask` if this is a `ResolvConf` variant.
    pub fn resolv_conf_task(&self) -> Option<&AssembleResolvConfTask> {
        match self {
            Self::ResolvConf(task) => Some(task),
        }
    }
}

impl PhaseItem for AssembleTask {
    fn name(&self) -> Cow<'_, str> {
        match self {
            Self::ResolvConf(task) => Cow::Owned(format!("resolv_conf:{}", task.name())),
        }
    }

    fn validate(&self) -> Result<(), RsdebstrapError> {
        match self {
            Self::ResolvConf(task) => task.validate(),
        }
    }

    fn execute(&self, ctx: &dyn crate::isolation::IsolationContext) -> anyhow::Result<()> {
        match self {
            Self::ResolvConf(task) => task.execute(ctx),
        }
    }

    fn resolved_isolation_config(&self) -> Option<&IsolationConfig> {
        match self {
            // Assemble resolv_conf operates directly on rootfs filesystem
            Self::ResolvConf(_) => None,
        }
    }
}
