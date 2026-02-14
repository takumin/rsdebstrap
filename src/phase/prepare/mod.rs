//! Prepare phase module for pre-provisioning tasks.
//!
//! This module provides the `PrepareTask` enum for tasks that run before
//! the main provisioning phase. Currently supports:
//! - [`Mount`](PrepareTask::Mount) — declares filesystem mounts for the rootfs
//! - [`ResolvConf`](PrepareTask::ResolvConf) — declares resolv.conf setup for DNS resolution

pub mod mount;
pub mod resolv_conf;

use std::borrow::Cow;

use serde::Deserialize;

pub use mount::MountTask;
pub use resolv_conf::ResolvConfTask;

use crate::config::IsolationConfig;
use crate::error::RsdebstrapError;
use crate::phase::PhaseItem;

/// Prepare phase task definition.
///
/// The `#[non_exhaustive]` attribute ensures that adding variants in the
/// future does not break downstream code.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
#[non_exhaustive]
pub enum PrepareTask {
    /// Mount task for declaring filesystem mounts
    Mount(MountTask),
    /// resolv_conf task for declaring DNS configuration
    #[serde(rename = "resolv_conf")]
    ResolvConf(ResolvConfTask),
}

impl PrepareTask {
    /// Returns a reference to the inner `MountTask` if this is a `Mount` variant.
    pub fn mount_task(&self) -> Option<&MountTask> {
        match self {
            Self::Mount(task) => Some(task),
            _ => None,
        }
    }

    /// Returns a reference to the inner `ResolvConfTask` if this is a `ResolvConf` variant.
    pub fn resolv_conf_task(&self) -> Option<&ResolvConfTask> {
        match self {
            Self::ResolvConf(task) => Some(task),
            _ => None,
        }
    }
}

impl PhaseItem for PrepareTask {
    fn name(&self) -> Cow<'_, str> {
        match self {
            Self::Mount(task) => Cow::Owned(format!("mount:{}", task.name())),
            Self::ResolvConf(task) => Cow::Owned(format!("resolv_conf:{}", task.name())),
        }
    }

    fn validate(&self) -> Result<(), RsdebstrapError> {
        match self {
            Self::Mount(task) => task.validate(),
            Self::ResolvConf(task) => task.validate(),
        }
    }

    fn execute(&self, _ctx: &dyn crate::isolation::IsolationContext) -> anyhow::Result<()> {
        match self {
            // Mount lifecycle is managed at the pipeline level, not per-task
            Self::Mount(_) => Ok(()),
            // resolv_conf lifecycle is managed at the pipeline level, not per-task
            Self::ResolvConf(_) => Ok(()),
        }
    }

    fn resolved_isolation_config(&self) -> Option<&IsolationConfig> {
        match self {
            // Mount tasks don't use per-task isolation
            Self::Mount(_) => None,
            // resolv_conf tasks don't use per-task isolation
            Self::ResolvConf(_) => None,
        }
    }
}
