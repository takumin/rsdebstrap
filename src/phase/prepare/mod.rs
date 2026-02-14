//! Prepare phase module for pre-provisioning tasks.
//!
//! This module provides the `PrepareTask` enum for tasks that run before
//! the main provisioning phase. Currently supports:
//! - [`Mount`](PrepareTask::Mount) — declares filesystem mounts for the rootfs

pub mod mount;

use std::borrow::Cow;

use serde::Deserialize;

pub use mount::MountTask;

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
}

impl PrepareTask {
    /// Returns a reference to the inner `MountTask` if this is a `Mount` variant.
    pub fn mount_task(&self) -> Option<&MountTask> {
        match self {
            Self::Mount(task) => Some(task),
        }
    }
}

impl PhaseItem for PrepareTask {
    fn name(&self) -> Cow<'_, str> {
        match self {
            Self::Mount(task) => Cow::Owned(format!("mount:{}", task.name())),
        }
    }

    fn validate(&self) -> Result<(), RsdebstrapError> {
        match self {
            Self::Mount(task) => task.validate(),
        }
    }

    fn execute(&self, _ctx: &dyn crate::isolation::IsolationContext) -> anyhow::Result<()> {
        match self {
            // Mount lifecycle is managed at the pipeline level, not per-task
            Self::Mount(_) => Ok(()),
        }
    }

    fn resolved_isolation_config(&self) -> Option<&IsolationConfig> {
        match self {
            // Mount tasks don't use per-task isolation
            Self::Mount(_) => None,
        }
    }
}
