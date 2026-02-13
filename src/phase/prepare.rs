//! Prepare phase module for pre-provisioning tasks.
//!
//! Currently empty — variants will be added when prepare-specific
//! task types are introduced (e.g., partition, format, debootstrap hooks).

use std::borrow::Cow;

use serde::Deserialize;

use crate::config::IsolationConfig;
use crate::error::RsdebstrapError;
use crate::phase::PhaseItem;

/// Prepare phase task definition.
///
/// Currently has no variants. The `#[non_exhaustive]` attribute ensures
/// that adding variants in the future does not break downstream code.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
#[non_exhaustive]
pub enum PrepareTask {}

impl PhaseItem for PrepareTask {
    fn name(&self) -> Cow<'_, str> {
        match *self {}
    }

    fn validate(&self) -> Result<(), RsdebstrapError> {
        match *self {}
    }

    fn execute(&self, _ctx: &dyn crate::isolation::IsolationContext) -> anyhow::Result<()> {
        match *self {}
    }

    fn resolved_isolation_config(&self) -> Option<&IsolationConfig> {
        match *self {}
    }
}
