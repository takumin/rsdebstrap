//! Assemble phase module for post-provisioning tasks.
//!
//! This module provides the [`AssembleConfig`] named-field struct describing the
//! tasks that run after the main provisioning phase. Currently the only role is:
//! - [`resolv_conf`](AssembleConfig::resolv_conf) — writes a permanent `/etc/resolv.conf`
//!
//! The named-field shape makes "at most one resolv_conf" structural rather than
//! validated after the fact.

pub mod resolv_conf;

use serde::Deserialize;

pub use resolv_conf::AssembleResolvConfTask;

use crate::phase::PhaseItem;

/// Assemble phase configuration (named-field, schema-first).
///
/// The single field is an optional singleton; a duplicate YAML key is rejected
/// by `serde_yaml` at parse time and an unknown key by `deny_unknown_fields`.
#[derive(Debug, Deserialize, Default, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AssembleConfig {
    /// resolv_conf task writing a permanent `/etc/resolv.conf` into the final rootfs.
    #[serde(default)]
    pub resolv_conf: Option<AssembleResolvConfTask>,
}

impl AssembleConfig {
    /// Returns the present phase items in execution order.
    pub(crate) fn items(&self) -> Vec<&dyn PhaseItem> {
        let mut items: Vec<&dyn PhaseItem> = Vec::new();
        if let Some(resolv_conf) = &self.resolv_conf {
            items.push(resolv_conf);
        }
        items
    }

    /// Returns true if no assemble tasks are configured.
    pub fn is_empty(&self) -> bool {
        self.resolv_conf.is_none()
    }

    /// Returns the number of configured assemble tasks.
    pub fn len(&self) -> usize {
        usize::from(self.resolv_conf.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_resolv_conf_present() {
        let yaml = "resolv_conf:\n  name_servers:\n  - 8.8.8.8\n";
        let config: AssembleConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.resolv_conf.is_some());
        assert_eq!(config.len(), 1);
        assert!(!config.is_empty());
    }

    #[test]
    fn deserialize_absent_defaults_to_empty() {
        let config: AssembleConfig = serde_yaml::from_str("{}").unwrap();
        assert!(config.is_empty());
        assert_eq!(config.len(), 0);
        assert!(config.items().is_empty());
    }

    #[test]
    fn deserialize_rejects_unknown_field() {
        let yaml = "mount:\n  preset: recommends\n";
        let result: Result<AssembleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "unknown key must be rejected");
    }

    #[test]
    fn deserialize_rejects_duplicate_resolv_conf_key() {
        let yaml = "resolv_conf:\n  name_servers:\n  - 8.8.8.8\nresolv_conf:\n  link: ../run/x\n";
        let result: Result<AssembleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "duplicate resolv_conf key must be rejected at parse time");
    }
}
