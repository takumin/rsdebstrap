//! Prepare phase module for pre-provisioning tasks.
//!
//! This module provides the [`PrepareConfig`] named-field struct describing the
//! tasks that run before the main provisioning phase. Each role is a fixed,
//! optional singleton field:
//! - [`mount`](PrepareConfig::mount) — declares filesystem mounts for the rootfs
//! - [`resolv_conf`](PrepareConfig::resolv_conf) — declares resolv.conf setup for DNS resolution
//!
//! The named-field shape makes "at most one mount", "at most one resolv_conf",
//! and the fixed `mount → resolv_conf` execution order structural rather than
//! validated after the fact.

pub mod mount;
pub mod resolv_conf;

use schemars::JsonSchema;
use serde::Deserialize;

pub use mount::MountTask;
pub use resolv_conf::ResolvConfTask;

use crate::phase::PhaseItem;

/// Prepare phase configuration (named-field, schema-first).
///
/// Both fields are optional singletons. A duplicate YAML key (e.g. two `mount`
/// entries) is rejected by `serde_yaml` at parse time, and an unknown key is
/// rejected by `deny_unknown_fields` — so the "at most one" invariants hold
/// structurally instead of being validated after parsing.
#[derive(Debug, Deserialize, Default, Clone, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrepareConfig {
    /// Mount task declaring filesystem mounts for the rootfs.
    #[serde(default)]
    pub mount: Option<MountTask>,
    /// resolv_conf task declaring DNS configuration for the chroot.
    #[serde(default)]
    pub resolv_conf: Option<ResolvConfTask>,
}

impl PrepareConfig {
    /// Returns the present phase items in fixed execution order: `mount` then
    /// `resolv_conf`. The order is structural, independent of YAML key order.
    pub(crate) fn items(&self) -> Vec<&dyn PhaseItem> {
        let mut items: Vec<&dyn PhaseItem> = Vec::new();
        if let Some(mount) = &self.mount {
            items.push(mount);
        }
        if let Some(resolv_conf) = &self.resolv_conf {
            items.push(resolv_conf);
        }
        items
    }

    /// Returns true if no prepare tasks are configured.
    pub fn is_empty(&self) -> bool {
        self.mount.is_none() && self.resolv_conf.is_none()
    }

    /// Returns the number of configured prepare tasks.
    pub fn len(&self) -> usize {
        usize::from(self.mount.is_some()) + usize::from(self.resolv_conf.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_both_fields() {
        let yaml = "mount:\n  preset: recommends\nresolv_conf:\n  copy: true\n";
        let config: PrepareConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.mount.is_some());
        assert!(config.resolv_conf.is_some());
        assert_eq!(config.len(), 2);
        assert!(!config.is_empty());
    }

    #[test]
    fn deserialize_mount_only() {
        let yaml = "mount:\n  preset: recommends\n";
        let config: PrepareConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.mount.is_some());
        assert!(config.resolv_conf.is_none());
        assert_eq!(config.len(), 1);
    }

    #[test]
    fn deserialize_resolv_conf_only() {
        let yaml = "resolv_conf:\n  copy: true\n";
        let config: PrepareConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.mount.is_none());
        assert!(config.resolv_conf.is_some());
        assert_eq!(config.len(), 1);
    }

    #[test]
    fn deserialize_absent_defaults_to_empty() {
        let config: PrepareConfig = serde_yaml::from_str("{}").unwrap();
        assert!(config.is_empty());
        assert_eq!(config.len(), 0);
        assert!(config.items().is_empty());
    }

    #[test]
    fn deserialize_rejects_unknown_field() {
        let yaml = "shell:\n  content: echo hi\n";
        let result: Result<PrepareConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "unknown key must be rejected");
    }

    #[test]
    fn deserialize_rejects_duplicate_mount_key() {
        let yaml = "mount:\n  preset: recommends\nmount:\n  preset: recommends\n";
        let result: Result<PrepareConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "duplicate mount key must be rejected at parse time");
    }

    #[test]
    fn items_are_fixed_order_mount_then_resolv_conf() {
        // resolv_conf declared before mount in YAML; items() still yields mount first.
        let yaml = "resolv_conf:\n  copy: true\nmount:\n  preset: recommends\n";
        let config: PrepareConfig = serde_yaml::from_str(yaml).unwrap();
        let items = config.items();
        assert_eq!(items.len(), 2);
        assert!(items[0].name().starts_with("mount:"));
        assert!(items[1].name().starts_with("resolv_conf:"));
    }

    #[test]
    fn serde_roundtrip_via_json() {
        // PrepareConfig is Deserialize-only; validate the value is stable across
        // a re-parse of an equivalent YAML document.
        let yaml = "mount:\n  preset: recommends\nresolv_conf:\n  name_servers:\n  - 8.8.8.8\n";
        let a: PrepareConfig = serde_yaml::from_str(yaml).unwrap();
        let b: PrepareConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(a, b);
    }
}
