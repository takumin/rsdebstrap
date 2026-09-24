//! Assemble phase module for post-provisioning tasks.
//!
//! This module provides the [`AssembleConfig`] named-field struct describing the
//! tasks that run after the main provisioning phase:
//! - [`apt_clean`](AssembleConfig::apt_clean) — empties apt's caches in the final rootfs
//! - [`resolv_conf`](AssembleConfig::resolv_conf) — writes a permanent `/etc/resolv.conf`
//! - [`output`](AssembleConfig::output) — writes the kernel, the initramfs and a squashfs
//!   image of the rootfs next to it, once the rootfs is final
//!
//! The named-field shape makes "at most one resolv_conf" structural rather than
//! validated after the fact.

pub mod apt_clean;
pub mod output;
pub mod resolv_conf;

use schemars::JsonSchema;
use serde::Deserialize;

pub use output::{BootFileOutput, OutputConfig, SquashfsCompression, SquashfsOutput};
pub use resolv_conf::AssembleResolvConfTask;

use crate::phase::AssembleItem;
use apt_clean::AptCleanTask;

/// Assemble phase configuration (named-field, schema-first).
///
/// Each field is an optional singleton; a duplicate YAML key is rejected by `yaml_serde` at
/// parse time and an unknown key by `deny_unknown_fields`.
#[derive(Debug, Deserialize, Default, Clone, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssembleConfig {
    /// Empty apt's download cache and package lists in the final rootfs, as `apt-get
    /// distclean` would (default false). The image then needs `apt-get update` before it
    /// can install anything.
    #[serde(default)]
    pub apt_clean: bool,
    /// resolv_conf task writing a permanent `/etc/resolv.conf` into the final rootfs.
    #[serde(default)]
    pub resolv_conf: Option<AssembleResolvConfTask>,
    /// Build artifacts written into `dir` after the rootfs is final.
    #[serde(default, deserialize_with = "crate::de::null_to_default")]
    #[schemars(with = "Option<OutputConfig>")]
    pub output: OutputConfig,
}

impl AssembleConfig {
    /// Returns the present phase items in execution order.
    pub(crate) fn items(&self) -> Vec<&dyn AssembleItem> {
        let mut items: Vec<&dyn AssembleItem> = Vec::new();
        if self.apt_clean {
            items.push(&AptCleanTask);
        }
        if let Some(resolv_conf) = &self.resolv_conf {
            items.push(resolv_conf);
        }
        items
    }

    /// Returns true if no assemble tasks or outputs are configured.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of configured assemble tasks, outputs included.
    pub fn len(&self) -> usize {
        usize::from(self.apt_clean) + usize::from(self.resolv_conf.is_some()) + self.output.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_resolv_conf_present() {
        let yaml = "resolv_conf:\n  name_servers:\n  - 8.8.8.8\n";
        let config: AssembleConfig = yaml_serde::from_str(yaml).unwrap();
        assert!(config.resolv_conf.is_some());
        assert_eq!(config.len(), 1);
        assert!(!config.is_empty());
    }

    #[test]
    fn items_run_apt_clean_before_resolv_conf() {
        let yaml = "resolv_conf:\n  name_servers:\n  - 8.8.8.8\napt_clean: true\n";
        let config: AssembleConfig = yaml_serde::from_str(yaml).unwrap();
        let names: Vec<_> = config
            .items()
            .iter()
            .map(|item| item.name().into_owned())
            .collect();
        assert_eq!(names, ["apt_clean", "resolv_conf:generate"]);
        assert_eq!(config.len(), 2);
    }

    #[test]
    fn apt_clean_false_adds_no_item() {
        let config: AssembleConfig = yaml_serde::from_str("apt_clean: false\n").unwrap();
        assert!(config.items().is_empty());
        assert!(config.is_empty());
    }

    #[test]
    fn deserialize_rejects_a_non_bool_apt_clean() {
        let result: Result<AssembleConfig, _> = yaml_serde::from_str("apt_clean:\n  lists: true\n");
        assert!(result.is_err(), "apt_clean takes a bool, not a mapping");
    }

    #[test]
    fn deserialize_absent_defaults_to_empty() {
        let config: AssembleConfig = yaml_serde::from_str("{}").unwrap();
        assert!(config.is_empty());
        assert_eq!(config.len(), 0);
        assert!(config.items().is_empty());
    }

    #[test]
    fn deserialize_rejects_unknown_field() {
        let yaml = "mount:\n  preset: recommends\n";
        let result: Result<AssembleConfig, _> = yaml_serde::from_str(yaml);
        assert!(result.is_err(), "unknown key must be rejected");
    }

    #[test]
    fn deserialize_rejects_duplicate_resolv_conf_key() {
        let yaml = "resolv_conf:\n  name_servers:\n  - 8.8.8.8\nresolv_conf:\n  link: ../run/x\n";
        let result: Result<AssembleConfig, _> = yaml_serde::from_str(yaml);
        assert!(result.is_err(), "duplicate resolv_conf key must be rejected at parse time");
    }
}
