//! Assemble phase module for post-provisioning tasks.
//!
//! This module provides the [`AssembleConfig`] named-field struct describing the
//! tasks that run after the main provisioning phase:
//! - [`apt`](AssembleConfig::apt) — writes apt's keyrings, repositories and preferences
//!   into the final rootfs, removes the bootstrap's `sources.list` and empties apt's caches
//! - [`machine_id`](AssembleConfig::machine_id) — resets `/etc/machine-id` so each machine
//!   generates its own
//! - [`resolv_conf`](AssembleConfig::resolv_conf) — writes a permanent `/etc/resolv.conf`
//! - [`output`](AssembleConfig::output) — writes the kernel, the initramfs and a squashfs
//!   image of the rootfs next to it, once the rootfs is final
//!
//! The named-field shape makes "at most one resolv_conf" structural rather than
//! validated after the fact.

pub mod apt;
pub mod dist_clean;
pub mod machine_id;
pub mod output;
pub mod resolv_conf;

use schemars::JsonSchema;
use serde::Deserialize;

pub use apt::AssembleAptTask;
pub use machine_id::MachineId;
pub use output::{
    AssetOutput, AssetSource, BootFileOutput, OutputConfig, SquashfsCompression, SquashfsOutput,
};
pub use resolv_conf::AssembleResolvConfTask;

use crate::phase::AssembleItem;

/// Assemble phase configuration (named-field, schema-first).
///
/// Each field is an optional singleton; a duplicate YAML key is rejected by `yaml_serde` at
/// parse time and an unknown key by `deny_unknown_fields`.
#[derive(Debug, Deserialize, Default, Clone, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssembleConfig {
    /// apt task writing apt's configuration into the final rootfs and cleaning up after
    /// provisioning.
    #[serde(default)]
    pub apt: Option<AssembleAptTask>,
    /// Reset `/etc/machine-id` in the final rootfs, so every machine booted from the image
    /// generates its own ID rather than sharing the build's.
    #[serde(default)]
    pub machine_id: Option<MachineId>,
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
        if let Some(apt) = &self.apt {
            items.push(apt);
        }
        if let Some(machine_id) = &self.machine_id {
            items.push(machine_id);
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
        usize::from(self.apt.is_some())
            + usize::from(self.machine_id.is_some())
            + usize::from(self.resolv_conf.is_some())
            + self.output.len()
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
    fn items_run_apt_before_resolv_conf() {
        let yaml = "resolv_conf:\n  name_servers:\n  - 8.8.8.8\napt:\n  dist_clean: true\n";
        let config: AssembleConfig = yaml_serde::from_str(yaml).unwrap();
        let names: Vec<_> = config
            .items()
            .iter()
            .map(|item| item.name().into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "apt:keyrings[],repositories[],preferences[],dist_clean",
                "resolv_conf:generate"
            ]
        );
        assert_eq!(config.len(), 2);
    }

    #[test]
    fn items_run_machine_id_between_apt_and_resolv_conf() {
        let yaml = "resolv_conf:\n  link: ../run/x\nmachine_id: empty\napt:\n  dist_clean: true\n";
        let config: AssembleConfig = yaml_serde::from_str(yaml).unwrap();
        let names: Vec<_> = config
            .items()
            .iter()
            .map(|item| item.name().into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "apt:keyrings[],repositories[],preferences[],dist_clean",
                "machine_id:empty",
                "resolv_conf:link"
            ]
        );
        assert_eq!(config.len(), 3);
    }

    #[test]
    fn deserialize_machine_id_values() {
        for (yaml, expected) in [
            ("machine_id: uninitialized\n", Some(MachineId::Uninitialized)),
            ("machine_id: empty\n", Some(MachineId::Empty)),
            ("machine_id: null\n", None),
        ] {
            let config: AssembleConfig = yaml_serde::from_str(yaml).unwrap();
            assert_eq!(config.machine_id, expected, "{yaml}");
        }
    }

    #[test]
    fn deserialize_rejects_an_unknown_machine_id() {
        for yaml in ["machine_id: remove\n", "machine_id: true\n"] {
            let result: Result<AssembleConfig, _> = yaml_serde::from_str(yaml);
            assert!(result.is_err(), "{yaml} must be rejected");
        }
    }

    #[test]
    fn a_null_apt_adds_no_item() {
        let config: AssembleConfig = yaml_serde::from_str("apt:\n").unwrap();
        assert!(config.items().is_empty());
        assert!(config.is_empty());
    }

    #[test]
    fn deserialize_rejects_the_former_apt_clean_key() {
        let result: Result<AssembleConfig, _> = yaml_serde::from_str("apt_clean: true\n");
        assert!(result.is_err(), "apt_clean is now apt.dist_clean");
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
