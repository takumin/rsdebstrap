//! Mount task implementation for the prepare phase.
//!
//! This module provides the `MountTask` data structure for declaring
//! filesystem mounts that should be set up before pipeline execution.
//! Mount entries are processed at the pipeline level (not per-task),
//! bracketing the entire pipeline execution.

use std::collections::{HashMap, HashSet};

use camino::Utf8Path;
use serde::{Deserialize, Serialize};

use crate::config::{MountEntry, MountPreset};
use crate::error::RsdebstrapError;

/// Mount task for declaring filesystem mounts in the prepare phase.
///
/// This task declares which filesystems should be mounted into the rootfs
/// before provisioning tasks run. The actual mount/unmount lifecycle is
/// managed at the pipeline level, not by the task's `execute()` method.
///
/// At most one `MountTask` may appear in the prepare phase.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MountTask {
    /// Optional preset for predefined mount sets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<MountPreset>,
    /// Custom mount entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<MountEntry>,
}

impl MountTask {
    /// Returns a human-readable name for this mount task.
    pub fn name(&self) -> &str {
        match (&self.preset, self.mounts.is_empty()) {
            (Some(_), true) => "preset",
            (None, false) => "custom",
            (Some(_), false) => "preset+custom",
            (None, true) => "empty",
        }
    }

    /// Returns true if this task has any mount entries (preset or custom).
    pub fn has_mounts(&self) -> bool {
        self.preset.is_some() || !self.mounts.is_empty()
    }

    /// Returns the resolved list of mount entries.
    ///
    /// If a preset is set, expands the preset entries first. Custom mounts
    /// with the same target as a preset entry replace the preset entry
    /// at its original position, preserving mount order (parent before child).
    /// Non-overlapping custom mounts are appended in YAML definition order.
    pub fn resolved_mounts(&self) -> Vec<MountEntry> {
        let mut preset_entries = self
            .preset
            .as_ref()
            .map(|p| p.to_entries())
            .unwrap_or_default();

        if self.mounts.is_empty() {
            return preset_entries;
        }
        if preset_entries.is_empty() {
            return self.mounts.clone();
        }

        // Build lookup from target path to custom mount entry
        let mut custom_by_target: HashMap<&Utf8Path, &MountEntry> = self
            .mounts
            .iter()
            .map(|m| (m.target.as_path(), m))
            .collect();

        // Replace preset entries in-place where custom overrides exist
        for entry in &mut preset_entries {
            if let Some(custom) = custom_by_target.remove(entry.target.as_path()) {
                *entry = custom.clone();
            }
        }

        // Append non-overlapping custom mounts in YAML definition order
        for m in &self.mounts {
            if custom_by_target.contains_key(m.target.as_path()) {
                preset_entries.push(m.clone());
            }
        }

        preset_entries
    }

    /// Validates the mount task configuration.
    ///
    /// Checks each mount entry and validates mount order.
    pub fn validate(&self) -> Result<(), RsdebstrapError> {
        // Check for duplicate targets in custom mounts
        let mut seen_targets = HashSet::new();
        for entry in &self.mounts {
            if !seen_targets.insert(&entry.target) {
                return Err(RsdebstrapError::Validation(format!(
                    "duplicate mount target '{}' in custom mounts is not allowed",
                    entry.target
                )));
            }
        }

        let resolved_mounts = self.resolved_mounts();

        for entry in &resolved_mounts {
            entry.validate()?;

            // Validate bind mount source exists on host
            if entry.is_bind_mount() {
                let source_path = Utf8Path::new(&entry.source);
                if !source_path.exists() {
                    return Err(RsdebstrapError::Validation(format!(
                        "bind mount source '{}' does not exist on host",
                        entry.source
                    )));
                }
            }
        }

        // Validate mount order: parent directories must come before children
        crate::config::validate_mount_order(&resolved_mounts)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // name() tests
    // =========================================================================

    #[test]
    fn name_preset_only() {
        let task = MountTask {
            preset: Some(MountPreset::Recommends),
            mounts: vec![],
        };
        assert_eq!(task.name(), "preset");
    }

    #[test]
    fn name_custom_only() {
        let task = MountTask {
            preset: None,
            mounts: vec![MountEntry {
                source: "proc".to_string(),
                target: "/proc".into(),
                options: vec![],
            }],
        };
        assert_eq!(task.name(), "custom");
    }

    #[test]
    fn name_preset_and_custom() {
        let task = MountTask {
            preset: Some(MountPreset::Recommends),
            mounts: vec![MountEntry {
                source: "proc".to_string(),
                target: "/proc".into(),
                options: vec![],
            }],
        };
        assert_eq!(task.name(), "preset+custom");
    }

    #[test]
    fn name_empty() {
        let task = MountTask {
            preset: None,
            mounts: vec![],
        };
        assert_eq!(task.name(), "empty");
    }

    // =========================================================================
    // has_mounts() tests
    // =========================================================================

    #[test]
    fn has_mounts_empty() {
        let task = MountTask {
            preset: None,
            mounts: vec![],
        };
        assert!(!task.has_mounts());
    }

    #[test]
    fn has_mounts_preset_only() {
        let task = MountTask {
            preset: Some(MountPreset::Recommends),
            mounts: vec![],
        };
        assert!(task.has_mounts());
    }

    #[test]
    fn has_mounts_custom_only() {
        let task = MountTask {
            preset: None,
            mounts: vec![MountEntry {
                source: "proc".to_string(),
                target: "/proc".into(),
                options: vec![],
            }],
        };
        assert!(task.has_mounts());
    }

    // =========================================================================
    // resolved_mounts() tests
    // =========================================================================

    #[test]
    fn resolved_mounts_empty() {
        let task = MountTask {
            preset: None,
            mounts: vec![],
        };
        assert!(task.resolved_mounts().is_empty());
    }

    #[test]
    fn resolved_mounts_preset_only() {
        let task = MountTask {
            preset: Some(MountPreset::Recommends),
            mounts: vec![],
        };
        let mounts = task.resolved_mounts();
        assert_eq!(mounts.len(), 6);
    }

    #[test]
    fn resolved_mounts_custom_only() {
        let task = MountTask {
            preset: None,
            mounts: vec![MountEntry {
                source: "proc".to_string(),
                target: "/proc".into(),
                options: vec![],
            }],
        };
        let mounts = task.resolved_mounts();
        assert_eq!(mounts.len(), 1);
    }

    #[test]
    fn resolved_mounts_merge_replaces_preset() {
        let task = MountTask {
            preset: Some(MountPreset::Recommends),
            mounts: vec![MountEntry {
                source: "/dev".to_string(),
                target: "/dev".into(),
                options: vec!["bind".to_string()],
            }],
        };
        let mounts = task.resolved_mounts();
        assert_eq!(mounts.len(), 6);

        let dev_entry = mounts.iter().find(|m| m.target.as_str() == "/dev").unwrap();
        assert_eq!(dev_entry.source, "/dev");
        assert!(dev_entry.is_bind_mount());
    }

    #[test]
    fn resolved_mounts_merge_preserves_mount_order() {
        let task = MountTask {
            preset: Some(MountPreset::Recommends),
            mounts: vec![MountEntry {
                source: "/dev".to_string(),
                target: "/dev".into(),
                options: vec!["bind".to_string()],
            }],
        };
        let mounts = task.resolved_mounts();
        assert_eq!(mounts.len(), 6);

        let dev_pos = mounts
            .iter()
            .position(|m| m.target.as_str() == "/dev")
            .unwrap();
        let devpts_pos = mounts
            .iter()
            .position(|m| m.target.as_str() == "/dev/pts")
            .unwrap();
        assert!(
            dev_pos < devpts_pos,
            "/dev (pos {}) should come before /dev/pts (pos {})",
            dev_pos,
            devpts_pos
        );

        crate::config::validate_mount_order(&mounts).unwrap();
    }

    #[test]
    fn resolved_mounts_merge_multiple_overrides() {
        let task = MountTask {
            preset: Some(MountPreset::Recommends),
            mounts: vec![
                MountEntry {
                    source: "tmpfs".to_string(),
                    target: "/tmp".into(),
                    options: vec!["size=2G".to_string()],
                },
                MountEntry {
                    source: "/dev".to_string(),
                    target: "/dev".into(),
                    options: vec!["bind".to_string()],
                },
            ],
        };
        let mounts = task.resolved_mounts();
        assert_eq!(mounts.len(), 6);

        let dev_entry = mounts.iter().find(|m| m.target.as_str() == "/dev").unwrap();
        assert!(dev_entry.is_bind_mount());

        let tmp_entry = mounts.iter().find(|m| m.target.as_str() == "/tmp").unwrap();
        assert!(tmp_entry.options.contains(&"size=2G".to_string()));

        crate::config::validate_mount_order(&mounts).unwrap();
    }

    #[test]
    fn resolved_mounts_appends_non_overlapping_custom_mounts() {
        let task = MountTask {
            preset: Some(MountPreset::Recommends),
            mounts: vec![MountEntry {
                source: "tmpfs".to_string(),
                target: "/var/tmp".into(),
                options: vec![],
            }],
        };
        let mounts = task.resolved_mounts();
        assert_eq!(mounts.len(), 7);

        let last = mounts.last().unwrap();
        assert_eq!(last.target.as_str(), "/var/tmp");
        assert_eq!(last.source, "tmpfs");

        assert!(mounts.iter().any(|m| m.target.as_str() == "/proc"));
        assert!(mounts.iter().any(|m| m.target.as_str() == "/sys"));
        assert!(mounts.iter().any(|m| m.target.as_str() == "/dev"));
        assert!(mounts.iter().any(|m| m.target.as_str() == "/dev/pts"));
        assert!(mounts.iter().any(|m| m.target.as_str() == "/tmp"));
        assert!(mounts.iter().any(|m| m.target.as_str() == "/run"));
    }

    // =========================================================================
    // validate() tests
    // =========================================================================

    #[test]
    fn validate_duplicate_custom_mount_targets() {
        let task = MountTask {
            preset: None,
            mounts: vec![
                MountEntry {
                    source: "proc".to_string(),
                    target: "/proc".into(),
                    options: vec![],
                },
                MountEntry {
                    source: "proc".to_string(),
                    target: "/proc".into(),
                    options: vec!["nosuid".to_string()],
                },
            ],
        };
        let err = task.validate().unwrap_err();
        assert!(
            matches!(
                &err,
                RsdebstrapError::Validation(msg) if msg.contains("duplicate mount target '/proc'")
            ),
            "expected duplicate target error, got: {err}"
        );
    }

    // =========================================================================
    // serde tests
    // =========================================================================

    #[test]
    fn serialize_deserialize_roundtrip() {
        let task = MountTask {
            preset: Some(MountPreset::Recommends),
            mounts: vec![MountEntry {
                source: "/dev".to_string(),
                target: "/dev".into(),
                options: vec!["bind".to_string()],
            }],
        };
        let yaml = serde_yaml::to_string(&task).unwrap();
        let deserialized: MountTask = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(task, deserialized);
    }

    #[test]
    fn serialize_skips_empty_fields() {
        let task = MountTask {
            preset: None,
            mounts: vec![],
        };
        let yaml = serde_yaml::to_string(&task).unwrap();
        assert!(!yaml.contains("preset"));
        assert!(!yaml.contains("mounts"));
    }

    #[test]
    fn deserialize_preset_only() {
        let yaml = "preset: recommends\n";
        let task: MountTask = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(task.preset, Some(MountPreset::Recommends));
        assert!(task.mounts.is_empty());
    }

    #[test]
    fn deserialize_mounts_only() {
        let yaml = "mounts:\n  - source: proc\n    target: /proc\n";
        let task: MountTask = serde_yaml::from_str(yaml).unwrap();
        assert!(task.preset.is_none());
        assert_eq!(task.mounts.len(), 1);
    }
}
