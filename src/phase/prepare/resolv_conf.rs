//! resolv_conf task implementation for the prepare phase.
//!
//! This module provides the `ResolvConfTask` data structure for declaring
//! resolv.conf setup that should be applied before pipeline execution.
//! The actual setup/teardown lifecycle is managed at the pipeline level
//! (not per-task), similar to mount tasks.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::config::ResolvConfConfig;
use crate::error::RsdebstrapError;

/// resolv_conf task for declaring DNS configuration in the prepare phase.
///
/// This task declares how resolv.conf should be set up inside the rootfs
/// before provisioning tasks run. The actual setup/teardown lifecycle is
/// managed at the pipeline level, not by the task's `execute()` method.
///
/// At most one `ResolvConfTask` may appear in the prepare phase.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolvConfTask {
    /// Copy host's /etc/resolv.conf into the chroot (following symlinks).
    #[serde(default)]
    pub copy: bool,
    /// Nameserver IP addresses to write to resolv.conf.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub name_servers: Vec<IpAddr>,
    /// Search domains to write to resolv.conf.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search: Vec<String>,
}

impl ResolvConfTask {
    /// Returns a human-readable name for this resolv_conf task.
    pub fn name(&self) -> &str {
        if self.copy { "copy" } else { "generate" }
    }

    /// Converts this task into a `ResolvConfConfig` for use with `RootfsResolvConf`.
    pub fn config(&self) -> ResolvConfConfig {
        ResolvConfConfig {
            copy: self.copy,
            name_servers: self.name_servers.clone(),
            search: self.search.clone(),
        }
    }

    /// Validates the resolv_conf task configuration.
    ///
    /// Delegates to `ResolvConfConfig::validate()`.
    pub fn validate(&self) -> Result<(), RsdebstrapError> {
        self.config().validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // name() tests
    // =========================================================================

    #[test]
    fn name_copy() {
        let task = ResolvConfTask {
            copy: true,
            name_servers: vec![],
            search: vec![],
        };
        assert_eq!(task.name(), "copy");
    }

    #[test]
    fn name_generate() {
        let task = ResolvConfTask {
            copy: false,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec![],
        };
        assert_eq!(task.name(), "generate");
    }

    // =========================================================================
    // config() tests
    // =========================================================================

    #[test]
    fn config_copy() {
        let task = ResolvConfTask {
            copy: true,
            name_servers: vec![],
            search: vec![],
        };
        let config = task.config();
        assert!(config.copy);
        assert!(config.name_servers.is_empty());
        assert!(config.search.is_empty());
    }

    #[test]
    fn config_generate() {
        let task = ResolvConfTask {
            copy: false,
            name_servers: vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()],
            search: vec!["example.com".to_string()],
        };
        let config = task.config();
        assert!(!config.copy);
        assert_eq!(config.name_servers.len(), 2);
        assert_eq!(config.search, vec!["example.com"]);
    }

    // =========================================================================
    // validate() tests
    // =========================================================================

    #[test]
    fn validate_valid_copy() {
        let task = ResolvConfTask {
            copy: true,
            name_servers: vec![],
            search: vec![],
        };
        assert!(task.validate().is_ok());
    }

    #[test]
    fn validate_valid_generate() {
        let task = ResolvConfTask {
            copy: false,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec!["example.com".to_string()],
        };
        assert!(task.validate().is_ok());
    }

    #[test]
    fn validate_rejects_copy_with_name_servers() {
        let task = ResolvConfTask {
            copy: true,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec![],
        };
        let err = task.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn validate_rejects_empty_config() {
        let task = ResolvConfTask {
            copy: false,
            name_servers: vec![],
            search: vec![],
        };
        let err = task.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("name_servers"));
    }

    // =========================================================================
    // serde tests
    // =========================================================================

    #[test]
    fn serialize_deserialize_roundtrip_copy() {
        let task = ResolvConfTask {
            copy: true,
            name_servers: vec![],
            search: vec![],
        };
        let yaml = serde_yaml::to_string(&task).unwrap();
        let deserialized: ResolvConfTask = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(task, deserialized);
    }

    #[test]
    fn serialize_deserialize_roundtrip_generate() {
        let task = ResolvConfTask {
            copy: false,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec!["example.com".to_string()],
        };
        let yaml = serde_yaml::to_string(&task).unwrap();
        let deserialized: ResolvConfTask = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(task, deserialized);
    }

    #[test]
    fn serialize_skips_empty_fields() {
        let task = ResolvConfTask {
            copy: false,
            name_servers: vec![],
            search: vec![],
        };
        let yaml = serde_yaml::to_string(&task).unwrap();
        assert!(!yaml.contains("name_servers"));
        assert!(!yaml.contains("search"));
    }

    #[test]
    fn deserialize_copy_only() {
        let yaml = "copy: true\n";
        let task: ResolvConfTask = serde_yaml::from_str(yaml).unwrap();
        assert!(task.copy);
        assert!(task.name_servers.is_empty());
        assert!(task.search.is_empty());
    }

    #[test]
    fn deserialize_name_servers_only() {
        let yaml = "name_servers:\n  - 8.8.8.8\n";
        let task: ResolvConfTask = serde_yaml::from_str(yaml).unwrap();
        assert!(!task.copy);
        assert_eq!(task.name_servers.len(), 1);
    }

    #[test]
    fn deserialize_rejects_unknown_fields() {
        let yaml = "copy: true\nunknown_field: true\n";
        let result: Result<ResolvConfTask, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }
}
