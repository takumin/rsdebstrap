//! resolv_conf task implementation for the assemble phase.
//!
//! This module provides the `AssembleResolvConfTask` for writing a permanent
//! `/etc/resolv.conf` file or symlink into the final rootfs image.
//! Unlike the prepare phase's `ResolvConfTask` (which is temporary and restored
//! after provisioning), this task produces a persistent configuration.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::ResolvConfConfig;
use crate::error::RsdebstrapError;
use crate::isolation::IsolationContext;
use crate::isolation::resolv_conf::generate_resolv_conf;

/// Assemble phase resolv_conf task for writing a permanent `/etc/resolv.conf`.
///
/// Supports two mutually exclusive modes:
/// - **generate**: writes a resolv.conf file from `name_servers` and `search`
/// - **link**: creates a symlink to the specified target path
///
/// At most one `AssembleResolvConfTask` may appear in the assemble phase.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AssembleResolvConfTask {
    /// Symlink target path (mutually exclusive with `name_servers`/`search`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    /// Nameserver IP addresses to write to resolv.conf.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub name_servers: Vec<IpAddr>,
    /// Search domains to write to resolv.conf.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search: Vec<String>,
}

impl AssembleResolvConfTask {
    /// Returns a human-readable name for this resolv_conf task.
    pub fn name(&self) -> &str {
        if self.link.is_some() {
            "link"
        } else {
            "generate"
        }
    }

    /// Validates the assemble resolv_conf task configuration.
    pub fn validate(&self) -> Result<(), RsdebstrapError> {
        let has_link = self.link.is_some();
        let has_generate = !self.name_servers.is_empty() || !self.search.is_empty();

        if has_link && has_generate {
            return Err(RsdebstrapError::Validation(
                "assemble resolv_conf: 'link' and 'name_servers'/'search' are mutually exclusive"
                    .to_string(),
            ));
        }

        if !has_link && !has_generate {
            return Err(RsdebstrapError::Validation(
                "assemble resolv_conf: either 'link' or 'name_servers' must be specified"
                    .to_string(),
            ));
        }

        if let Some(link) = &self.link {
            if link.is_empty() {
                return Err(RsdebstrapError::Validation(
                    "assemble resolv_conf: 'link' must not be empty".to_string(),
                ));
            }
            if link.contains('\n') || link.contains('\r') {
                return Err(RsdebstrapError::Validation(
                    "assemble resolv_conf: 'link' must not contain newline characters".to_string(),
                ));
            }
            if link.contains('\0') {
                return Err(RsdebstrapError::Validation(
                    "assemble resolv_conf: 'link' must not contain null characters".to_string(),
                ));
            }
        } else {
            // Delegate to ResolvConfConfig for nameserver/search validation
            let config = ResolvConfConfig {
                copy: false,
                name_servers: self.name_servers.clone(),
                search: self.search.clone(),
            };
            config.validate()?;
        }

        Ok(())
    }

    /// Executes the assemble resolv_conf task.
    ///
    /// Writes a permanent `/etc/resolv.conf` file or creates a symlink
    /// in the rootfs directory.
    pub fn execute(&self, ctx: &dyn IsolationContext) -> anyhow::Result<()> {
        let rootfs = ctx.rootfs();
        let resolv_conf_path = rootfs.join("etc/resolv.conf");

        if ctx.dry_run() {
            match &self.link {
                Some(target) => {
                    info!("would create symlink {} -> {} in {}", resolv_conf_path, target, rootfs);
                }
                None => {
                    info!("would write resolv.conf to {} in {}", resolv_conf_path, rootfs);
                }
            }
            return Ok(());
        }

        // Validate /etc is not a symlink
        let etc_path = rootfs.join("etc");
        let etc_meta = std::fs::symlink_metadata(&etc_path).map_err(|e| {
            RsdebstrapError::io(format!("failed to read metadata for {}", etc_path), e)
        })?;
        if etc_meta.is_symlink() {
            return Err(RsdebstrapError::Isolation(format!(
                "{} is a symlink, refusing to write resolv.conf (possible symlink attack)",
                etc_path
            ))
            .into());
        }

        // Remove existing file/symlink (ignore ENOENT)
        match std::fs::remove_file(&resolv_conf_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(RsdebstrapError::io(
                    format!("failed to remove existing {}", resolv_conf_path),
                    e,
                )
                .into());
            }
        }

        match &self.link {
            Some(target) => {
                std::os::unix::fs::symlink(target, &resolv_conf_path).map_err(|e| {
                    RsdebstrapError::io(format!("failed to create symlink {}", resolv_conf_path), e)
                })?;
                info!("created symlink {} -> {}", resolv_conf_path, target);
            }
            None => {
                let config = ResolvConfConfig {
                    copy: false,
                    name_servers: self.name_servers.clone(),
                    search: self.search.clone(),
                };
                let content = generate_resolv_conf(&config);
                std::fs::write(&resolv_conf_path, &content).map_err(|e| {
                    RsdebstrapError::io(format!("failed to write {}", resolv_conf_path), e)
                })?;
                info!("wrote resolv.conf to {}", resolv_conf_path);
            }
        }

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
    fn name_link() {
        let task = AssembleResolvConfTask {
            link: Some("../run/systemd/resolve/stub-resolv.conf".to_string()),
            name_servers: vec![],
            search: vec![],
        };
        assert_eq!(task.name(), "link");
    }

    #[test]
    fn name_generate() {
        let task = AssembleResolvConfTask {
            link: None,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec![],
        };
        assert_eq!(task.name(), "generate");
    }

    // =========================================================================
    // validate() tests
    // =========================================================================

    #[test]
    fn validate_valid_generate() {
        let task = AssembleResolvConfTask {
            link: None,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec!["example.com".to_string()],
        };
        assert!(task.validate().is_ok());
    }

    #[test]
    fn validate_valid_link_relative() {
        let task = AssembleResolvConfTask {
            link: Some("../run/systemd/resolve/stub-resolv.conf".to_string()),
            name_servers: vec![],
            search: vec![],
        };
        assert!(task.validate().is_ok());
    }

    #[test]
    fn validate_valid_link_absolute() {
        let task = AssembleResolvConfTask {
            link: Some("/run/systemd/resolve/stub-resolv.conf".to_string()),
            name_servers: vec![],
            search: vec![],
        };
        assert!(task.validate().is_ok());
    }

    #[test]
    fn validate_rejects_mutual_exclusion() {
        let task = AssembleResolvConfTask {
            link: Some("/run/systemd/resolve/stub-resolv.conf".to_string()),
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec![],
        };
        let err = task.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn validate_rejects_empty_config() {
        let task = AssembleResolvConfTask {
            link: None,
            name_servers: vec![],
            search: vec![],
        };
        let err = task.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("either"));
    }

    #[test]
    fn validate_rejects_empty_link() {
        let task = AssembleResolvConfTask {
            link: Some("".to_string()),
            name_servers: vec![],
            search: vec![],
        };
        let err = task.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_rejects_link_with_newline() {
        let task = AssembleResolvConfTask {
            link: Some("foo\nbar".to_string()),
            name_servers: vec![],
            search: vec![],
        };
        let err = task.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("newline"));
    }

    #[test]
    fn validate_rejects_link_with_carriage_return() {
        let task = AssembleResolvConfTask {
            link: Some("foo\rbar".to_string()),
            name_servers: vec![],
            search: vec![],
        };
        let err = task.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("newline"));
    }

    #[test]
    fn validate_rejects_link_with_null() {
        let task = AssembleResolvConfTask {
            link: Some("foo\0bar".to_string()),
            name_servers: vec![],
            search: vec![],
        };
        let err = task.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("null"));
    }

    #[test]
    fn validate_delegates_nameserver_limits() {
        let task = AssembleResolvConfTask {
            link: None,
            name_servers: vec![
                "8.8.8.8".parse().unwrap(),
                "8.8.4.4".parse().unwrap(),
                "1.1.1.1".parse().unwrap(),
                "1.0.0.1".parse().unwrap(),
            ],
            search: vec![],
        };
        let err = task.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("at most 3"));
    }

    #[test]
    fn validate_link_and_search_mutual_exclusion() {
        let task = AssembleResolvConfTask {
            link: Some("/run/systemd/resolve/stub-resolv.conf".to_string()),
            name_servers: vec![],
            search: vec!["example.com".to_string()],
        };
        let err = task.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("mutually exclusive"));
    }

    // =========================================================================
    // serde tests
    // =========================================================================

    #[test]
    fn deserialize_link_relative() {
        let yaml = "link: ../run/systemd/resolve/stub-resolv.conf\n";
        let task: AssembleResolvConfTask = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(task.link.as_deref(), Some("../run/systemd/resolve/stub-resolv.conf"));
        assert!(task.name_servers.is_empty());
        assert!(task.search.is_empty());
    }

    #[test]
    fn deserialize_link_absolute() {
        let yaml = "link: /run/systemd/resolve/stub-resolv.conf\n";
        let task: AssembleResolvConfTask = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(task.link.as_deref(), Some("/run/systemd/resolve/stub-resolv.conf"));
    }

    #[test]
    fn deserialize_name_servers() {
        let yaml = "name_servers:\n  - 8.8.8.8\n  - 8.8.4.4\n";
        let task: AssembleResolvConfTask = serde_yaml::from_str(yaml).unwrap();
        assert!(task.link.is_none());
        assert_eq!(task.name_servers.len(), 2);
    }

    #[test]
    fn deserialize_rejects_unknown_fields() {
        let yaml = "link: /foo\nunknown_field: true\n";
        let result: Result<AssembleResolvConfTask, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn serialize_deserialize_roundtrip_link() {
        let task = AssembleResolvConfTask {
            link: Some("../run/systemd/resolve/stub-resolv.conf".to_string()),
            name_servers: vec![],
            search: vec![],
        };
        let yaml = serde_yaml::to_string(&task).unwrap();
        let deserialized: AssembleResolvConfTask = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(task, deserialized);
    }

    #[test]
    fn serialize_deserialize_roundtrip_generate() {
        let task = AssembleResolvConfTask {
            link: None,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec!["example.com".to_string()],
        };
        let yaml = serde_yaml::to_string(&task).unwrap();
        let deserialized: AssembleResolvConfTask = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(task, deserialized);
    }

    #[test]
    fn serialize_skips_empty_fields() {
        let task = AssembleResolvConfTask {
            link: None,
            name_servers: vec![],
            search: vec![],
        };
        let yaml = serde_yaml::to_string(&task).unwrap();
        assert!(!yaml.contains("link"));
        assert!(!yaml.contains("name_servers"));
        assert!(!yaml.contains("search"));
    }

    // =========================================================================
    // execute() tests
    // =========================================================================

    #[test]
    fn execute_generate_writes_file() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();

        let task = AssembleResolvConfTask {
            link: None,
            name_servers: vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()],
            search: vec!["example.com".to_string()],
        };

        let ctx = MockAssembleContext::new(&rootfs, false);
        task.execute(&ctx).unwrap();

        let content = std::fs::read_to_string(rootfs.join("etc/resolv.conf")).unwrap();
        assert!(content.contains("nameserver 8.8.8.8"));
        assert!(content.contains("nameserver 8.8.4.4"));
        assert!(content.contains("search example.com"));
        assert!(content.contains("# Generated by rsdebstrap"));
    }

    #[test]
    fn execute_link_creates_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();

        let task = AssembleResolvConfTask {
            link: Some("../run/systemd/resolve/stub-resolv.conf".to_string()),
            name_servers: vec![],
            search: vec![],
        };

        let ctx = MockAssembleContext::new(&rootfs, false);
        task.execute(&ctx).unwrap();

        let resolv_path = rootfs.join("etc/resolv.conf");
        let meta = std::fs::symlink_metadata(&resolv_path).unwrap();
        assert!(meta.is_symlink());
        let target = std::fs::read_link(&resolv_path).unwrap();
        assert_eq!(target.to_str().unwrap(), "../run/systemd/resolve/stub-resolv.conf");
    }

    #[test]
    fn execute_link_absolute_creates_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();

        let task = AssembleResolvConfTask {
            link: Some("/run/systemd/resolve/stub-resolv.conf".to_string()),
            name_servers: vec![],
            search: vec![],
        };

        let ctx = MockAssembleContext::new(&rootfs, false);
        task.execute(&ctx).unwrap();

        let resolv_path = rootfs.join("etc/resolv.conf");
        let target = std::fs::read_link(&resolv_path).unwrap();
        assert_eq!(target.to_str().unwrap(), "/run/systemd/resolve/stub-resolv.conf");
    }

    #[test]
    fn execute_dry_run_does_not_create_file() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();

        let task = AssembleResolvConfTask {
            link: None,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec![],
        };

        let ctx = MockAssembleContext::new(&rootfs, true);
        task.execute(&ctx).unwrap();

        assert!(!rootfs.join("etc/resolv.conf").exists());
    }

    #[test]
    fn execute_overwrites_existing_file() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();
        std::fs::write(rootfs.join("etc/resolv.conf"), "old content").unwrap();

        let task = AssembleResolvConfTask {
            link: None,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec![],
        };

        let ctx = MockAssembleContext::new(&rootfs, false);
        task.execute(&ctx).unwrap();

        let content = std::fs::read_to_string(rootfs.join("etc/resolv.conf")).unwrap();
        assert!(content.contains("nameserver 8.8.8.8"));
        assert!(!content.contains("old content"));
    }

    #[test]
    fn execute_overwrites_existing_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();
        std::os::unix::fs::symlink("/old/target", rootfs.join("etc/resolv.conf")).unwrap();

        let task = AssembleResolvConfTask {
            link: Some("/new/target".to_string()),
            name_servers: vec![],
            search: vec![],
        };

        let ctx = MockAssembleContext::new(&rootfs, false);
        task.execute(&ctx).unwrap();

        let target = std::fs::read_link(rootfs.join("etc/resolv.conf")).unwrap();
        assert_eq!(target.to_str().unwrap(), "/new/target");
    }

    #[test]
    fn execute_errors_when_etc_is_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let real_etc = rootfs.join("real_etc");
        std::fs::create_dir_all(&real_etc).unwrap();
        std::os::unix::fs::symlink(&real_etc, rootfs.join("etc")).unwrap();

        let task = AssembleResolvConfTask {
            link: None,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec![],
        };

        let ctx = MockAssembleContext::new(&rootfs, false);
        let err = task.execute(&ctx).unwrap_err();
        assert!(err.to_string().contains("symlink"));
    }

    // =========================================================================
    // Mock context for execute tests
    // =========================================================================

    struct MockAssembleContext {
        rootfs: camino::Utf8PathBuf,
        dry_run: bool,
    }

    impl MockAssembleContext {
        fn new(rootfs: &camino::Utf8Path, dry_run: bool) -> Self {
            Self {
                rootfs: rootfs.to_owned(),
                dry_run,
            }
        }
    }

    impl IsolationContext for MockAssembleContext {
        fn name(&self) -> &'static str {
            "mock"
        }

        fn rootfs(&self) -> &camino::Utf8Path {
            &self.rootfs
        }

        fn dry_run(&self) -> bool {
            self.dry_run
        }

        fn execute(
            &self,
            _command: &[String],
            _privilege: Option<crate::privilege::PrivilegeMethod>,
        ) -> anyhow::Result<crate::executor::ExecutionResult> {
            unimplemented!("not used by assemble resolv_conf tests")
        }

        fn teardown(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
    }
}
