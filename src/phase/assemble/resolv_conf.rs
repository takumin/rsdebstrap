//! resolv_conf task implementation for the assemble phase.
//!
//! This module provides the `AssembleResolvConfTask` for writing a permanent
//! `/etc/resolv.conf` file or symlink into the final rootfs image.
//! Unlike the prepare phase's `ResolvConfTask` (which is temporary and restored
//! after provisioning), this task produces a persistent configuration.

use std::borrow::Cow;
use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::ResolvConfConfig;
use crate::error::RsdebstrapError;
use crate::isolation::RootfsContext;
use crate::isolation::resolv_conf::{generate_resolv_conf, resolv_conf_path};
use crate::phase::{AssembleItem, PhaseItem};
use crate::rootfs::FileMode;

/// Assemble phase resolv_conf task for writing a permanent `/etc/resolv.conf`.
///
/// Supports two mutually exclusive modes:
/// - **generate**: writes a resolv.conf file from `name_servers` and `search`
/// - **link**: creates a symlink to the specified target path
///
/// At most one `AssembleResolvConfTask` may appear in the assemble phase.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssembleResolvConfTask {
    /// Symlink target path (mutually exclusive with `name_servers`/`search`).
    #[serde(
        default,
        deserialize_with = "crate::de::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub link: Option<String>,
    /// Nameserver IP addresses to write to resolv.conf.
    #[serde(
        default,
        deserialize_with = "crate::de::null_to_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[schemars(with = "Option<Vec<crate::schema::IpAddrSchema>>")]
    pub name_servers: Vec<IpAddr>,
    /// Search domains to write to resolv.conf.
    #[serde(
        default,
        deserialize_with = "crate::de::string_list",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[schemars(with = "Option<Vec<String>>")]
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
            self.config().validate()?;
        }

        Ok(())
    }

    /// The generated file's configuration. Never `copy`: the assemble phase writes the
    /// image's permanent resolver config, not a copy of the build host's.
    fn config(&self) -> ResolvConfConfig {
        ResolvConfConfig {
            copy: false,
            name_servers: self.name_servers.clone(),
            search: self.search.clone(),
        }
    }

    /// Executes the assemble resolv_conf task.
    ///
    /// Installs the permanent `/etc/resolv.conf` — a generated file, or a
    /// symlink when `link` is set. The write is atomic, so a failure leaves the
    /// previous entry in place rather than a half-written one.
    pub fn execute(&self, ctx: &dyn RootfsContext) -> anyhow::Result<()> {
        let rootfs = ctx.rootfs();
        let path = resolv_conf_path();

        if ctx.dry_run() {
            match &self.link {
                Some(target) => {
                    info!("would create symlink /etc/resolv.conf -> {} in {}", target, rootfs)
                }
                None => info!("would write resolv.conf in {}", rootfs),
            }
            return Ok(());
        }

        let ops = ctx.rootfs_ops();
        match &self.link {
            Some(target) => {
                ops.write_symlink(&path, target.as_bytes())?;
                info!("created symlink /etc/resolv.conf -> {} in {}", target, rootfs);
            }
            None => {
                ops.write_file(
                    &path,
                    generate_resolv_conf(&self.config()).as_bytes(),
                    FileMode::new(0o644),
                )?;
                info!("wrote resolv.conf in {}", rootfs);
            }
        }

        Ok(())
    }
}

impl PhaseItem for AssembleResolvConfTask {
    fn name(&self) -> Cow<'_, str> {
        // `self.name()` resolves to the inherent method (inherent methods take
        // precedence over trait methods), so this is not recursive.
        Cow::Owned(format!("resolv_conf:{}", self.name()))
    }

    fn validate(&self) -> Result<(), RsdebstrapError> {
        AssembleResolvConfTask::validate(self)
    }
}

impl AssembleItem for AssembleResolvConfTask {
    fn execute(&self, ctx: &dyn RootfsContext) -> anyhow::Result<()> {
        AssembleResolvConfTask::execute(self, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn name_link() {
        let task = make_task_link("../run/systemd/resolve/stub-resolv.conf");
        assert_eq!(task.name(), "link");
    }

    #[test]
    fn name_generate() {
        let task = make_task_generate(vec!["8.8.8.8"], vec![]);
        assert_eq!(task.name(), "generate");
    }

    #[test]
    fn validate_valid_generate() {
        let task = make_task_generate(vec!["8.8.8.8"], vec!["example.com"]);
        assert!(task.validate().is_ok());
    }

    #[test]
    fn validate_valid_link_relative() {
        let task = make_task_link("../run/systemd/resolve/stub-resolv.conf");
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

    #[test]
    fn deserialize_link_relative() {
        let yaml = "link: ../run/systemd/resolve/stub-resolv.conf\n";
        let task: AssembleResolvConfTask = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(task.link.as_deref(), Some("../run/systemd/resolve/stub-resolv.conf"));
        assert!(task.name_servers.is_empty());
        assert!(task.search.is_empty());
    }

    #[test]
    fn deserialize_name_servers() {
        let yaml = "name_servers:\n  - 8.8.8.8\n  - 8.8.4.4\n";
        let task: AssembleResolvConfTask = yaml_serde::from_str(yaml).unwrap();
        assert!(task.link.is_none());
        assert_eq!(task.name_servers.len(), 2);
    }

    #[test]
    fn deserialize_rejects_unknown_fields() {
        let yaml = "link: /foo\nunknown_field: true\n";
        let result: Result<AssembleResolvConfTask, _> = yaml_serde::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn serialize_deserialize_roundtrip_link() {
        let task = make_task_link("../run/systemd/resolve/stub-resolv.conf");
        let yaml = yaml_serde::to_string(&task).unwrap();
        let deserialized: AssembleResolvConfTask = yaml_serde::from_str(&yaml).unwrap();
        assert_eq!(task, deserialized);
    }

    #[test]
    fn serialize_deserialize_roundtrip_generate() {
        let task = make_task_generate(vec!["8.8.8.8"], vec!["example.com"]);
        let yaml = yaml_serde::to_string(&task).unwrap();
        let deserialized: AssembleResolvConfTask = yaml_serde::from_str(&yaml).unwrap();
        assert_eq!(task, deserialized);
    }

    #[test]
    fn serialize_skips_empty_fields() {
        let task = AssembleResolvConfTask {
            link: None,
            name_servers: vec![],
            search: vec![],
        };
        let yaml = yaml_serde::to_string(&task).unwrap();
        assert!(!yaml.contains("link"));
        assert!(!yaml.contains("name_servers"));
        assert!(!yaml.contains("search"));
    }
    fn make_task_link(target: &str) -> AssembleResolvConfTask {
        AssembleResolvConfTask {
            link: Some(target.to_string()),
            name_servers: vec![],
            search: vec![],
        }
    }

    fn make_task_generate(ns: Vec<&str>, search: Vec<&str>) -> AssembleResolvConfTask {
        AssembleResolvConfTask {
            link: None,
            name_servers: ns.into_iter().map(|s| s.parse().unwrap()).collect(),
            search: search.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    // These assert the entry the task leaves in the rootfs. The task has no command
    // sequence to assert: staging and promotion happen inside `RootfsOps`, which pins
    // them with its own tests.
    fn assemble_rootfs() -> (tempfile::TempDir, camino::Utf8PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();
        (temp, rootfs)
    }

    fn generate_task(name_servers: &[&str]) -> AssembleResolvConfTask {
        AssembleResolvConfTask {
            name_servers: name_servers.iter().map(|s| s.parse().unwrap()).collect(),
            search: vec![],
            link: None,
        }
    }

    fn link_task(target: &str) -> AssembleResolvConfTask {
        AssembleResolvConfTask {
            name_servers: vec![],
            search: vec![],
            link: Some(target.to_string()),
        }
    }

    #[test]
    fn execute_generate_writes_the_file() {
        let (_temp, rootfs) = assemble_rootfs();
        let ctx = MockAssembleContext::new(&rootfs, false);

        generate_task(&["1.1.1.1"]).execute(&ctx).unwrap();

        assert_eq!(
            std::fs::read_to_string(rootfs.join("etc/resolv.conf")).unwrap(),
            "# Generated by rsdebstrap\nnameserver 1.1.1.1\n"
        );
    }

    #[test]
    fn execute_link_creates_the_symlink() {
        let (_temp, rootfs) = assemble_rootfs();
        let ctx = MockAssembleContext::new(&rootfs, false);

        link_task("../run/systemd/resolve/stub-resolv.conf")
            .execute(&ctx)
            .unwrap();

        let path = rootfs.join("etc/resolv.conf");
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_link(&path).unwrap().to_str().unwrap(),
            "../run/systemd/resolve/stub-resolv.conf"
        );
    }

    #[test]
    fn execute_dry_run_creates_nothing() {
        let (_temp, rootfs) = assemble_rootfs();
        let ctx = MockAssembleContext::new(&rootfs, true);

        generate_task(&["1.1.1.1"]).execute(&ctx).unwrap();

        assert!(!rootfs.join("etc/resolv.conf").exists());
    }

    #[test]
    fn execute_replaces_an_existing_file() {
        let (_temp, rootfs) = assemble_rootfs();
        std::fs::write(rootfs.join("etc/resolv.conf"), "stale\n").unwrap();
        let ctx = MockAssembleContext::new(&rootfs, false);

        generate_task(&["1.1.1.1"]).execute(&ctx).unwrap();

        assert_eq!(
            std::fs::read_to_string(rootfs.join("etc/resolv.conf")).unwrap(),
            "# Generated by rsdebstrap\nnameserver 1.1.1.1\n"
        );
    }

    // Debian's default /etc/resolv.conf is a symlink. Replacing it must unlink
    // it, not write through it to whatever it pointed at.
    #[test]
    fn execute_replaces_a_symlink_without_writing_through_it() {
        let (_temp, rootfs) = assemble_rootfs();
        let pointee = rootfs.join("etc/pointee");
        std::fs::write(&pointee, "untouched\n").unwrap();
        std::os::unix::fs::symlink("pointee", rootfs.join("etc/resolv.conf")).unwrap();
        let ctx = MockAssembleContext::new(&rootfs, false);

        generate_task(&["1.1.1.1"]).execute(&ctx).unwrap();

        assert_eq!(std::fs::read_to_string(&pointee).unwrap(), "untouched\n");
        assert_eq!(
            std::fs::read_to_string(rootfs.join("etc/resolv.conf")).unwrap(),
            "# Generated by rsdebstrap\nnameserver 1.1.1.1\n"
        );
    }

    #[test]
    fn execute_replaces_a_symlink_with_a_symlink() {
        let (_temp, rootfs) = assemble_rootfs();
        std::os::unix::fs::symlink("old-target", rootfs.join("etc/resolv.conf")).unwrap();
        let ctx = MockAssembleContext::new(&rootfs, false);

        link_task("new-target").execute(&ctx).unwrap();

        assert_eq!(
            std::fs::read_link(rootfs.join("etc/resolv.conf"))
                .unwrap()
                .to_str()
                .unwrap(),
            "new-target"
        );
    }

    #[test]
    fn execute_refuses_a_symlinked_etc() {
        let (_temp, rootfs) = assemble_rootfs();
        let outside = rootfs.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::remove_dir(rootfs.join("etc")).unwrap();
        std::os::unix::fs::symlink(&outside, rootfs.join("etc")).unwrap();
        let ctx = MockAssembleContext::new(&rootfs, false);

        let err = generate_task(&["1.1.1.1"]).execute(&ctx).unwrap_err();

        assert!(err.to_string().contains("symlink"), "unexpected error: {err}");
        assert!(!outside.join("resolv.conf").exists(), "wrote through the symlink");
    }

    // Implements `RootfsContext` and nothing else, which is the assertion: if
    // `execute` ever asked for an `IsolationContext` again, these tests would
    // stop compiling rather than quietly grant the assemble phase a way to run
    // programs.
    struct MockAssembleContext {
        rootfs: camino::Utf8PathBuf,
        dry_run: bool,
        ops: Arc<dyn crate::rootfs::RootfsOps>,
    }

    impl MockAssembleContext {
        fn new(rootfs: &camino::Utf8Path, dry_run: bool) -> Self {
            // Real ops over the temp rootfs, so the tests assert what the task
            // actually left on disk. A dry-run context never touches them.
            let ops: Arc<dyn crate::rootfs::RootfsOps> =
                match crate::rootfs::LocalRootfsOps::open(rootfs) {
                    Ok(ops) => Arc::new(ops),
                    Err(_) => Arc::new(crate::rootfs::DryRunRootfsOps::new(rootfs)),
                };
            Self {
                rootfs: rootfs.to_owned(),
                dry_run,
                ops,
            }
        }
    }

    impl RootfsContext for MockAssembleContext {
        fn rootfs(&self) -> &camino::Utf8Path {
            &self.rootfs
        }

        fn dry_run(&self) -> bool {
            self.dry_run
        }

        fn rootfs_ops(&self) -> &dyn crate::rootfs::RootfsOps {
            &*self.ops
        }
    }
}
