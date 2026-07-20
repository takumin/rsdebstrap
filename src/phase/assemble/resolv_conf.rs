//! resolv_conf task implementation for the assemble phase.
//!
//! This module provides the `AssembleResolvConfTask` for writing a permanent
//! `/etc/resolv.conf` file or symlink into the final rootfs image.
//! Unlike the prepare phase's `ResolvConfTask` (which is temporary and restored
//! after provisioning), this task produces a persistent configuration.

use std::borrow::Cow;
use std::net::IpAddr;

use camino::{Utf8Path, Utf8PathBuf};
use rustix::fs::{self as rfs, CWD, Mode, OFlags};
#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::{IsolationConfig, ResolvConfConfig};
use crate::error::RsdebstrapError;
use crate::executor::CommandSpec;
use crate::isolation::IsolationContext;
use crate::isolation::resolv_conf::generate_resolv_conf;
use crate::phase::PhaseItem;
use crate::privilege::{Privilege, PrivilegeDefaults, PrivilegeMethod};

/// Returns true if the privilege setting is the default (`Inherit`).
fn privilege_is_default(p: &Privilege) -> bool {
    matches!(p, Privilege::Inherit)
}

/// Suffix for the staging entry used to atomically replace `/etc/resolv.conf`.
///
/// Mirrors the prepare guard's `.rsdebstrap-orig` naming: the suffix is
/// appended to the full final path, keeping the staging entry in the same
/// directory — and thus on the same filesystem — as the final path, which is
/// what makes the promoting rename atomic. A staging entry persists only after
/// a failed build; the next run force-overwrites it.
const STAGING_SUFFIX: &str = ".rsdebstrap-tmp";

/// Returns the staging path for the given final resolv.conf path.
fn staging_path(resolv_conf_path: &Utf8Path) -> Utf8PathBuf {
    let mut path = resolv_conf_path.to_string();
    path.push_str(STAGING_SUFFIX);
    Utf8PathBuf::from(path)
}

/// Assemble phase resolv_conf task for writing a permanent `/etc/resolv.conf`.
///
/// Supports two mutually exclusive modes:
/// - **generate**: writes a resolv.conf file from `name_servers` and `search`
/// - **link**: creates a symlink to the specified target path
///
/// At most one `AssembleResolvConfTask` may appear in the assemble phase.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AssembleResolvConfTask {
    /// Privilege escalation setting (resolved during defaults application).
    #[serde(default, skip_serializing_if = "privilege_is_default")]
    pub privilege: Privilege,
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
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<Vec<crate::schema::IpAddrSchema>>")
    )]
    pub name_servers: Vec<IpAddr>,
    /// Search domains to write to resolv.conf.
    #[serde(
        default,
        deserialize_with = "crate::de::string_list",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<Vec<String>>"))]
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

    /// Resolves the privilege setting against profile defaults.
    pub fn resolve_privilege(
        &mut self,
        defaults: Option<&PrivilegeDefaults>,
    ) -> Result<(), RsdebstrapError> {
        self.privilege.resolve_in_place(defaults)
    }

    /// Returns the resolved privilege method.
    ///
    /// Should only be called after `resolve_privilege()`.
    pub fn resolved_privilege_method(&self) -> Option<PrivilegeMethod> {
        self.privilege.resolved_method()
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
    /// Writes a permanent `/etc/resolv.conf` file or creates a symlink in the
    /// rootfs directory. Uses TOCTOU-safe `/etc` validation via
    /// `openat(O_NOFOLLOW)` and privilege escalation when configured. The new
    /// entry is staged at a sibling `.rsdebstrap-tmp` path and promoted with an
    /// atomic same-directory rename (`mv`), so any failure up to the rename
    /// leaves the previous `/etc/resolv.conf` intact.
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

        // Validate /etc exists and is not a symlink (fd-based, avoids TOCTOU with symlink_metadata)
        let etc_path = rootfs.join("etc");
        let _etc_fd = rfs::openat(
            CWD,
            etc_path.as_str(),
            OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| match e {
            rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => {
                RsdebstrapError::Isolation(format!(
                    "{} is a symlink or not a directory, refusing to write resolv.conf \
                    (possible symlink attack)",
                    etc_path
                ))
            }
            _ => {
                RsdebstrapError::io(format!("failed to open {}", etc_path), std::io::Error::from(e))
            }
        })?;

        let executor = ctx.executor();
        let privilege = self.resolved_privilege_method();

        // Stage the new resolv.conf at a sibling path, then atomically rename
        // it onto the final path. By the time assemble runs, the prepare-phase
        // guard has already restored the original and deleted its backup, so a
        // non-atomic replace here could leave the rootfs with *no* resolv.conf
        // on a mid-task failure. With staging, every failure point up to and
        // including the rename leaves the previous /etc/resolv.conf intact.
        let staging = staging_path(&resolv_conf_path);

        match &self.link {
            Some(target) => {
                // `-n` replaces a stale staging entry that is a symlink to a
                // directory instead of dereferencing it (plain `-sf` would
                // create the link *inside* that directory); `-f` overwrites
                // any other stale staging entry.
                let ln_spec = CommandSpec::new(
                    "ln",
                    vec!["-sfn".to_string(), target.clone(), staging.to_string()],
                )
                .with_privilege(privilege);
                executor.execute_checked(&ln_spec)?;
            }
            None => {
                // Generate content to a host temporary file, then copy it to
                // the staging path.
                let config = ResolvConfConfig {
                    copy: false,
                    name_servers: self.name_servers.clone(),
                    search: self.search.clone(),
                };
                let content = generate_resolv_conf(&config);

                let temp_file = tempfile::NamedTempFile::new().map_err(|e| {
                    RsdebstrapError::io("failed to create temporary file".to_string(), e)
                })?;
                std::fs::write(temp_file.path(), &content).map_err(|e| {
                    RsdebstrapError::io(
                        format!("failed to write temporary file {}", temp_file.path().display()),
                        e,
                    )
                })?;

                let temp_path = temp_file.path().to_string_lossy().to_string();

                // Remove any stale staging entry first. A leftover symlink from
                // a previously failed LINK-mode build would otherwise make `cp`
                // follow it and write *through* to the link target — escaping
                // the staging path, and under privilege the rootfs itself —
                // instead of replacing the staging entry. `ln -sfn` gives the
                // LINK path the equivalent protection.
                let rm_spec = CommandSpec::new("rm", vec!["-f".to_string(), staging.to_string()])
                    .with_privilege(privilege);
                executor.execute_checked(&rm_spec)?;

                let cp_spec = CommandSpec::new("cp", vec![temp_path, staging.to_string()])
                    .with_privilege(privilege);
                executor.execute_checked(&cp_spec)?;

                let chmod_spec =
                    CommandSpec::new("chmod", vec!["644".to_string(), staging.to_string()])
                        .with_privilege(privilege);
                executor.execute_checked(&chmod_spec)?;
            }
        }

        // Promote the staged entry onto /etc/resolv.conf. The staging path is
        // a sibling of the final path, so this is a same-filesystem rename(2),
        // which replaces the destination atomically. Plain `mv` (no GNU-only
        // `-T`) keeps this portable to busybox/musl hosts and is correct for
        // every resolv.conf shape rsdebstrap produces: a regular file, a symlink
        // to a file, or absent. A pre-existing `/etc/resolv.conf` that is itself
        // a directory (or a symlink to one) is out of scope — `mv` would move
        // the staging entry into it — but rsdebstrap never creates that state.
        let mv_spec =
            CommandSpec::new("mv", vec![staging.to_string(), resolv_conf_path.to_string()])
                .with_privilege(privilege);
        executor.execute_checked(&mv_spec)?;

        match &self.link {
            Some(target) => info!("created symlink {} -> {}", resolv_conf_path, target),
            None => info!("wrote resolv.conf to {}", resolv_conf_path),
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

    fn execute(&self, ctx: &dyn IsolationContext) -> anyhow::Result<()> {
        // Assemble resolv_conf operates directly on the final rootfs filesystem.
        AssembleResolvConfTask::execute(self, ctx)
    }

    fn resolved_isolation_config(&self) -> Option<&IsolationConfig> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::{CommandExecutor, ExecutionResult};
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::sync::{Arc, Mutex};

    // =========================================================================
    // name() tests
    // =========================================================================

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

    // =========================================================================
    // validate() tests
    // =========================================================================

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
    fn validate_valid_link_absolute() {
        let task = make_task_link("/run/systemd/resolve/stub-resolv.conf");
        assert!(task.validate().is_ok());
    }

    #[test]
    fn validate_rejects_mutual_exclusion() {
        let task = AssembleResolvConfTask {
            privilege: Privilege::Disabled,
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
            privilege: Privilege::Disabled,
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
            privilege: Privilege::Disabled,
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
            privilege: Privilege::Disabled,
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
            privilege: Privilege::Disabled,
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
            privilege: Privilege::Disabled,
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
            privilege: Privilege::Disabled,
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
            privilege: Privilege::Disabled,
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
        assert_eq!(task.privilege, Privilege::Inherit);
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
    fn deserialize_privilege_true() {
        let yaml = "name_servers:\n  - 8.8.8.8\nprivilege: true\n";
        let task: AssembleResolvConfTask = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(task.privilege, Privilege::UseDefault);
    }

    #[test]
    fn deserialize_privilege_false() {
        let yaml = "name_servers:\n  - 8.8.8.8\nprivilege: false\n";
        let task: AssembleResolvConfTask = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(task.privilege, Privilege::Disabled);
    }

    #[test]
    fn deserialize_privilege_method() {
        let yaml = "name_servers:\n  - 8.8.8.8\nprivilege:\n  method: sudo\n";
        let task: AssembleResolvConfTask = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(task.privilege, Privilege::Method(PrivilegeMethod::Sudo));
    }

    #[test]
    fn deserialize_privilege_absent_is_inherit() {
        let yaml = "name_servers:\n  - 8.8.8.8\n";
        let task: AssembleResolvConfTask = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(task.privilege, Privilege::Inherit);
    }

    #[test]
    fn serialize_deserialize_roundtrip_link() {
        let task = make_task_link("../run/systemd/resolve/stub-resolv.conf");
        let yaml = serde_yaml::to_string(&task).unwrap();
        let deserialized: AssembleResolvConfTask = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(task, deserialized);
    }

    #[test]
    fn serialize_deserialize_roundtrip_generate() {
        let task = make_task_generate(vec!["8.8.8.8"], vec!["example.com"]);
        let yaml = serde_yaml::to_string(&task).unwrap();
        let deserialized: AssembleResolvConfTask = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(task, deserialized);
    }

    #[test]
    fn serialize_skips_default_privilege() {
        let task = make_task_generate(vec!["8.8.8.8"], vec![]);
        let yaml = serde_yaml::to_string(&task).unwrap();
        assert!(!yaml.contains("privilege"));
    }

    #[test]
    fn serialize_skips_empty_fields() {
        let task = AssembleResolvConfTask {
            privilege: Privilege::Inherit,
            link: None,
            name_servers: vec![],
            search: vec![],
        };
        let yaml = serde_yaml::to_string(&task).unwrap();
        assert!(!yaml.contains("link"));
        assert!(!yaml.contains("name_servers"));
        assert!(!yaml.contains("search"));
        assert!(!yaml.contains("privilege"));
    }

    // =========================================================================
    // resolve_privilege() tests
    // =========================================================================

    #[test]
    fn resolve_privilege_inherit_with_defaults() {
        let mut task = make_task_generate(vec!["8.8.8.8"], vec![]);
        let defaults = crate::privilege::PrivilegeDefaults {
            method: PrivilegeMethod::Sudo,
        };
        task.resolve_privilege(Some(&defaults)).unwrap();
        assert_eq!(task.resolved_privilege_method(), Some(PrivilegeMethod::Sudo));
    }

    #[test]
    fn resolve_privilege_inherit_without_defaults() {
        let mut task = make_task_generate(vec!["8.8.8.8"], vec![]);
        task.resolve_privilege(None).unwrap();
        assert_eq!(task.resolved_privilege_method(), None);
    }

    #[test]
    fn resolve_privilege_disabled() {
        let mut task = AssembleResolvConfTask {
            privilege: Privilege::Disabled,
            link: None,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec![],
        };
        let defaults = crate::privilege::PrivilegeDefaults {
            method: PrivilegeMethod::Sudo,
        };
        task.resolve_privilege(Some(&defaults)).unwrap();
        assert_eq!(task.resolved_privilege_method(), None);
    }

    // =========================================================================
    // execute() tests
    // =========================================================================

    #[test]
    fn execute_generate_writes_file() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();

        let task = make_task_generate_resolved(vec!["8.8.8.8", "8.8.4.4"], vec!["example.com"]);

        let ctx = MockAssembleContext::new(&rootfs, false);
        task.execute(&ctx).unwrap();

        let content = std::fs::read_to_string(rootfs.join("etc/resolv.conf")).unwrap();
        assert!(content.contains("nameserver 8.8.8.8"));
        assert!(content.contains("nameserver 8.8.4.4"));
        assert!(content.contains("search example.com"));
        assert!(content.contains("# Generated by rsdebstrap"));
    }

    #[test]
    fn execute_generate_verifies_commands() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();

        let task = make_task_generate_resolved(vec!["8.8.8.8"], vec![]);

        let ctx = MockAssembleContext::new(&rootfs, false);
        task.execute(&ctx).unwrap();

        let commands = ctx.executed_commands();
        let staging = format!("{}{}", rootfs.join("etc/resolv.conf"), STAGING_SUFFIX);
        assert_eq!(commands.len(), 4);
        assert_eq!(commands[0].0, "rm");
        assert_eq!(commands[0].1, vec!["-f", staging.as_str()]);
        assert_eq!(commands[1].0, "cp");
        assert_eq!(commands[1].1[1], staging);
        assert_eq!(commands[2].0, "chmod");
        assert_eq!(commands[2].1, vec!["644", staging.as_str()]);
        assert_eq!(commands[3].0, "mv");
        assert_eq!(commands[3].1, vec![staging.as_str(), rootfs.join("etc/resolv.conf").as_str()]);
    }

    #[test]
    fn execute_link_creates_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();

        let task = make_task_link_resolved("../run/systemd/resolve/stub-resolv.conf");

        let ctx = MockAssembleContext::new(&rootfs, false);
        task.execute(&ctx).unwrap();

        let resolv_path = rootfs.join("etc/resolv.conf");
        let meta = std::fs::symlink_metadata(&resolv_path).unwrap();
        assert!(meta.is_symlink());
        let target = std::fs::read_link(&resolv_path).unwrap();
        assert_eq!(target.to_str().unwrap(), "../run/systemd/resolve/stub-resolv.conf");
    }

    #[test]
    fn execute_link_verifies_commands() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();

        let task = make_task_link_resolved("../run/systemd/resolve/stub-resolv.conf");

        let ctx = MockAssembleContext::new(&rootfs, false);
        task.execute(&ctx).unwrap();

        let commands = ctx.executed_commands();
        let staging = format!("{}{}", rootfs.join("etc/resolv.conf"), STAGING_SUFFIX);
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0].0, "ln");
        assert_eq!(
            commands[0].1,
            vec![
                "-sfn",
                "../run/systemd/resolve/stub-resolv.conf",
                staging.as_str()
            ]
        );
        assert_eq!(commands[1].0, "mv");
        assert_eq!(commands[1].1, vec![staging.as_str(), rootfs.join("etc/resolv.conf").as_str()]);
    }

    #[test]
    fn execute_link_absolute_creates_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();

        let task = make_task_link_resolved("/run/systemd/resolve/stub-resolv.conf");

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

        let task = make_task_generate_resolved(vec!["8.8.8.8"], vec![]);

        let ctx = MockAssembleContext::new(&rootfs, true);
        task.execute(&ctx).unwrap();

        assert!(!rootfs.join("etc/resolv.conf").exists());
        assert!(ctx.executed_commands().is_empty());
    }

    #[test]
    fn execute_overwrites_existing_file() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();
        std::fs::write(rootfs.join("etc/resolv.conf"), "old content").unwrap();

        let task = make_task_generate_resolved(vec!["8.8.8.8"], vec![]);

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

        let task = make_task_link_resolved("/new/target");

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

        let task = make_task_generate_resolved(vec!["8.8.8.8"], vec![]);

        let ctx = MockAssembleContext::new(&rootfs, false);
        let err = task.execute(&ctx).unwrap_err();
        assert!(err.to_string().contains("symlink"));
    }

    #[test]
    fn execute_generate_with_privilege() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();

        let task = AssembleResolvConfTask {
            privilege: Privilege::Method(PrivilegeMethod::Sudo),
            link: None,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec![],
        };

        let ctx = MockAssembleContext::new(&rootfs, false);
        task.execute(&ctx).unwrap();

        let privileges = ctx.executed_privileges();
        // rm, cp, chmod, mv — all escalated.
        assert_eq!(privileges.len(), 4);
        assert!(privileges.iter().all(|p| *p == Some(PrivilegeMethod::Sudo)));
    }

    #[test]
    fn execute_link_with_privilege() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();

        let task = AssembleResolvConfTask {
            privilege: Privilege::Method(PrivilegeMethod::Doas),
            link: Some("/run/systemd/resolve/stub-resolv.conf".to_string()),
            name_servers: vec![],
            search: vec![],
        };

        let ctx = MockAssembleContext::new(&rootfs, false);
        task.execute(&ctx).unwrap();

        let privileges = ctx.executed_privileges();
        assert_eq!(privileges.len(), 2);
        assert_eq!(privileges[0], Some(PrivilegeMethod::Doas));
        assert_eq!(privileges[1], Some(PrivilegeMethod::Doas));
    }

    #[test]
    fn execute_generate_errors_on_non_zero_cp_exit() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();

        let task = make_task_generate_resolved(vec!["8.8.8.8"], vec![]);

        let ctx = MockAssembleContext::new(&rootfs, false);
        ctx.executor.fail_on_command("cp");
        let err = task.execute(&ctx).unwrap_err();

        assert!(err.to_string().contains("command execution failed"));
        assert!(err.to_string().contains("cp"));
        // The failed stage never touched the final path.
        assert!(!rootfs.join("etc/resolv.conf").exists());
    }

    #[test]
    fn execute_link_errors_on_non_zero_ln_exit() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();

        let task = make_task_link_resolved("/run/systemd/resolve/stub-resolv.conf");

        let ctx = MockAssembleContext::new(&rootfs, false);
        ctx.executor.fail_on_command("ln");
        let err = task.execute(&ctx).unwrap_err();

        assert!(err.to_string().contains("command execution failed"));
        assert!(err.to_string().contains("ln"));
    }

    #[test]
    fn execute_link_errors_on_non_zero_mv_exit() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();
        std::fs::write(rootfs.join("etc/resolv.conf"), "old content").unwrap();

        let task = make_task_link_resolved("/run/systemd/resolve/stub-resolv.conf");

        let ctx = MockAssembleContext::new(&rootfs, false);
        ctx.executor.fail_on_command("mv");
        let err = task.execute(&ctx).unwrap_err();

        assert!(err.to_string().contains("command execution failed"));
        assert!(err.to_string().contains("mv"));
        // The atomicity invariant: a failed promote leaves the previous
        // resolv.conf untouched; only the staged symlink is left behind.
        let resolv = rootfs.join("etc/resolv.conf");
        assert_eq!(std::fs::read_to_string(&resolv).unwrap(), "old content");
        let staging = staging_path(&resolv);
        assert!(
            std::fs::symlink_metadata(&staging)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn execute_link_overwrites_stale_staging_symlink_to_directory() {
        // A stale staging entry from a failed build that is a symlink to a
        // directory: plain `ln -sf` would create the link *inside* it; `-n`
        // replaces the staging symlink itself.
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();
        let stale_dir = rootfs.join("stale_dir");
        std::fs::create_dir_all(&stale_dir).unwrap();
        let staging = staging_path(&rootfs.join("etc/resolv.conf"));
        std::os::unix::fs::symlink(&stale_dir, &staging).unwrap();

        let task = make_task_link_resolved("/new/target");
        let ctx = MockAssembleContext::new(&rootfs, false);
        task.execute(&ctx).unwrap();

        let target = std::fs::read_link(rootfs.join("etc/resolv.conf")).unwrap();
        assert_eq!(target.to_str().unwrap(), "/new/target");
        // Nothing leaked into the stale directory; the staging entry was
        // consumed by the rename.
        assert!(std::fs::read_dir(&stale_dir).unwrap().next().is_none());
        assert!(std::fs::symlink_metadata(&staging).is_err());
    }

    #[test]
    fn execute_generate_overwrites_stale_staging_symlink_to_directory() {
        // A stale staging entry left by a failed LINK-mode build that is a
        // symlink to a directory: a bare `cp` would follow it and write the
        // generated content *inside* the directory, leaving the staging symlink
        // for `mv` to promote (a wrong-typed resolv.conf). The `rm -f <staging>`
        // before the copy replaces the stale symlink so a real file is staged.
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();
        let stale_dir = rootfs.join("stale_dir");
        std::fs::create_dir_all(&stale_dir).unwrap();
        let staging = staging_path(&rootfs.join("etc/resolv.conf"));
        std::os::unix::fs::symlink(&stale_dir, &staging).unwrap();

        let task = make_task_generate_resolved(vec!["8.8.8.8"], vec![]);
        let ctx = MockAssembleContext::new(&rootfs, false);
        task.execute(&ctx).unwrap();

        let resolv = rootfs.join("etc/resolv.conf");
        assert!(
            std::fs::symlink_metadata(&resolv)
                .unwrap()
                .file_type()
                .is_file()
        );
        assert!(
            std::fs::read_to_string(&resolv)
                .unwrap()
                .contains("nameserver 8.8.8.8")
        );
        // Nothing was written through the stale symlink into the directory, and
        // the staging entry was consumed by the promoting rename.
        assert!(std::fs::read_dir(&stale_dir).unwrap().next().is_none());
        assert!(std::fs::symlink_metadata(&staging).is_err());
    }

    #[test]
    fn execute_generate_overwrites_stale_dangling_staging_symlink() {
        // A stale staging entry that is a dangling symlink (a failed LINK-mode
        // build whose target does not exist): a bare `cp` refuses with "not
        // writing through dangling symlink" and the build would stay stuck on
        // every retry. The `rm -f <staging>` clears it so the copy succeeds.
        let temp = tempfile::tempdir().unwrap();
        let rootfs = camino::Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();
        let staging = staging_path(&rootfs.join("etc/resolv.conf"));
        std::os::unix::fs::symlink(rootfs.join("does_not_exist"), &staging).unwrap();

        let task = make_task_generate_resolved(vec!["8.8.8.8"], vec![]);
        let ctx = MockAssembleContext::new(&rootfs, false);
        task.execute(&ctx).unwrap();

        let resolv = rootfs.join("etc/resolv.conf");
        assert!(
            std::fs::symlink_metadata(&resolv)
                .unwrap()
                .file_type()
                .is_file()
        );
        assert!(
            std::fs::read_to_string(&resolv)
                .unwrap()
                .contains("nameserver 8.8.8.8")
        );
        assert!(std::fs::symlink_metadata(&staging).is_err());
    }

    // =========================================================================
    // Test helpers
    // =========================================================================

    fn make_task_link(target: &str) -> AssembleResolvConfTask {
        AssembleResolvConfTask {
            privilege: Privilege::Inherit,
            link: Some(target.to_string()),
            name_servers: vec![],
            search: vec![],
        }
    }

    fn make_task_link_resolved(target: &str) -> AssembleResolvConfTask {
        AssembleResolvConfTask {
            privilege: Privilege::Disabled,
            link: Some(target.to_string()),
            name_servers: vec![],
            search: vec![],
        }
    }

    fn make_task_generate(ns: Vec<&str>, search: Vec<&str>) -> AssembleResolvConfTask {
        AssembleResolvConfTask {
            privilege: Privilege::Inherit,
            link: None,
            name_servers: ns.into_iter().map(|s| s.parse().unwrap()).collect(),
            search: search.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    fn make_task_generate_resolved(ns: Vec<&str>, search: Vec<&str>) -> AssembleResolvConfTask {
        AssembleResolvConfTask {
            privilege: Privilege::Disabled,
            link: None,
            name_servers: ns.into_iter().map(|s| s.parse().unwrap()).collect(),
            search: search.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    // =========================================================================
    // Mock executor and context for execute tests
    // =========================================================================

    /// A recorded command with its arguments and privilege setting.
    type RecordedCommand = (String, Vec<String>, Option<PrivilegeMethod>);

    /// Records executed commands for assertion.
    struct MockCommandExecutor {
        commands: Mutex<Vec<RecordedCommand>>,
        fail_on_command: Mutex<Option<String>>,
    }

    impl MockCommandExecutor {
        fn new() -> Self {
            Self {
                commands: Mutex::new(Vec::new()),
                fail_on_command: Mutex::new(None),
            }
        }

        fn fail_on_command(&self, command: &str) {
            *self.fail_on_command.lock().unwrap() = Some(command.to_string());
        }
    }

    impl CommandExecutor for MockCommandExecutor {
        fn execute(&self, spec: &crate::executor::CommandSpec) -> anyhow::Result<ExecutionResult> {
            if self
                .fail_on_command
                .lock()
                .unwrap()
                .as_deref()
                .is_some_and(|command| command == spec.command)
            {
                self.commands.lock().unwrap().push((
                    spec.command.clone(),
                    spec.args.clone(),
                    spec.privilege,
                ));
                return Ok(ExecutionResult {
                    status: Some(ExitStatus::from_raw(1 << 8)),
                });
            }

            // Actually execute the command so tests can verify file effects
            let mut cmd = std::process::Command::new(&spec.command);
            cmd.args(&spec.args);
            if let Some(cwd) = &spec.cwd {
                cmd.current_dir(cwd.as_std_path());
            }
            for (key, value) in &spec.env {
                cmd.env(key, value);
            }
            let status = cmd.status()?;

            self.commands.lock().unwrap().push((
                spec.command.clone(),
                spec.args.clone(),
                spec.privilege,
            ));

            Ok(ExecutionResult {
                status: Some(status),
            })
        }
    }

    struct MockAssembleContext {
        rootfs: camino::Utf8PathBuf,
        dry_run: bool,
        executor: Arc<MockCommandExecutor>,
    }

    impl MockAssembleContext {
        fn new(rootfs: &camino::Utf8Path, dry_run: bool) -> Self {
            Self {
                rootfs: rootfs.to_owned(),
                dry_run,
                executor: Arc::new(MockCommandExecutor::new()),
            }
        }

        fn executed_commands(&self) -> Vec<(String, Vec<String>)> {
            self.executor
                .commands
                .lock()
                .unwrap()
                .iter()
                .map(|(cmd, args, _)| (cmd.clone(), args.clone()))
                .collect()
        }

        fn executed_privileges(&self) -> Vec<Option<PrivilegeMethod>> {
            self.executor
                .commands
                .lock()
                .unwrap()
                .iter()
                .map(|(_, _, p)| *p)
                .collect()
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

        fn executor(&self) -> &dyn CommandExecutor {
            &*self.executor
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
