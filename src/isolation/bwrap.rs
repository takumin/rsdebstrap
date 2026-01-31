//! bubblewrap (bwrap) isolation implementation.

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use serde::Deserialize;
use std::ffi::OsString;

use super::IsolationStrategy;
use crate::executor::CommandSpec;

/// bubblewrap isolation configuration.
///
/// Uses `bwrap` (bubblewrap) to execute scripts in an unprivileged sandbox.
///
/// # Example YAML
///
/// ```yaml
/// isolation:
///   type: bwrap
///   dev: /dev
///   proc: /proc
///   unshare_net: true
///   bind:
///     - /some/path
///   bind_ro:
///     - /etc/resolv.conf
/// ```
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct BwrapIsolation {
    /// Create a new /dev tmpfs at the given path inside the sandbox (`--dev <path>`).
    #[serde(default)]
    pub dev: Option<Utf8PathBuf>,

    /// Mount a new procfs at the given path inside the sandbox (`--proc <path>`).
    #[serde(default)]
    pub proc: Option<Utf8PathBuf>,

    /// Unshare network namespace (--unshare-net)
    #[serde(default)]
    pub unshare_net: bool,

    /// Bind mount paths read-write inside the sandbox (`--bind SRC DEST`).
    /// Each path is mounted at the same location inside the sandbox.
    #[serde(default)]
    pub bind: Vec<Utf8PathBuf>,

    /// Bind mount paths read-only inside the sandbox (`--ro-bind SRC DEST`).
    /// Each path is mounted at the same location inside the sandbox.
    #[serde(default)]
    pub bind_ro: Vec<Utf8PathBuf>,
}

impl IsolationStrategy for BwrapIsolation {
    fn command_name(&self) -> &str {
        "bwrap"
    }

    fn build_command(
        &self,
        rootfs: &Utf8Path,
        shell: &str,
        script_path: &str,
    ) -> Result<CommandSpec> {
        let mut args: Vec<OsString> = Vec::new();

        // Bind the rootfs as root
        args.push("--bind".into());
        args.push(rootfs.as_str().into());
        args.push("/".into());

        // Optional /dev mount
        if let Some(dev) = &self.dev {
            args.push("--dev".into());
            args.push(dev.as_str().into());
        }

        // Optional /proc mount
        if let Some(proc) = &self.proc {
            args.push("--proc".into());
            args.push(proc.as_str().into());
        }

        // Bind mounts (read-write)
        for path in &self.bind {
            args.push("--bind".into());
            args.push(path.as_str().into());
            args.push(path.as_str().into()); // Same dest as src
        }

        // Bind mounts (read-only)
        for path in &self.bind_ro {
            args.push("--ro-bind".into());
            args.push(path.as_str().into());
            args.push(path.as_str().into()); // Same dest as src
        }

        // Optional network namespace unsharing
        if self.unshare_net {
            args.push("--unshare-net".into());
        }

        // Separator to prevent script path from being interpreted as options
        args.push("--".into());

        // Shell and script
        args.push(shell.into());
        args.push(script_path.into());

        Ok(CommandSpec::new("bwrap", args))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bwrap_isolation_default() {
        let isolation = BwrapIsolation::default();
        assert!(isolation.dev.is_none());
        assert!(isolation.proc.is_none());
        assert!(!isolation.unshare_net);
        assert!(isolation.bind.is_empty());
        assert!(isolation.bind_ro.is_empty());
    }

    #[test]
    fn test_bwrap_isolation_command_name() {
        let isolation = BwrapIsolation::default();
        assert_eq!(isolation.command_name(), "bwrap");
    }

    #[test]
    fn test_bwrap_isolation_build_command_minimal() {
        let isolation = BwrapIsolation {
            dev: None,
            proc: None,
            unshare_net: false,
            bind: vec![],
            bind_ro: vec![],
        };
        let rootfs = Utf8Path::new("/rootfs");
        let spec = isolation
            .build_command(rootfs, "/bin/sh", "/tmp/script.sh")
            .unwrap();

        assert_eq!(spec.command, "bwrap");
        assert_eq!(spec.args.len(), 6);
        assert_eq!(spec.args[0], "--bind");
        assert_eq!(spec.args[1], "/rootfs");
        assert_eq!(spec.args[2], "/");
        assert_eq!(spec.args[3], "--");
        assert_eq!(spec.args[4], "/bin/sh");
        assert_eq!(spec.args[5], "/tmp/script.sh");
    }

    #[test]
    fn test_bwrap_isolation_build_command_with_dev() {
        let isolation = BwrapIsolation {
            dev: Some("/dev".into()),
            proc: None,
            unshare_net: false,
            bind: vec![],
            bind_ro: vec![],
        };
        let rootfs = Utf8Path::new("/rootfs");
        let spec = isolation
            .build_command(rootfs, "/bin/sh", "/tmp/script.sh")
            .unwrap();

        assert_eq!(spec.command, "bwrap");
        assert_eq!(spec.args.len(), 8);
        assert_eq!(spec.args[0], "--bind");
        assert_eq!(spec.args[1], "/rootfs");
        assert_eq!(spec.args[2], "/");
        assert_eq!(spec.args[3], "--dev");
        assert_eq!(spec.args[4], "/dev");
        assert_eq!(spec.args[5], "--");
        assert_eq!(spec.args[6], "/bin/sh");
        assert_eq!(spec.args[7], "/tmp/script.sh");
    }

    #[test]
    fn test_bwrap_isolation_build_command_with_all_options() {
        let isolation = BwrapIsolation {
            dev: Some("/dev".into()),
            proc: Some("/proc".into()),
            unshare_net: true,
            bind: vec![],
            bind_ro: vec![],
        };
        let rootfs = Utf8Path::new("/rootfs");
        let spec = isolation
            .build_command(rootfs, "/bin/sh", "/tmp/script.sh")
            .unwrap();

        assert_eq!(spec.command, "bwrap");
        assert_eq!(spec.args.len(), 11);
        assert_eq!(spec.args[0], "--bind");
        assert_eq!(spec.args[1], "/rootfs");
        assert_eq!(spec.args[2], "/");
        assert_eq!(spec.args[3], "--dev");
        assert_eq!(spec.args[4], "/dev");
        assert_eq!(spec.args[5], "--proc");
        assert_eq!(spec.args[6], "/proc");
        assert_eq!(spec.args[7], "--unshare-net");
        assert_eq!(spec.args[8], "--");
        assert_eq!(spec.args[9], "/bin/sh");
        assert_eq!(spec.args[10], "/tmp/script.sh");
    }

    #[test]
    fn test_bwrap_isolation_deserialize() {
        let yaml = r#"
type: bwrap
dev: /dev
proc: /proc
unshare_net: true
"#;
        let config: super::super::IsolationConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            super::super::IsolationConfig::Bwrap(bwrap) => {
                assert_eq!(bwrap.dev, Some("/dev".into()));
                assert_eq!(bwrap.proc, Some("/proc".into()));
                assert!(bwrap.unshare_net);
            }
            _ => panic!("Expected BwrapIsolation"),
        }
    }

    #[test]
    fn test_bwrap_isolation_deserialize_defaults() {
        let yaml = r#"
type: bwrap
"#;
        let config: super::super::IsolationConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            super::super::IsolationConfig::Bwrap(bwrap) => {
                assert!(bwrap.dev.is_none());
                assert!(bwrap.proc.is_none());
                assert!(!bwrap.unshare_net);
                assert!(bwrap.bind.is_empty());
                assert!(bwrap.bind_ro.is_empty());
            }
            _ => panic!("Expected BwrapIsolation"),
        }
    }

    #[test]
    fn test_bwrap_isolation_build_command_with_binds() {
        let isolation = BwrapIsolation {
            dev: Some("/dev".into()),
            proc: None,
            unshare_net: false,
            bind: vec!["/some/path".into()],
            bind_ro: vec!["/etc/resolv.conf".into()],
        };
        let rootfs = Utf8Path::new("/rootfs");
        let spec = isolation
            .build_command(rootfs, "/bin/sh", "/tmp/script.sh")
            .unwrap();

        assert_eq!(spec.command, "bwrap");
        assert_eq!(spec.args.len(), 14);
        assert_eq!(spec.args[0], "--bind");
        assert_eq!(spec.args[1], "/rootfs");
        assert_eq!(spec.args[2], "/");
        assert_eq!(spec.args[3], "--dev");
        assert_eq!(spec.args[4], "/dev");
        assert_eq!(spec.args[5], "--bind");
        assert_eq!(spec.args[6], "/some/path");
        assert_eq!(spec.args[7], "/some/path");
        assert_eq!(spec.args[8], "--ro-bind");
        assert_eq!(spec.args[9], "/etc/resolv.conf");
        assert_eq!(spec.args[10], "/etc/resolv.conf");
        assert_eq!(spec.args[11], "--");
        assert_eq!(spec.args[12], "/bin/sh");
        assert_eq!(spec.args[13], "/tmp/script.sh");
    }

    #[test]
    fn test_bwrap_isolation_deserialize_with_binds() {
        let yaml = r#"
type: bwrap
dev: /dev
bind:
    - /some/path
bind_ro:
    - /etc/resolv.conf
"#;
        let config: super::super::IsolationConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            super::super::IsolationConfig::Bwrap(bwrap) => {
                assert_eq!(bwrap.dev, Some("/dev".into()));
                assert_eq!(bwrap.bind.len(), 1);
                assert_eq!(bwrap.bind[0], "/some/path");
                assert_eq!(bwrap.bind_ro.len(), 1);
                assert_eq!(bwrap.bind_ro[0], "/etc/resolv.conf");
            }
            _ => panic!("Expected BwrapIsolation"),
        }
    }
}
