//! bubblewrap (bwrap) isolation implementation.

use anyhow::Result;
use camino::Utf8Path;
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
/// ```
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct BwrapIsolation {
    /// Bind mount /dev from host (--dev)
    #[serde(default)]
    pub dev: Option<String>,

    /// Bind mount /proc from host (--proc)
    #[serde(default)]
    pub proc: Option<String>,

    /// Unshare network namespace (--unshare-net)
    #[serde(default)]
    pub unshare_net: bool,
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

        // Optional network namespace unsharing
        if self.unshare_net {
            args.push("--unshare-net".into());
        }

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
        };
        let rootfs = Utf8Path::new("/rootfs");
        let spec = isolation
            .build_command(rootfs, "/bin/sh", "/tmp/script.sh")
            .unwrap();

        assert_eq!(spec.command, "bwrap");
        assert_eq!(spec.args.len(), 5);
        assert_eq!(spec.args[0], "--bind");
        assert_eq!(spec.args[1], "/rootfs");
        assert_eq!(spec.args[2], "/");
        assert_eq!(spec.args[3], "/bin/sh");
        assert_eq!(spec.args[4], "/tmp/script.sh");
    }

    #[test]
    fn test_bwrap_isolation_build_command_with_dev() {
        let isolation = BwrapIsolation {
            dev: Some("/dev".to_string()),
            proc: None,
            unshare_net: false,
        };
        let rootfs = Utf8Path::new("/rootfs");
        let spec = isolation
            .build_command(rootfs, "/bin/sh", "/tmp/script.sh")
            .unwrap();

        assert_eq!(spec.command, "bwrap");
        assert_eq!(spec.args.len(), 7);
        assert_eq!(spec.args[0], "--bind");
        assert_eq!(spec.args[1], "/rootfs");
        assert_eq!(spec.args[2], "/");
        assert_eq!(spec.args[3], "--dev");
        assert_eq!(spec.args[4], "/dev");
        assert_eq!(spec.args[5], "/bin/sh");
        assert_eq!(spec.args[6], "/tmp/script.sh");
    }

    #[test]
    fn test_bwrap_isolation_build_command_with_all_options() {
        let isolation = BwrapIsolation {
            dev: Some("/dev".to_string()),
            proc: Some("/proc".to_string()),
            unshare_net: true,
        };
        let rootfs = Utf8Path::new("/rootfs");
        let spec = isolation
            .build_command(rootfs, "/bin/sh", "/tmp/script.sh")
            .unwrap();

        assert_eq!(spec.command, "bwrap");
        assert_eq!(spec.args.len(), 10);
        assert_eq!(spec.args[0], "--bind");
        assert_eq!(spec.args[1], "/rootfs");
        assert_eq!(spec.args[2], "/");
        assert_eq!(spec.args[3], "--dev");
        assert_eq!(spec.args[4], "/dev");
        assert_eq!(spec.args[5], "--proc");
        assert_eq!(spec.args[6], "/proc");
        assert_eq!(spec.args[7], "--unshare-net");
        assert_eq!(spec.args[8], "/bin/sh");
        assert_eq!(spec.args[9], "/tmp/script.sh");
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
                assert_eq!(bwrap.dev, Some("/dev".to_string()));
                assert_eq!(bwrap.proc, Some("/proc".to_string()));
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
            }
            _ => panic!("Expected BwrapIsolation"),
        }
    }
}
