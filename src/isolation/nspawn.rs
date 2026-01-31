//! systemd-nspawn isolation implementation.

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use serde::Deserialize;
use std::ffi::OsString;

use super::{IsolationStrategy, Privilege};
use crate::executor::CommandSpec;

/// systemd-nspawn isolation configuration.
///
/// Uses `systemd-nspawn` to execute scripts in an isolated container environment.
///
/// # Example YAML
///
/// ```yaml
/// isolation:
///   type: nspawn
///   privilege: sudo
///   quiet: true
///   private_network: true
///   bind_ro:
///     - /etc/resolv.conf
///     - /etc/hosts
/// ```
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct NspawnIsolation {
    /// Privilege escalation method (none or sudo)
    #[serde(default)]
    pub privilege: Privilege,

    /// Suppress informational messages (--quiet)
    #[serde(default)]
    pub quiet: bool,

    /// Disconnect networking from the container (--private-network)
    #[serde(default)]
    pub private_network: bool,

    /// Read-only bind mount paths (`--bind-ro=`).
    /// Each path is mounted at the same location inside the container.
    #[serde(default)]
    pub bind_ro: Vec<Utf8PathBuf>,
}

impl IsolationStrategy for NspawnIsolation {
    fn command_name(&self) -> &str {
        match self.privilege {
            Privilege::None => "systemd-nspawn",
            Privilege::Sudo => "sudo",
        }
    }

    fn build_command(
        &self,
        rootfs: &Utf8Path,
        shell: &str,
        script_path: &str,
    ) -> Result<CommandSpec> {
        let mut args: Vec<OsString> = Vec::new();

        // Add systemd-nspawn if using sudo
        if self.privilege == Privilege::Sudo {
            args.push("systemd-nspawn".into());
        }

        // Directory option
        args.push("-D".into());
        args.push(rootfs.as_str().into());

        // Optional flags
        if self.quiet {
            args.push("--quiet".into());
        }

        if self.private_network {
            args.push("--private-network".into());
        }

        // Read-only bind mounts
        for path in &self.bind_ro {
            args.push(format!("--bind-ro={}", path).into());
        }

        // Separator to prevent script path from being interpreted as options
        args.push("--".into());

        // Shell and script
        args.push(shell.into());
        args.push(script_path.into());

        let command = self.command_name().to_string();
        Ok(CommandSpec::new(command, args))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nspawn_isolation_default() {
        let isolation = NspawnIsolation::default();
        assert_eq!(isolation.privilege, Privilege::None);
        assert!(!isolation.quiet);
        assert!(!isolation.private_network);
        assert!(isolation.bind_ro.is_empty());
    }

    #[test]
    fn test_nspawn_isolation_command_name_no_privilege() {
        let isolation = NspawnIsolation {
            privilege: Privilege::None,
            ..Default::default()
        };
        assert_eq!(isolation.command_name(), "systemd-nspawn");
    }

    #[test]
    fn test_nspawn_isolation_command_name_sudo() {
        let isolation = NspawnIsolation {
            privilege: Privilege::Sudo,
            ..Default::default()
        };
        assert_eq!(isolation.command_name(), "sudo");
    }

    #[test]
    fn test_nspawn_isolation_build_command_minimal() {
        let isolation = NspawnIsolation {
            privilege: Privilege::None,
            quiet: false,
            private_network: false,
            bind_ro: vec![],
        };
        let rootfs = Utf8Path::new("/rootfs");
        let spec = isolation
            .build_command(rootfs, "/bin/sh", "/tmp/script.sh")
            .unwrap();

        assert_eq!(spec.command, "systemd-nspawn");
        assert_eq!(spec.args.len(), 5);
        assert_eq!(spec.args[0], "-D");
        assert_eq!(spec.args[1], "/rootfs");
        assert_eq!(spec.args[2], "--");
        assert_eq!(spec.args[3], "/bin/sh");
        assert_eq!(spec.args[4], "/tmp/script.sh");
    }

    #[test]
    fn test_nspawn_isolation_build_command_with_options() {
        let isolation = NspawnIsolation {
            privilege: Privilege::None,
            quiet: true,
            private_network: true,
            bind_ro: vec![],
        };
        let rootfs = Utf8Path::new("/rootfs");
        let spec = isolation
            .build_command(rootfs, "/bin/sh", "/tmp/script.sh")
            .unwrap();

        assert_eq!(spec.command, "systemd-nspawn");
        assert_eq!(spec.args.len(), 7);
        assert_eq!(spec.args[0], "-D");
        assert_eq!(spec.args[1], "/rootfs");
        assert_eq!(spec.args[2], "--quiet");
        assert_eq!(spec.args[3], "--private-network");
        assert_eq!(spec.args[4], "--");
        assert_eq!(spec.args[5], "/bin/sh");
        assert_eq!(spec.args[6], "/tmp/script.sh");
    }

    #[test]
    fn test_nspawn_isolation_build_command_sudo() {
        let isolation = NspawnIsolation {
            privilege: Privilege::Sudo,
            quiet: true,
            private_network: false,
            bind_ro: vec![],
        };
        let rootfs = Utf8Path::new("/rootfs");
        let spec = isolation
            .build_command(rootfs, "/bin/sh", "/tmp/script.sh")
            .unwrap();

        assert_eq!(spec.command, "sudo");
        assert_eq!(spec.args.len(), 7);
        assert_eq!(spec.args[0], "systemd-nspawn");
        assert_eq!(spec.args[1], "-D");
        assert_eq!(spec.args[2], "/rootfs");
        assert_eq!(spec.args[3], "--quiet");
        assert_eq!(spec.args[4], "--");
        assert_eq!(spec.args[5], "/bin/sh");
        assert_eq!(spec.args[6], "/tmp/script.sh");
    }

    #[test]
    fn test_nspawn_isolation_deserialize() {
        let yaml = r#"
type: nspawn
privilege: sudo
quiet: true
private_network: true
"#;
        let config: super::super::IsolationConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            super::super::IsolationConfig::Nspawn(nspawn) => {
                assert_eq!(nspawn.privilege, Privilege::Sudo);
                assert!(nspawn.quiet);
                assert!(nspawn.private_network);
            }
            _ => panic!("Expected NspawnIsolation"),
        }
    }

    #[test]
    fn test_nspawn_isolation_deserialize_defaults() {
        let yaml = r#"
type: nspawn
"#;
        let config: super::super::IsolationConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            super::super::IsolationConfig::Nspawn(nspawn) => {
                assert_eq!(nspawn.privilege, Privilege::None);
                assert!(!nspawn.quiet);
                assert!(!nspawn.private_network);
                assert!(nspawn.bind_ro.is_empty());
            }
            _ => panic!("Expected NspawnIsolation"),
        }
    }

    #[test]
    fn test_nspawn_isolation_build_command_with_bind_ro() {
        let isolation = NspawnIsolation {
            privilege: Privilege::Sudo,
            quiet: false,
            private_network: false,
            bind_ro: vec!["/etc/resolv.conf".into(), "/etc/hosts".into()],
        };
        let rootfs = Utf8Path::new("/rootfs");
        let spec = isolation
            .build_command(rootfs, "/bin/sh", "/tmp/script.sh")
            .unwrap();

        assert_eq!(spec.command, "sudo");
        assert_eq!(spec.args.len(), 8);
        assert_eq!(spec.args[0], "systemd-nspawn");
        assert_eq!(spec.args[1], "-D");
        assert_eq!(spec.args[2], "/rootfs");
        assert_eq!(spec.args[3], "--bind-ro=/etc/resolv.conf");
        assert_eq!(spec.args[4], "--bind-ro=/etc/hosts");
        assert_eq!(spec.args[5], "--");
        assert_eq!(spec.args[6], "/bin/sh");
        assert_eq!(spec.args[7], "/tmp/script.sh");
    }

    #[test]
    fn test_nspawn_isolation_deserialize_with_bind_ro() {
        let yaml = r#"
type: nspawn
privilege: sudo
bind_ro:
    - /etc/resolv.conf
    - /etc/hosts
"#;
        let config: super::super::IsolationConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            super::super::IsolationConfig::Nspawn(nspawn) => {
                assert_eq!(nspawn.privilege, Privilege::Sudo);
                assert_eq!(nspawn.bind_ro.len(), 2);
                assert_eq!(nspawn.bind_ro[0], "/etc/resolv.conf");
                assert_eq!(nspawn.bind_ro[1], "/etc/hosts");
            }
            _ => panic!("Expected NspawnIsolation"),
        }
    }
}
