//! systemd-nspawn isolation implementation.

use anyhow::Result;
use camino::Utf8Path;
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
        };
        let rootfs = Utf8Path::new("/rootfs");
        let spec = isolation
            .build_command(rootfs, "/bin/sh", "/tmp/script.sh")
            .unwrap();

        assert_eq!(spec.command, "systemd-nspawn");
        assert_eq!(spec.args.len(), 4);
        assert_eq!(spec.args[0], "-D");
        assert_eq!(spec.args[1], "/rootfs");
        assert_eq!(spec.args[2], "/bin/sh");
        assert_eq!(spec.args[3], "/tmp/script.sh");
    }

    #[test]
    fn test_nspawn_isolation_build_command_with_options() {
        let isolation = NspawnIsolation {
            privilege: Privilege::None,
            quiet: true,
            private_network: true,
        };
        let rootfs = Utf8Path::new("/rootfs");
        let spec = isolation
            .build_command(rootfs, "/bin/sh", "/tmp/script.sh")
            .unwrap();

        assert_eq!(spec.command, "systemd-nspawn");
        assert_eq!(spec.args.len(), 6);
        assert_eq!(spec.args[0], "-D");
        assert_eq!(spec.args[1], "/rootfs");
        assert_eq!(spec.args[2], "--quiet");
        assert_eq!(spec.args[3], "--private-network");
        assert_eq!(spec.args[4], "/bin/sh");
        assert_eq!(spec.args[5], "/tmp/script.sh");
    }

    #[test]
    fn test_nspawn_isolation_build_command_sudo() {
        let isolation = NspawnIsolation {
            privilege: Privilege::Sudo,
            quiet: true,
            private_network: false,
        };
        let rootfs = Utf8Path::new("/rootfs");
        let spec = isolation
            .build_command(rootfs, "/bin/sh", "/tmp/script.sh")
            .unwrap();

        assert_eq!(spec.command, "sudo");
        assert_eq!(spec.args.len(), 6);
        assert_eq!(spec.args[0], "systemd-nspawn");
        assert_eq!(spec.args[1], "-D");
        assert_eq!(spec.args[2], "/rootfs");
        assert_eq!(spec.args[3], "--quiet");
        assert_eq!(spec.args[4], "/bin/sh");
        assert_eq!(spec.args[5], "/tmp/script.sh");
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
            }
            _ => panic!("Expected NspawnIsolation"),
        }
    }
}
