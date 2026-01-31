//! chroot isolation implementation.

use anyhow::Result;
use camino::Utf8Path;
use serde::Deserialize;
use std::ffi::OsString;

use super::{IsolationStrategy, Privilege};
use crate::executor::CommandSpec;

/// chroot isolation configuration.
///
/// Uses the `chroot` command to execute scripts in an isolated rootfs.
///
/// # Example YAML
///
/// ```yaml
/// isolation:
///   type: chroot
///   privilege: sudo
/// ```
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct ChrootIsolation {
    /// Privilege escalation method (none or sudo)
    #[serde(default)]
    pub privilege: Privilege,
}

impl IsolationStrategy for ChrootIsolation {
    fn command_name(&self) -> &str {
        match self.privilege {
            Privilege::None => "chroot",
            Privilege::Sudo => "sudo",
        }
    }

    fn build_command(
        &self,
        rootfs: &Utf8Path,
        shell: &str,
        script_path: &str,
    ) -> Result<CommandSpec> {
        let args: Vec<OsString> = match self.privilege {
            Privilege::None => {
                vec![rootfs.as_str().into(), shell.into(), script_path.into()]
            }
            Privilege::Sudo => {
                vec![
                    "chroot".into(),
                    rootfs.as_str().into(),
                    shell.into(),
                    script_path.into(),
                ]
            }
        };

        let command = self.command_name().to_string();
        Ok(CommandSpec::new(command, args))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chroot_isolation_default() {
        let isolation = ChrootIsolation::default();
        assert_eq!(isolation.privilege, Privilege::None);
    }

    #[test]
    fn test_chroot_isolation_command_name_no_privilege() {
        let isolation = ChrootIsolation {
            privilege: Privilege::None,
        };
        assert_eq!(isolation.command_name(), "chroot");
    }

    #[test]
    fn test_chroot_isolation_command_name_sudo() {
        let isolation = ChrootIsolation {
            privilege: Privilege::Sudo,
        };
        assert_eq!(isolation.command_name(), "sudo");
    }

    #[test]
    fn test_chroot_isolation_build_command_no_privilege() {
        let isolation = ChrootIsolation {
            privilege: Privilege::None,
        };
        let rootfs = Utf8Path::new("/rootfs");
        let spec = isolation
            .build_command(rootfs, "/bin/sh", "/tmp/script.sh")
            .unwrap();

        assert_eq!(spec.command, "chroot");
        assert_eq!(spec.args.len(), 3);
        assert_eq!(spec.args[0], "/rootfs");
        assert_eq!(spec.args[1], "/bin/sh");
        assert_eq!(spec.args[2], "/tmp/script.sh");
    }

    #[test]
    fn test_chroot_isolation_build_command_sudo() {
        let isolation = ChrootIsolation {
            privilege: Privilege::Sudo,
        };
        let rootfs = Utf8Path::new("/rootfs");
        let spec = isolation
            .build_command(rootfs, "/bin/sh", "/tmp/script.sh")
            .unwrap();

        assert_eq!(spec.command, "sudo");
        assert_eq!(spec.args.len(), 4);
        assert_eq!(spec.args[0], "chroot");
        assert_eq!(spec.args[1], "/rootfs");
        assert_eq!(spec.args[2], "/bin/sh");
        assert_eq!(spec.args[3], "/tmp/script.sh");
    }

    #[test]
    fn test_chroot_isolation_deserialize() {
        let yaml = r#"
type: chroot
privilege: sudo
"#;
        let config: super::super::IsolationConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            super::super::IsolationConfig::Chroot(chroot) => {
                assert_eq!(chroot.privilege, Privilege::Sudo);
            }
            _ => panic!("Expected ChrootIsolation"),
        }
    }

    #[test]
    fn test_chroot_isolation_deserialize_defaults() {
        let yaml = r#"
type: chroot
"#;
        let config: super::super::IsolationConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            super::super::IsolationConfig::Chroot(chroot) => {
                assert_eq!(chroot.privilege, Privilege::None);
            }
            _ => panic!("Expected ChrootIsolation"),
        }
    }
}
