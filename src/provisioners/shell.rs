//! Shell provisioner implementation.

use super::Provisioner;
use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use serde::Deserialize;
use std::ffi::OsString;
use std::fs;
use tracing::{debug, info};

use crate::executor::CommandExecutor;

/// Shell provisioner configuration.
///
/// Executes shell scripts inside the bootstrapped rootfs using chroot.
/// Either `script` (external file) or `content` (inline script) must be specified,
/// but not both.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct ShellProvisioner {
    /// Path to external shell script file (mutually exclusive with `content`)
    #[serde(default)]
    pub script: Option<Utf8PathBuf>,

    /// Inline shell script content (mutually exclusive with `script`)
    #[serde(default)]
    pub content: Option<String>,

    /// Shell interpreter to use (default: /bin/sh)
    #[serde(default = "default_shell")]
    pub shell: String,
}

fn default_shell() -> String {
    "/bin/sh".to_string()
}

impl ShellProvisioner {
    /// Validates that exactly one of `script` or `content` is specified.
    fn validate(&self) -> Result<()> {
        match (&self.script, &self.content) {
            (None, None) => {
                bail!("shell provisioner must specify either 'script' or 'content'")
            }
            (Some(_), Some(_)) => {
                bail!("shell provisioner cannot specify both 'script' and 'content'")
            }
            _ => Ok(()),
        }
    }

    /// Returns the script source for logging purposes.
    fn script_source(&self) -> &str {
        if let Some(script) = &self.script {
            script.as_str()
        } else {
            "<inline>"
        }
    }

    /// Validates that the rootfs is ready for chroot operations.
    fn validate_rootfs(&self, rootfs: &Utf8Path) -> Result<()> {
        // Check if /tmp directory exists
        let tmp_dir = rootfs.join("tmp");
        if !tmp_dir.exists() {
            bail!(
                "rootfs does not have /tmp directory: {}. The rootfs may not be properly bootstrapped.",
                rootfs
            );
        }

        // Check if the specified shell exists in rootfs
        let shell_in_rootfs = rootfs.join(self.shell.trim_start_matches('/'));
        if !shell_in_rootfs.exists() {
            bail!("shell '{}' does not exist in rootfs at {}", self.shell, shell_in_rootfs);
        }

        Ok(())
    }
}

impl Provisioner for ShellProvisioner {
    fn provision(&self, rootfs: &Utf8Path, executor: &dyn CommandExecutor) -> Result<()> {
        self.validate()
            .context("shell provisioner validation failed")?;

        self.validate_rootfs(rootfs)
            .context("rootfs validation failed")?;

        info!("running shell provisioner: {}", self.script_source());
        debug!("rootfs: {}, shell: {}", rootfs, self.shell);

        // Generate unique script name in rootfs
        let script_name = format!("provision-{}.sh", uuid::Uuid::new_v4());
        let target_script = rootfs.join("tmp").join(&script_name);

        // Copy or write script to rootfs
        if let Some(script_path) = &self.script {
            // External script: copy to rootfs
            info!("copying script from {} to rootfs", script_path);
            fs::copy(script_path, &target_script).with_context(|| {
                format!("failed to copy script {} to {}", script_path, target_script)
            })?;
        } else if let Some(content) = &self.content {
            // Inline script: write to rootfs
            info!("writing inline script to rootfs");
            fs::write(&target_script, content)
                .with_context(|| format!("failed to write inline script to {}", target_script))?;
        }

        // Make script executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&target_script)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&target_script, perms)
                .context("failed to set execute permission on script")?;
        }

        // Execute script in chroot
        let script_path_in_chroot = format!("/tmp/{}", script_name);
        let args: Vec<OsString> = vec![
            rootfs.as_str().into(),
            self.shell.clone().into(),
            script_path_in_chroot.into(),
        ];

        executor
            .execute("chroot", &args)
            .context("failed to execute provisioning script in chroot")?;

        // Cleanup: remove script from rootfs
        info!("cleaning up provisioning script");
        fs::remove_file(&target_script).context("failed to remove provisioning script")?;

        info!("shell provisioner completed successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_no_script_or_content() {
        let provisioner = ShellProvisioner {
            script: None,
            content: None,
            shell: default_shell(),
        };
        assert!(provisioner.validate().is_err());
    }

    #[test]
    fn test_validate_both_script_and_content() {
        let provisioner = ShellProvisioner {
            script: Some("test.sh".into()),
            content: Some("echo test".to_string()),
            shell: default_shell(),
        };
        assert!(provisioner.validate().is_err());
    }

    #[test]
    fn test_validate_script_only() {
        let provisioner = ShellProvisioner {
            script: Some("test.sh".into()),
            content: None,
            shell: default_shell(),
        };
        assert!(provisioner.validate().is_ok());
    }

    #[test]
    fn test_validate_content_only() {
        let provisioner = ShellProvisioner {
            script: None,
            content: Some("echo test".to_string()),
            shell: default_shell(),
        };
        assert!(provisioner.validate().is_ok());
    }

    #[test]
    fn test_script_source_external() {
        let provisioner = ShellProvisioner {
            script: Some("test.sh".into()),
            content: None,
            shell: default_shell(),
        };
        assert_eq!(provisioner.script_source(), "test.sh");
    }

    #[test]
    fn test_script_source_inline() {
        let provisioner = ShellProvisioner {
            script: None,
            content: Some("echo test".to_string()),
            shell: default_shell(),
        };
        assert_eq!(provisioner.script_source(), "<inline>");
    }
}
