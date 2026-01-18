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
    pub fn validate(&self) -> Result<()> {
        match (&self.script, &self.content) {
            (Some(_), None) | (None, Some(_)) => Ok(()),
            (Some(_), Some(_)) => {
                bail!("shell provisioner cannot specify both 'script' and 'content'")
            }
            (None, None) => bail!("shell provisioner must specify either 'script' or 'content'"),
        }
    }

    /// Returns the script source for logging purposes.
    pub fn script_source(&self) -> &str {
        self.script.as_ref().map_or("<inline>", |p| p.as_str())
    }

    /// Validates that the rootfs is ready for chroot operations.
    fn validate_rootfs(&self, rootfs: &Utf8Path) -> Result<()> {
        // Check if /tmp directory exists and is a real directory (not a symlink)
        let tmp_dir = rootfs.join("tmp");
        if !tmp_dir.is_dir() {
            bail!(
                "rootfs does not have a /tmp directory: {}. \
                The rootfs may not be properly bootstrapped.",
                rootfs
            );
        }

        // Prevent symlink attacks: ensure /tmp is not a symlink
        let metadata =
            std::fs::symlink_metadata(&tmp_dir).context("failed to read /tmp metadata")?;
        if metadata.file_type().is_symlink() {
            bail!(
                "/tmp in rootfs is a symlink, which is not allowed for security reasons. \
                An attacker could use this to write files outside the chroot."
            );
        }

        // Validate shell path to prevent path traversal attacks
        let shell_path = self.shell.trim_start_matches('/');
        if camino::Utf8Path::new(shell_path)
            .components()
            .any(|c| c == camino::Utf8Component::ParentDir)
        {
            bail!(
                "shell path '{}' contains '..' components, \
                which is not allowed for security reasons",
                self.shell
            );
        }

        // Check if the specified shell exists and is a file in rootfs
        let shell_in_rootfs = rootfs.join(shell_path);
        if !shell_in_rootfs.is_file() {
            if shell_in_rootfs.is_dir() {
                bail!(
                    "shell path '{}' points to a directory, not a file: {}",
                    self.shell,
                    shell_in_rootfs
                );
            } else {
                bail!(
                    "shell '{}' does not exist or is not a file in rootfs at {}",
                    self.shell,
                    shell_in_rootfs
                );
            }
        }

        Ok(())
    }
}

/// RAII guard to ensure script cleanup even on error
struct ScriptGuard {
    path: Utf8PathBuf,
    dry_run: bool,
}

impl ScriptGuard {
    fn new(path: Utf8PathBuf, dry_run: bool) -> Self {
        Self { path, dry_run }
    }
}

impl Drop for ScriptGuard {
    fn drop(&mut self) {
        if !self.dry_run && self.path.exists() {
            if let Err(e) = fs::remove_file(&self.path) {
                tracing::warn!("failed to cleanup script {}: {}", self.path, e);
            } else {
                tracing::debug!("cleaned up script: {}", self.path);
            }
        }
    }
}

impl Provisioner for ShellProvisioner {
    fn provision(
        &self,
        rootfs: &Utf8Path,
        executor: &dyn CommandExecutor,
        dry_run: bool,
    ) -> Result<()> {
        self.validate()
            .context("shell provisioner validation failed")?;

        if !dry_run {
            self.validate_rootfs(rootfs)
                .context("rootfs validation failed")?;
        }

        info!("running shell provisioner: {}", self.script_source());
        debug!("rootfs: {}, shell: {}, dry_run: {}", rootfs, self.shell, dry_run);

        // Generate unique script name in rootfs
        let script_name = format!("provision-{}.sh", uuid::Uuid::new_v4());
        let target_script = rootfs.join("tmp").join(&script_name);

        // RAII guard ensures cleanup even on error
        let _guard = ScriptGuard::new(target_script.clone(), dry_run);

        if !dry_run {
            // Copy or write script to rootfs
            match (&self.script, &self.content) {
                (Some(script_path), None) => {
                    // External script: copy to rootfs
                    info!("copying script from {} to rootfs", script_path);
                    fs::copy(script_path, &target_script).with_context(|| {
                        format!("failed to copy script {} to {}", script_path, target_script)
                    })?;
                }
                (None, Some(content)) => {
                    // Inline script: write to rootfs
                    info!("writing inline script to rootfs");
                    fs::write(&target_script, content).with_context(|| {
                        format!("failed to write inline script to {}", target_script)
                    })?;
                }
                _ => unreachable!(
                    "validate() ensures exactly one of 'script' or 'content' is specified"
                ),
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

        info!("shell provisioner completed successfully");
        Ok(())
    }
}
