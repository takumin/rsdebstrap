//! Shell provisioner implementation.

use super::Provisioner;
use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use serde::Deserialize;
use std::ffi::OsString;
use std::fs;
use tracing::{debug, info};

use crate::isolation::IsolationContext;

/// Script source for shell provisioner.
///
/// This enum enforces at the type level that exactly one of `script` or `content`
/// must be specified, eliminating the need for runtime validation of mutual exclusivity.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptSource {
    /// External shell script file path
    Script(Utf8PathBuf),
    /// Inline shell script content
    Content(String),
}

/// Shell provisioner configuration.
///
/// Executes shell scripts inside the bootstrapped rootfs using chroot.
/// The script source is specified via the `source` field, which must be either
/// `script` (external file) or `content` (inline script).
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct ShellProvisioner {
    /// Script source: either an external file path or inline content
    #[serde(flatten)]
    pub source: ScriptSource,

    /// Shell interpreter to use (default: /bin/sh)
    #[serde(default = "default_shell")]
    pub shell: String,
}

fn default_shell() -> String {
    "/bin/sh".to_string()
}

impl ShellProvisioner {
    /// Validates the shell provisioner configuration.
    ///
    /// For external script files, validates that the file exists and is a regular file.
    /// For inline content, no additional validation is needed (type system ensures it's present).
    pub fn validate(&self) -> Result<()> {
        match &self.source {
            ScriptSource::Script(script) => {
                let metadata = fs::metadata(script).with_context(|| {
                    format!("failed to read shell provisioner script metadata: {}", script)
                })?;
                if !metadata.is_file() {
                    bail!("shell provisioner script is not a file: {}", script);
                }
                Ok(())
            }
            ScriptSource::Content(_) => Ok(()),
        }
    }

    /// Returns the script source for logging purposes.
    pub fn script_source(&self) -> &str {
        match &self.source {
            ScriptSource::Script(path) => path.as_str(),
            ScriptSource::Content(_) => "<inline>",
        }
    }

    /// Returns the script path if this provisioner uses an external script file.
    pub fn script_path(&self) -> Option<&Utf8PathBuf> {
        match &self.source {
            ScriptSource::Script(path) => Some(path),
            ScriptSource::Content(_) => None,
        }
    }

    /// Returns a mutable reference to the script path if this provisioner uses an
    /// external script file.
    pub fn script_path_mut(&mut self) -> Option<&mut Utf8PathBuf> {
        match &mut self.source {
            ScriptSource::Script(path) => Some(path),
            ScriptSource::Content(_) => None,
        }
    }

    /// Validates that /tmp exists as a real directory (not a symlink).
    ///
    /// This is a security-critical check to prevent attackers from using symlinks
    /// to write files outside the chroot.
    fn validate_tmp_directory(rootfs: &Utf8Path) -> Result<()> {
        let tmp_dir = rootfs.join("tmp");
        let metadata = match std::fs::symlink_metadata(&tmp_dir) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                bail!(
                    "/tmp directory not found in rootfs at {}. \
                    The rootfs may not be properly bootstrapped.",
                    tmp_dir
                );
            }
            Err(e) => {
                return Err(e).context("failed to read /tmp metadata");
            }
        };

        if metadata.file_type().is_symlink() {
            bail!(
                "/tmp in rootfs is a symlink, which is not allowed for security reasons. \
                An attacker could use this to write files outside the chroot."
            );
        }

        if !metadata.file_type().is_dir() {
            bail!(
                "/tmp in rootfs is not a directory: {}. \
                The rootfs may not be properly bootstrapped.",
                tmp_dir
            );
        }

        Ok(())
    }

    /// Validates that the rootfs is ready for chroot operations.
    fn validate_rootfs(&self, rootfs: &Utf8Path) -> Result<()> {
        // Check if /tmp directory exists and is a real directory (not a symlink)
        Self::validate_tmp_directory(rootfs)?;

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
    fn provision(&self, context: &dyn IsolationContext, dry_run: bool) -> Result<()> {
        let rootfs = context.rootfs();

        if !dry_run {
            self.validate_rootfs(rootfs)
                .context("rootfs validation failed")?;
        }

        info!(
            "running shell provisioner: {} (isolation: {})",
            self.script_source(),
            context.name()
        );
        debug!("rootfs: {}, shell: {}, dry_run: {}", rootfs, self.shell, dry_run);

        // Generate unique script name in rootfs
        let script_name = format!("provision-{}.sh", uuid::Uuid::new_v4());
        let target_script = rootfs.join("tmp").join(&script_name);

        // RAII guard ensures cleanup even on error
        let _guard = ScriptGuard::new(target_script.clone(), dry_run);

        if !dry_run {
            // Re-validate /tmp immediately before use to mitigate TOCTOU race conditions
            Self::validate_tmp_directory(rootfs)
                .context("TOCTOU check: /tmp validation failed before writing script")?;

            // Copy or write script to rootfs based on source type
            match &self.source {
                ScriptSource::Script(script_path) => {
                    // External script: copy to rootfs
                    info!("copying script from {} to rootfs", script_path);
                    fs::copy(script_path, &target_script).with_context(|| {
                        format!("failed to copy script {} to {}", script_path, target_script)
                    })?;
                }
                ScriptSource::Content(content) => {
                    // Inline script: write to rootfs
                    info!("writing inline script to rootfs");
                    fs::write(&target_script, content).with_context(|| {
                        format!("failed to write inline script to {}", target_script)
                    })?;
                }
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

        // Execute script using the configured isolation backend
        let script_path_in_chroot = format!("/tmp/{}", script_name);
        let command: Vec<OsString> = vec![self.shell.as_str().into(), script_path_in_chroot.into()];

        let result = context
            .execute(&command)
            .context("failed to execute provisioning script")?;

        if !result.success() {
            anyhow::bail!(
                "provisioning script with command `{:?}` \
                failed in isolation backend '{}' with status: {}",
                command,
                context.name(),
                result.status.expect("status should be present on failure")
            );
        }

        info!("shell provisioner completed successfully");
        Ok(())
    }
}
