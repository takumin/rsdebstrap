//! Shell task implementation.
//!
//! This module provides the `ShellTask` data structure and execution logic
//! for running shell scripts within an isolation context. It handles:
//! - Script source management (external files or inline content)
//! - Security validation (path traversal, symlink attacks, TOCTOU mitigation)
//! - Script lifecycle (copy/write to rootfs, execute, cleanup via RAII guard)

use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use serde::Deserialize;
use serde::de::{self, MapAccess, Visitor};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use tracing::{debug, info};

use crate::isolation::IsolationContext;

/// Script source for shell execution.
///
/// Represents exactly one of `script` (external file) or `content` (inline).
/// When deserialized via `ShellTask`'s custom `Deserialize` impl, mutual
/// exclusivity is validated at parse time — specifying both or neither
/// produces a descriptive error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptSource {
    /// External shell script file path
    Script(Utf8PathBuf),
    /// Inline shell script content
    Content(String),
}

/// Shell task data and execution logic.
///
/// Represents a shell script to be executed within an isolation context.
/// Holds configuration data and provides methods for validation and execution.
/// Used as a variant in the `TaskDefinition` enum for compile-time dispatch.
///
/// Deserialization validates that exactly one of `script` or `content` is
/// specified, rejecting YAML that provides both or neither.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellTask {
    /// Script source: either an external file path or inline content
    source: ScriptSource,

    /// Shell interpreter to use (default: /bin/sh)
    shell: String,
}

fn default_shell() -> String {
    "/bin/sh".to_string()
}

impl<'de> Deserialize<'de> for ShellTask {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Script,
            Content,
            Shell,
        }

        struct ShellTaskVisitor;

        impl<'de> Visitor<'de> for ShellTaskVisitor {
            type Value = ShellTask;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a shell task with either 'script' or 'content'")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<ShellTask, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut script: Option<Utf8PathBuf> = None;
                let mut content: Option<String> = None;
                let mut shell: Option<String> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Script => {
                            if script.is_some() {
                                return Err(de::Error::duplicate_field("script"));
                            }
                            script = Some(map.next_value()?);
                        }
                        Field::Content => {
                            if content.is_some() {
                                return Err(de::Error::duplicate_field("content"));
                            }
                            content = Some(map.next_value()?);
                        }
                        Field::Shell => {
                            if shell.is_some() {
                                return Err(de::Error::duplicate_field("shell"));
                            }
                            shell = Some(map.next_value()?);
                        }
                    }
                }

                let source = match (script, content) {
                    (Some(_), Some(_)) => {
                        return Err(de::Error::custom(
                            "'script' and 'content' are mutually exclusive",
                        ));
                    }
                    (None, None) => {
                        return Err(de::Error::custom(
                            "either 'script' or 'content' must be specified",
                        ));
                    }
                    (Some(s), None) => ScriptSource::Script(s),
                    (None, Some(c)) => ScriptSource::Content(c),
                };

                Ok(ShellTask {
                    source,
                    shell: shell.unwrap_or_else(default_shell),
                })
            }
        }

        const FIELDS: &[&str] = &["script", "content", "shell"];
        deserializer.deserialize_struct("ShellTask", FIELDS, ShellTaskVisitor)
    }
}

impl ShellTask {
    /// Creates a new ShellTask with the given script source and default shell (/bin/sh).
    pub fn new(source: ScriptSource) -> Self {
        Self {
            source,
            shell: default_shell(),
        }
    }

    /// Creates a new ShellTask with the given script source and custom shell.
    pub fn with_shell(source: ScriptSource, shell: impl Into<String>) -> Self {
        Self {
            source,
            shell: shell.into(),
        }
    }

    /// Returns a reference to the script source.
    pub fn source(&self) -> &ScriptSource {
        &self.source
    }

    /// Returns the shell interpreter path.
    pub fn shell(&self) -> &str {
        &self.shell
    }

    /// Returns a human-readable name for this task.
    pub fn name(&self) -> &str {
        match &self.source {
            ScriptSource::Script(path) => path.as_str(),
            ScriptSource::Content(_) => "<inline>",
        }
    }

    /// Returns the script path if this task uses an external script file.
    pub fn script_path(&self) -> Option<&Utf8PathBuf> {
        match &self.source {
            ScriptSource::Script(path) => Some(path),
            ScriptSource::Content(_) => None,
        }
    }

    /// Resolves relative paths in this task relative to the given base directory.
    pub fn resolve_paths(&mut self, base_dir: &Utf8Path) {
        if let ScriptSource::Script(path) = &mut self.source
            && path.is_relative()
        {
            *path = base_dir.join(path.as_path());
        }
    }

    /// Validates the task configuration.
    ///
    /// For external script files, validates that the file exists and is a regular file.
    /// For inline content, validates that the content is not empty.
    pub fn validate(&self) -> Result<()> {
        if self.shell.is_empty() {
            bail!("shell path must not be empty");
        }
        if !self.shell.starts_with('/') {
            bail!("shell path must be absolute (start with '/'): {}", self.shell);
        }

        match &self.source {
            ScriptSource::Script(script) => {
                // Prevent path traversal attacks
                if camino::Utf8Path::new(script.as_str())
                    .components()
                    .any(|c| c == camino::Utf8Component::ParentDir)
                {
                    bail!(
                        "script path '{}' contains '..' components, \
                        which is not allowed for security reasons",
                        script
                    );
                }

                let metadata = fs::metadata(script)
                    .with_context(|| format!("failed to read shell script metadata: {}", script))?;
                if !metadata.is_file() {
                    bail!("shell script is not a file: {}", script);
                }
                Ok(())
            }
            ScriptSource::Content(content) => {
                if content.trim().is_empty() {
                    bail!("inline script content must not be empty");
                }
                Ok(())
            }
        }
    }

    /// Executes the shell script using the provided isolation context.
    ///
    /// This method:
    /// 1. Validates the rootfs (unless dry_run)
    /// 2. Copies or writes the script to rootfs /tmp
    /// 3. Executes the script via the isolation context
    /// 4. Cleans up the script file (via RAII guard)
    pub fn execute(&self, context: &dyn IsolationContext) -> Result<()> {
        let rootfs = context.rootfs();
        let dry_run = context.dry_run();

        if !dry_run {
            self.validate_rootfs(rootfs)
                .context("rootfs validation failed")?;
        }

        info!("running shell script: {} (isolation: {})", self.name(), context.name());
        debug!("rootfs: {}, shell: {}, dry_run: {}", rootfs, self.shell, dry_run);

        // Generate unique script name in rootfs
        let script_name = format!("task-{}.sh", uuid::Uuid::new_v4());
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
                let mut perms = fs::metadata(&target_script)
                    .with_context(|| {
                        format!("failed to read metadata for script {}", target_script)
                    })?
                    .permissions();
                perms.set_mode(0o700);
                fs::set_permissions(&target_script, perms).with_context(|| {
                    format!("failed to set execute permission on script {}", target_script)
                })?;
            }
        }

        // Execute script using the configured isolation backend
        let script_path_in_chroot = format!("/tmp/{}", script_name);
        let command: Vec<OsString> = vec![self.shell.as_str().into(), script_path_in_chroot.into()];

        let result = context
            .execute(&command)
            .context("failed to execute script")?;

        if !result.success() {
            let status_display = result
                .status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown (no status available)".to_string());
            anyhow::bail!(
                "script with command `{:?}` \
                failed in isolation backend '{}' with status: {}",
                command,
                context.name(),
                status_display
            );
        }

        info!("shell script completed successfully");
        Ok(())
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
                return Err(e)
                    .with_context(|| format!("failed to read /tmp metadata at {}", tmp_dir));
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
        let metadata = match fs::metadata(&shell_in_rootfs) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                bail!("shell '{}' does not exist in rootfs at {}", self.shell, shell_in_rootfs);
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "failed to read shell metadata for '{}' at {}",
                        self.shell, shell_in_rootfs
                    )
                });
            }
        };

        if metadata.is_dir() {
            bail!(
                "shell path '{}' points to a directory, not a file: {}",
                self.shell,
                shell_in_rootfs
            );
        }

        if !metadata.is_file() {
            bail!("shell '{}' is not a regular file in rootfs at {}", self.shell, shell_in_rootfs);
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
        if !self.dry_run {
            match fs::remove_file(&self.path) {
                Ok(()) => tracing::debug!("cleaned up script: {}", self.path),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    tracing::debug!("script already removed: {}", self.path);
                }
                Err(e) => {
                    tracing::error!("failed to cleanup script {}: {}", self.path, e);
                }
            }
        }
    }
}
