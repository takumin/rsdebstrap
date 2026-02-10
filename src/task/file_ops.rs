//! File operation utilities for task execution.
//!
//! Provides RAII temporary file cleanup, file copying/writing with
//! permission management, and TOCTOU-mitigated file preparation.

use std::fs;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use tracing::info;

use super::ScriptSource;
use super::validation::validate_tmp_directory;

/// RAII guard to ensure temporary file cleanup even on error.
pub(crate) struct TempFileGuard {
    path: Utf8PathBuf,
    dry_run: bool,
}

impl TempFileGuard {
    pub(crate) fn new(path: Utf8PathBuf, dry_run: bool) -> Self {
        Self { path, dry_run }
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if !self.dry_run {
            match fs::remove_file(&self.path) {
                Ok(()) => tracing::debug!("cleaned up temp file: {}", self.path),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    tracing::debug!("temp file already removed: {}", self.path);
                }
                Err(e) => {
                    tracing::error!(
                        path = %self.path,
                        error_kind = ?e.kind(),
                        "failed to cleanup temp file: {}",
                        e,
                    );
                }
            }
        }
    }
}

/// Sets Unix file permissions on the given path.
#[cfg(unix)]
pub(crate) fn set_file_mode(path: &Utf8Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path))?
        .permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)
        .with_context(|| format!("failed to set permissions on {}", path))?;
    Ok(())
}

/// Copies or writes a script source to the target path and sets permissions.
///
/// On Unix systems, sets the file mode to the specified `mode`.
/// On other platforms, the permission step is skipped.
pub(crate) fn prepare_source_file(
    source: &ScriptSource,
    target: &Utf8Path,
    mode: u32,
    label: &str,
) -> Result<()> {
    match source {
        ScriptSource::Script(src_path) => {
            info!("copying {} from {} to rootfs", label, src_path);
            fs::copy(src_path, target)
                .with_context(|| format!("failed to copy {} {} to {}", label, src_path, target))?;
        }
        ScriptSource::Content(content) => {
            info!("writing inline {} to rootfs", label);
            fs::write(target, content)
                .with_context(|| format!("failed to write inline {} to {}", label, target))?;
        }
    }
    #[cfg(unix)]
    set_file_mode(target, mode)?;
    Ok(())
}

/// Re-validates `/tmp` (TOCTOU mitigation) and runs the file preparation closure.
///
/// In dry-run mode, skips both validation and file preparation entirely.
pub(crate) fn prepare_files_with_toctou_check(
    rootfs: &Utf8Path,
    dry_run: bool,
    prepare_fn: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if !dry_run {
        validate_tmp_directory(rootfs)
            .context("TOCTOU check: /tmp validation failed before writing files")?;
        prepare_fn()?;
    }
    Ok(())
}
