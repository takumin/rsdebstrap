//! Validation utilities for task configuration.
//!
//! Provides path traversal checks, file existence validation, and
//! rootfs /tmp directory verification.

use std::fs;

use anyhow::Result;
use camino::Utf8Path;

use crate::error::RsdebstrapError;

/// Validates that a path contains no `..` components.
///
/// Returns `RsdebstrapError::Validation` if any parent directory component is found.
/// The `label` parameter is used in error messages to describe the path's purpose
/// (e.g., "shell script", "mitamae binary").
pub(crate) fn validate_no_parent_dirs(path: &Utf8Path, label: &str) -> Result<(), RsdebstrapError> {
    if path
        .components()
        .any(|c| c == camino::Utf8Component::ParentDir)
    {
        return Err(RsdebstrapError::Validation(format!(
            "{} path '{}' contains '..' components, \
            which is not allowed for security reasons",
            label, path
        )));
    }
    Ok(())
}

/// Validates that a host-side file exists and is a regular file (not a symlink).
///
/// Uses `symlink_metadata` to avoid following symlinks. Returns
/// `RsdebstrapError::Io` if the file cannot be accessed, or
/// `RsdebstrapError::Validation` if the path is a symlink or not a regular file.
/// The `label` parameter is used in error messages (e.g., "shell script", "mitamae binary").
pub(crate) fn validate_host_file_exists(
    path: &Utf8Path,
    label: &str,
) -> Result<(), RsdebstrapError> {
    let metadata = fs::symlink_metadata(path).map_err(|e| {
        RsdebstrapError::io(format!("failed to read {} metadata: {}", label, path), e)
    })?;
    if metadata.is_symlink() {
        return Err(RsdebstrapError::Validation(format!(
            "{} path '{}' is a symlink, which is not allowed for security reasons",
            label, path
        )));
    }
    if !metadata.is_file() {
        return Err(RsdebstrapError::Validation(format!("{} is not a file: {}", label, path)));
    }
    Ok(())
}

/// Validates that /tmp exists as a real directory (not a symlink).
///
/// This is a security-critical check to prevent attackers from using symlinks
/// to write files outside the rootfs.
pub(crate) fn validate_tmp_directory(rootfs: &Utf8Path) -> Result<()> {
    let tmp_dir = rootfs.join("tmp");
    let metadata = match std::fs::symlink_metadata(&tmp_dir) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(RsdebstrapError::Validation(format!(
                "/tmp directory not found in rootfs at {}. \
                The rootfs may not be properly bootstrapped.",
                tmp_dir
            ))
            .into());
        }
        Err(e) => {
            return Err(RsdebstrapError::io(
                format!("failed to read /tmp metadata at {}", tmp_dir),
                e,
            )
            .into());
        }
    };

    if metadata.file_type().is_symlink() {
        return Err(RsdebstrapError::Validation(
            "/tmp in rootfs is a symlink, which is not allowed for security reasons. \
            An attacker could use this to write files outside the rootfs."
                .to_string(),
        )
        .into());
    }

    if !metadata.file_type().is_dir() {
        return Err(RsdebstrapError::Validation(format!(
            "/tmp in rootfs is not a directory: {}. \
            The rootfs may not be properly bootstrapped.",
            tmp_dir
        ))
        .into());
    }

    Ok(())
}

/// Validates that a shell path exists and is a regular file in the rootfs.
///
/// Checks for path traversal, existence, and that the shell is a regular file.
pub(crate) fn validate_shell_in_rootfs(shell: &str, rootfs: &Utf8Path) -> Result<()> {
    let shell_path = shell.trim_start_matches('/');
    validate_no_parent_dirs(camino::Utf8Path::new(shell_path), "shell")?;

    let shell_in_rootfs = rootfs.join(shell_path);
    let metadata = match fs::metadata(&shell_in_rootfs) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(RsdebstrapError::Validation(format!(
                "shell '{}' does not exist in rootfs at {}",
                shell, shell_in_rootfs
            ))
            .into());
        }
        Err(e) => {
            return Err(RsdebstrapError::io(
                format!("failed to read shell metadata for '{}' at {}", shell, shell_in_rootfs),
                e,
            )
            .into());
        }
    };

    if metadata.is_dir() {
        return Err(RsdebstrapError::Validation(format!(
            "shell path '{}' points to a directory, not a file: {}",
            shell, shell_in_rootfs
        ))
        .into());
    }

    if !metadata.is_file() {
        return Err(RsdebstrapError::Validation(format!(
            "shell '{}' is not a regular file in rootfs at {}",
            shell, shell_in_rootfs
        ))
        .into());
    }

    Ok(())
}
