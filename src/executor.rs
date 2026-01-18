use anyhow::{Context, Result};
use camino::Utf8Path;
use std::ffi::OsString;
use std::process::Command;
use which::which;

/// Trait for command execution
pub trait CommandExecutor {
    /// Execute a command with the given arguments
    fn execute(&self, command: &str, args: &[OsString]) -> Result<()>;
}

/// Real command executor that uses std::process::Command to execute actual commands
pub struct RealCommandExecutor {
    pub dry_run: bool,
}

impl CommandExecutor for RealCommandExecutor {
    fn execute(&self, command: &str, args: &[OsString]) -> Result<()> {
        if self.dry_run {
            tracing::info!("dry run: {}: {:?}", command, args);
            return Ok(());
        }

        let cmd = match which(command) {
            Ok(p) => p,
            Err(e) => {
                anyhow::bail!("command not found: {}: {}", command, e);
            }
        };
        tracing::trace!("command found: {}: {}", command, cmd.to_string_lossy());

        let mut child = match Command::new(cmd).args(args).spawn() {
            Ok(c) => c,
            Err(e) => {
                anyhow::bail!("failed to spawn command `{}` with args {:?}: {}", command, args, e);
            }
        };
        tracing::trace!("spawn command: {}: {}", command, child.id());

        let status = match child.wait() {
            Ok(c) => c,
            Err(e) => {
                anyhow::bail!("failed to wait command `{}` with args {:?}: {}", command, args, e);
            }
        };
        tracing::trace!("wait command: {}: {}", command, status.success());

        if !status.success() {
            anyhow::bail!(
                "{} exited with non-zero status: {} and args: {:?}",
                command,
                status,
                args
            );
        }

        Ok(())
    }
}

/// Chroot command executor that executes commands inside a chroot environment
///
/// This executor wraps commands to run inside a specified rootfs directory using `chroot`.
/// It validates the rootfs before execution and properly constructs chroot command arguments.
#[allow(dead_code)]
pub struct ChrootExecutor<'a> {
    /// Path to the rootfs directory where commands will be executed
    pub rootfs: &'a Utf8Path,
    /// Whether to run in dry-run mode
    pub dry_run: bool,
}

impl<'a> ChrootExecutor<'a> {
    /// Creates a new ChrootExecutor for the specified rootfs
    #[allow(dead_code)]
    pub fn new(rootfs: &'a Utf8Path, dry_run: bool) -> Self {
        Self { rootfs, dry_run }
    }

    /// Validates that the rootfs directory exists and is a directory
    #[allow(dead_code)]
    pub fn validate_rootfs(&self) -> Result<()> {
        if self.dry_run {
            return Ok(());
        }

        let metadata = std::fs::metadata(self.rootfs)
            .with_context(|| format!("failed to read rootfs metadata: {}", self.rootfs))?;

        if !metadata.is_dir() {
            anyhow::bail!("rootfs is not a directory: {}", self.rootfs);
        }

        Ok(())
    }
}

impl<'a> CommandExecutor for ChrootExecutor<'a> {
    fn execute(&self, command: &str, args: &[OsString]) -> Result<()> {
        // Validate rootfs before executing
        self.validate_rootfs()
            .context("rootfs validation failed before chroot execution")?;

        if self.dry_run {
            tracing::info!("dry run: chroot {}: {} {:?}", self.rootfs, command, args);
            return Ok(());
        }

        // Verify chroot command exists
        let chroot_cmd = which("chroot").context("chroot command not found")?;
        tracing::trace!("chroot command found: {}", chroot_cmd.to_string_lossy());

        // Build chroot arguments: chroot <rootfs> <command> <args...>
        let mut chroot_args = Vec::with_capacity(2 + args.len());
        chroot_args.push(OsString::from(self.rootfs.as_str()));
        chroot_args.push(OsString::from(command));
        chroot_args.extend_from_slice(args);

        tracing::debug!(
            "executing in chroot: rootfs={}, command={}, args={:?}",
            self.rootfs,
            command,
            args
        );

        let mut child = Command::new(chroot_cmd)
            .args(&chroot_args)
            .spawn()
            .with_context(|| {
                format!(
                    "failed to spawn chroot command for `{}` in rootfs `{}`",
                    command, self.rootfs
                )
            })?;

        tracing::trace!("spawned chroot process: pid={}", child.id());

        let status = child.wait().with_context(|| {
            format!("failed to wait for chroot command `{}` in rootfs `{}`", command, self.rootfs)
        })?;

        tracing::trace!("chroot process exited: success={}", status.success());

        if !status.success() {
            anyhow::bail!(
                "command `{}` in chroot {} exited with non-zero status: {}",
                command,
                self.rootfs,
                status
            );
        }

        Ok(())
    }
}
