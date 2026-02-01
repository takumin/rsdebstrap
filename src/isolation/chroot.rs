//! Chroot isolation implementation.

use super::Isolation;
use crate::executor::{CommandExecutor, CommandSpec, ExecutionResult};
use anyhow::Result;
use camino::Utf8Path;
use std::ffi::OsString;

/// Chroot-based isolation backend.
///
/// This is the simplest isolation mechanism, using the standard `chroot` command
/// to change the root directory before executing commands.
#[derive(Debug, Default, Clone)]
pub struct ChrootIsolation;

impl Isolation for ChrootIsolation {
    fn name(&self) -> &'static str {
        "chroot"
    }

    fn execute(
        &self,
        rootfs: &Utf8Path,
        command: &[OsString],
        executor: &dyn CommandExecutor,
    ) -> Result<ExecutionResult> {
        let mut args: Vec<OsString> = Vec::with_capacity(command.len() + 1);
        args.push(rootfs.as_str().into());
        args.extend(command.iter().cloned());

        let spec = CommandSpec::new("chroot", args);
        executor.execute(&spec)
    }
}
