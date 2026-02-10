//! Chroot isolation implementation.

use super::{IsolationContext, IsolationProvider};
use crate::executor::{CommandExecutor, CommandSpec, ExecutionResult};
use crate::privilege::PrivilegeMethod;
use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use std::sync::Arc;

/// Chroot-based isolation provider.
///
/// This is the simplest isolation mechanism, using the standard `chroot` command
/// to change the root directory before executing commands.
///
/// Chroot doesn't require any special setup or teardown operations,
/// making it a lightweight option for pipeline task execution.
#[derive(Debug, Default, Clone)]
pub struct ChrootProvider;

impl IsolationProvider for ChrootProvider {
    fn name(&self) -> &'static str {
        "chroot"
    }

    fn setup(
        &self,
        rootfs: &Utf8Path,
        executor: Arc<dyn CommandExecutor>,
        dry_run: bool,
    ) -> Result<Box<dyn IsolationContext>> {
        Ok(Box::new(ChrootContext {
            rootfs: rootfs.to_owned(),
            executor,
            dry_run,
            torn_down: false,
        }))
    }
}

/// Active chroot isolation context.
///
/// Holds the state for an active chroot session. For chroot, this is minimal
/// since chroot doesn't require any persistent state between commands.
pub struct ChrootContext {
    rootfs: Utf8PathBuf,
    executor: Arc<dyn CommandExecutor>,
    dry_run: bool,
    torn_down: bool,
}

impl IsolationContext for ChrootContext {
    fn name(&self) -> &'static str {
        "chroot"
    }

    fn rootfs(&self) -> &Utf8Path {
        &self.rootfs
    }

    fn dry_run(&self) -> bool {
        self.dry_run
    }

    fn execute(
        &self,
        command: &[String],
        privilege: Option<PrivilegeMethod>,
    ) -> Result<ExecutionResult> {
        super::check_not_torn_down(self.torn_down, "chroot")?;

        let mut args: Vec<String> = Vec::with_capacity(command.len() + 1);
        args.push(self.rootfs.to_string());
        args.extend(command.iter().cloned());

        let spec = CommandSpec::new("chroot", args).with_privilege(privilege);
        self.executor.execute(&spec)
    }

    fn teardown(&mut self) -> Result<()> {
        // Chroot doesn't need any cleanup
        self.torn_down = true;
        Ok(())
    }
}

impl Drop for ChrootContext {
    fn drop(&mut self) {
        if !self.torn_down {
            // Best effort teardown - log warning on failure
            if let Err(e) = self.teardown() {
                tracing::warn!("chroot teardown failed: {}", e);
            }
        }
    }
}
