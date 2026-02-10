//! Direct execution without isolation.
//!
//! This module provides a "no-op" isolation backend that executes commands
//! directly on the host filesystem, translating absolute paths to be relative
//! to the rootfs directory. Used when a task has `isolation: false`.

use super::{IsolationContext, IsolationProvider};
use crate::executor::{CommandExecutor, CommandSpec, ExecutionResult};
use crate::privilege::PrivilegeMethod;
use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use std::ffi::OsString;
use std::sync::Arc;

/// Direct execution provider (no isolation).
///
/// Creates contexts that execute commands directly on the host filesystem,
/// translating absolute paths to be prefixed with the rootfs directory.
#[derive(Debug, Default, Clone)]
pub struct DirectProvider;

impl IsolationProvider for DirectProvider {
    fn name(&self) -> &'static str {
        "direct"
    }

    fn setup(
        &self,
        rootfs: &Utf8Path,
        executor: Arc<dyn CommandExecutor>,
        dry_run: bool,
    ) -> Result<Box<dyn IsolationContext>> {
        Ok(Box::new(DirectContext {
            rootfs: rootfs.to_owned(),
            executor,
            dry_run,
            torn_down: false,
        }))
    }
}

/// Active direct execution context (no isolation).
///
/// Translates absolute command paths to be relative to the rootfs directory.
/// For example, `/bin/sh` becomes `<rootfs>/bin/sh`.
pub struct DirectContext {
    rootfs: Utf8PathBuf,
    executor: Arc<dyn CommandExecutor>,
    dry_run: bool,
    torn_down: bool,
}

impl IsolationContext for DirectContext {
    fn name(&self) -> &'static str {
        "direct"
    }

    fn rootfs(&self) -> &Utf8Path {
        &self.rootfs
    }

    fn dry_run(&self) -> bool {
        self.dry_run
    }

    /// Executes a command directly on the host filesystem.
    ///
    /// All arguments that start with '/' are translated to rootfs-prefixed paths.
    /// For example, `/bin/sh` becomes `<rootfs>/bin/sh` and `/tmp/task.sh` becomes
    /// `<rootfs>/tmp/task.sh`. This matches the current usage pattern where tasks
    /// pass isolation-relative absolute paths (e.g., shell path, script path) as
    /// arguments to the isolation context.
    fn execute(
        &self,
        command: &[OsString],
        privilege: Option<PrivilegeMethod>,
    ) -> Result<ExecutionResult> {
        if self.torn_down {
            return Err(crate::error::RsdebstrapError::Isolation(
                "cannot execute command: direct context has already been torn down".to_string(),
            )
            .into());
        }

        // Translate absolute paths to rootfs-prefixed paths
        let translated: Vec<OsString> = command
            .iter()
            .map(|arg| {
                let s = arg.to_string_lossy();
                if s.starts_with('/') {
                    OsString::from(self.rootfs.join(s.trim_start_matches('/')).as_str())
                } else {
                    arg.clone()
                }
            })
            .collect();

        let spec =
            CommandSpec::new(translated[0].to_string_lossy().to_string(), translated[1..].to_vec())
                .with_privilege(privilege);
        self.executor.execute(&spec)
    }

    fn teardown(&mut self) -> Result<()> {
        self.torn_down = true;
        Ok(())
    }
}

impl Drop for DirectContext {
    fn drop(&mut self) {
        if !self.torn_down
            && let Err(e) = self.teardown()
        {
            tracing::warn!("direct teardown failed: {}", e);
        }
    }
}
