//! Direct execution without isolation.
//!
//! This module provides a "no-op" isolation backend that executes commands
//! directly on the host filesystem, translating absolute paths to be relative
//! to the rootfs directory. Used when a task has `isolation: false`.

use super::{IsolationContext, IsolationProvider, RootfsContext};
use crate::executor::{CommandExecutor, CommandSpec, ExecutionResult};
use crate::privilege::PrivilegeMethod;
use crate::rootfs::{RelPath, RootfsOps};
use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use rustix::fs::{self as rfs, AtFlags, CWD, FileType, Mode, OFlags};
use std::sync::Arc;

/// Walks `program` inside `rootfs` with `O_NOFOLLOW`, refusing a symlink at any component.
///
/// The caller hands the joined path to the executor, and the kernel resolves it when it
/// execs — following any symlink in it, including one that leaves the rootfs. This is what
/// makes that an error instead.
fn verify_program_stays_in_rootfs(rootfs: &Utf8Path, program: &str) -> Result<()> {
    let path = RelPath::parse(program)?;
    let mut dir = rfs::openat(
        CWD,
        rootfs.as_str(),
        OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| symlink_error(e, rootfs.as_str()))?;

    let components = path.components();
    let (last, parents) = components.split_last().expect("RelPath is never empty");
    for component in parents {
        dir = rfs::openat(
            &dir,
            component.as_str(),
            OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| symlink_error(e, &format!("{}/{}", rootfs, component)))?;
    }
    // `statat` rather than an `openat`: `O_NOFOLLOW | O_PATH` opens the *link itself* and
    // succeeds, and a plain `O_NOFOLLOW` open needs read permission the program may not
    // grant. What matters is only whether the final component is a symlink.
    let stat = rfs::statat(&dir, last.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| symlink_error(e, &format!("{}{}", rootfs, path)))?;
    if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink {
        return Err(symlink_error(rustix::io::Errno::LOOP, &format!("{}{}", rootfs, path)));
    }
    Ok(())
}

fn symlink_error(e: rustix::io::Errno, what: &str) -> anyhow::Error {
    match e {
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => {
            crate::error::RsdebstrapError::Isolation(format!(
                "{} is a symlink or not a directory; refusing to run it without isolation, \
                because the kernel would resolve it and could leave the rootfs",
                what
            ))
            .into()
        }
        _ => crate::error::RsdebstrapError::io(
            format!("failed to open {}", what),
            std::io::Error::from(e),
        )
        .into(),
    }
}

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
        ops: Arc<dyn RootfsOps>,
        dry_run: bool,
    ) -> Result<Box<dyn IsolationContext>> {
        Ok(Box::new(DirectContext {
            rootfs: rootfs.to_owned(),
            executor,
            ops,
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
    ops: Arc<dyn RootfsOps>,
    dry_run: bool,
    torn_down: bool,
}

impl RootfsContext for DirectContext {
    fn rootfs(&self) -> &Utf8Path {
        &self.rootfs
    }

    fn dry_run(&self) -> bool {
        self.dry_run
    }

    fn rootfs_ops(&self) -> &dyn RootfsOps {
        &*self.ops
    }
}

impl IsolationContext for DirectContext {
    fn name(&self) -> &'static str {
        "direct"
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
        command: &[String],
        privilege: Option<PrivilegeMethod>,
    ) -> Result<ExecutionResult> {
        if self.torn_down {
            return Err(crate::error::RsdebstrapError::Isolation(
                "cannot execute command: direct context has already been torn down".to_string(),
            )
            .into());
        }

        if command.is_empty() {
            return Err(crate::error::RsdebstrapError::Isolation(
                "cannot execute command: empty command provided".to_string(),
            )
            .into());
        }

        let translated: Vec<String> = command
            .iter()
            .map(|arg| {
                let path = Utf8Path::new(arg);
                if path.is_absolute() {
                    match path.strip_prefix("/") {
                        Ok(relative) => self.rootfs.join(relative).to_string(),
                        Err(_) => arg.clone(),
                    }
                } else {
                    arg.clone()
                }
            })
            .collect();

        // The translation above is a string join, and the kernel resolves symlinks when it
        // execs. A rootfs whose `/bin/sh` is a symlink pointing out of the rootfs would
        // therefore run a host binary. Verify the program — and only the program, since it
        // is the one argument the kernel resolves on our behalf — component by component
        // with `O_NOFOLLOW`.
        if !self.dry_run && Utf8Path::new(&command[0]).is_absolute() {
            verify_program_stays_in_rootfs(&self.rootfs, &command[0])?;
        }

        let spec =
            CommandSpec::for_task_command(&super::TaskCommandToken::new(), &translated, privilege)?;
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
