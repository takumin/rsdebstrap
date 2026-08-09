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
use rustix::fs::{self as rfs, FileType, Mode, OFlags};
use std::os::fd::OwnedFd;
use std::sync::Arc;

/// Walks `program` inside `rootfs` with `O_NOFOLLOW`, refusing a symlink at any component,
/// and returns the descriptor it ends on.
///
/// The descriptor is the point. The kernel resolves a program path when it execs, so a
/// check that ends with a path lets the name be repointed in between — including at a
/// component that leaves the rootfs. The executor names this descriptor instead, and what
/// runs is the inode the walk landed on.
fn open_program_in_rootfs(rootfs: &Utf8Path, program: &str) -> Result<OwnedFd> {
    let path = RelPath::parse(program)?;
    // The anchor is walked the same way the rest of the path is, and by the same code: a
    // whole-path `openat` would follow an intermediate symlink and start this walk outside
    // the rootfs, which is the one thing every component below is checked for.
    let mut dir = crate::rootfs::open_anchor(rootfs)?;

    let components = path.components();
    let (last, parents) = components.split_last().expect("RelPath is never empty");
    for (depth, component) in parents.iter().enumerate() {
        dir = rfs::openat(
            &dir,
            component.as_str(),
            OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        // The components walked so far, not just this one: `<rootfs>/usr/bin` names the
        // entry that failed when `/usr/bin/env` is refused, while `<rootfs>/bin` names
        // something else entirely, or nothing.
        .map_err(|e| {
            let so_far = components[..=depth].join("/");
            symlink_error(e, &format!("{}/{}", rootfs, so_far))
        })?;
    }
    // `O_PATH` because an executable need not be readable, and this descriptor is only
    // ever named, never read. It also opens a symlink as the *link itself* rather than
    // failing, so whether the final component is one is decided by `fstat` below rather
    // than by the open.
    let program = rfs::openat(&dir, last.as_str(), OFlags::PATH | OFlags::NOFOLLOW, Mode::empty())
        .map_err(|e| symlink_error(e, &format!("{}{}", rootfs, path)))?;
    let stat =
        rfs::fstat(&program).map_err(|e| symlink_error(e, &format!("{}{}", rootfs, path)))?;
    if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink {
        return Err(symlink_error(rustix::io::Errno::LOOP, &format!("{}{}", rootfs, path)));
    }

    // The executor execs this descriptor by naming it `/proc/self/fd/N`, which is the only
    // way to exec an inode rather than a path here. Said now, against a path the caller
    // wrote, rather than as an `ENOENT` out of `spawn` naming a path they did not.
    if !std::path::Path::new("/proc/self/fd").is_dir() {
        return Err(crate::error::RsdebstrapError::Isolation(
            "cannot execute a task without isolation: /proc is not mounted, and the \
            verified program can only be executed by naming its descriptor under \
            /proc/self/fd"
                .to_string(),
        )
        .into());
    }

    Ok(program)
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
    ) -> Result<Box<dyn IsolationContext>> {
        Ok(Box::new(DirectContext {
            rootfs: rootfs.to_owned(),
            executor,
            ops,
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
    torn_down: bool,
}

impl RootfsContext for DirectContext {
    fn rootfs(&self) -> &Utf8Path {
        &self.rootfs
    }

    fn dry_run(&self) -> bool {
        self.executor.dry_run()
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

        // The translation above is a string join, and the kernel resolves the program —
        // the one argument it resolves on our behalf — when it execs. So the program is
        // walked component by component with `O_NOFOLLOW` and handed to the executor as
        // the descriptor that walk ended on, which the spec then owns for as long as the
        // execution takes. A relative program is left to `PATH` resolution, as before:
        // it names nothing inside the rootfs to check.
        let token = super::TaskCommandToken::new();
        let spec = if self.executor.dry_run() || !Utf8Path::new(&command[0]).is_absolute() {
            CommandSpec::for_task_command(&token, &translated, privilege)?
        } else {
            let program = open_program_in_rootfs(&self.rootfs, &command[0])?;
            match privilege {
                // `sudo` and `doas` close the descriptors they inherit, so the checked one
                // cannot reach the program through them and the path is all that is left.
                // A task that escalates without isolation is rejected when it is resolved,
                // so what stands here is the walk above, same as before descriptors.
                Some(_) => CommandSpec::for_task_command(&token, &translated, privilege)?,
                None => CommandSpec::for_verified_program(&token, program, &translated)?,
            }
        };
        self.executor.execute(&spec)
    }

    fn teardown(&mut self) -> Result<()> {
        self.torn_down = true;
        Ok(())
    }
}

impl std::fmt::Debug for DirectContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectContext")
            .field("rootfs", &self.rootfs)
            .field("torn_down", &self.torn_down)
            .finish_non_exhaustive()
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
