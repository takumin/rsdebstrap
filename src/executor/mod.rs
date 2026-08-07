//! Command execution abstraction for rsdebstrap.
//!
//! This module provides:
//! - [`CommandSpec`]: Specification for commands to execute
//! - [`ExecutionResult`]: Result of command execution
//! - [`CommandExecutor`]: Trait for command execution strategies
//! - [`RealCommandExecutor`]: Production implementation using `std::process::Command`

mod pipe;
mod real;

use std::process::ExitStatus;

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};

use crate::RsdebstrapError;
use crate::isolation::TaskCommandToken;
use crate::privilege::PrivilegeMethod;

pub use real::RealCommandExecutor;

/// Formats string arguments into a space-separated, debug-quoted string.
///
/// Used by error messages and dry-run output to consistently format
/// command arguments (e.g., `"--variant=debootstrap" "/tmp/rootfs"`).
pub(crate) fn format_command_args(args: &[String]) -> String {
    args.iter()
        .map(|a| format!("{:?}", a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A program that may run with elevated privilege.
///
/// Closed on purpose. Privilege can only reach a [`CommandSpec`] through this type, so
/// `sudo cp` to modify a rootfs is not something the code can express by accident: there
/// is no variant for it, and every variant here is a program with no syscall equivalent
/// in this crate. Rootfs *contents* are modified through
/// [`RootfsOps`](crate::rootfs::RootfsOps), which is anchored to a directory descriptor
/// rather than resolving a path string a second time under root.
///
/// Adding a variant is therefore a deliberate act with this note attached to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivilegedProgram {
    /// `mount`, for a prepare-phase mount entry.
    Mount,
    /// `umount`, releasing what [`Mount`](Self::Mount) set up.
    Umount,
    /// `chroot`, entering the rootfs to run a task inside it.
    Chroot,
    /// The bootstrap backend that builds the rootfs in the first place.
    Bootstrap(BootstrapProgram),
}

/// The bootstrap backends, as programs rather than as configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapProgram {
    Mmdebstrap,
    Debootstrap,
}

impl BootstrapProgram {
    /// The program name passed to the privilege escalation command.
    pub fn program_name(&self) -> &'static str {
        match self {
            Self::Mmdebstrap => "mmdebstrap",
            Self::Debootstrap => "debootstrap",
        }
    }
}

impl PrivilegedProgram {
    /// The program name passed to the privilege escalation command.
    pub fn program_name(&self) -> &'static str {
        match self {
            Self::Mount => "mount",
            Self::Umount => "umount",
            Self::Chroot => "chroot",
            Self::Bootstrap(backend) => backend.program_name(),
        }
    }
}

/// Specification for a command to be executed
#[derive(Debug, Clone)]
// Fields are private so `privilege` can only be set by the constructors below. A `pub`
// field would make `PrivilegedProgram` decorative: `CommandSpec { command: "cp".into(),
// privilege: Some(Sudo), .. }` would compile and bypass the whole boundary.
pub struct CommandSpec {
    command: String,
    args: Vec<String>,
    cwd: Option<Utf8PathBuf>,
    env: Vec<(String, String)>,
    privilege: Option<PrivilegeMethod>,
}

impl CommandSpec {
    /// The program to execute.
    pub fn command(&self) -> &str {
        &self.command
    }

    /// The arguments passed to it.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// The working directory, if one was set.
    pub fn cwd(&self) -> Option<&Utf8Path> {
        self.cwd.as_deref()
    }

    /// Environment variables set in addition to the inherited environment.
    pub fn env(&self) -> &[(String, String)] {
        &self.env
    }

    /// The privilege escalation method, if this spec is privileged.
    pub fn privilege(&self) -> Option<PrivilegeMethod> {
        self.privilege
    }

    /// Creates a new CommandSpec with command and args
    #[must_use]
    pub fn new(command: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            command: command.into(),
            args,
            cwd: None,
            env: Vec::new(),
            privilege: None,
        }
    }

    /// Creates a spec for one of the [`PrivilegedProgram`]s, optionally escalated.
    ///
    /// The only way to attach privilege to a fixed program. `new` produces an
    /// unprivileged spec and has no way to change that.
    #[must_use]
    pub fn privileged(
        program: PrivilegedProgram,
        args: Vec<String>,
        privilege: Option<PrivilegeMethod>,
    ) -> Self {
        Self {
            command: program.program_name().to_string(),
            args,
            cwd: None,
            env: Vec::new(),
            privilege,
        }
    }

    /// Creates a spec for the program a provision task declared, optionally escalated.
    ///
    /// Takes the task's whole argv, because that is what a task carries — a shell and its
    /// arguments, or a mitamae binary and a recipe. The program name comes from the profile,
    /// so unlike [`privileged`](Self::privileged) it cannot be an enum; the
    /// [`TaskCommandToken`] is what bounds it instead — only `isolation` can produce one, so
    /// this is unreachable from anywhere but the layer that runs a task's command.
    ///
    /// # Errors
    ///
    /// Returns `RsdebstrapError::Isolation` if `argv` is empty.
    pub(crate) fn for_task_command(
        _token: &TaskCommandToken,
        argv: &[String],
        privilege: Option<PrivilegeMethod>,
    ) -> Result<Self, RsdebstrapError> {
        let (command, args) = argv.split_first().ok_or_else(|| {
            RsdebstrapError::Isolation("cannot execute command: empty command provided".to_string())
        })?;
        Ok(Self {
            command: command.clone(),
            args: args.to_vec(),
            cwd: None,
            env: Vec::new(),
            privilege,
        })
    }

    /// Sets the working directory
    #[must_use]
    pub fn with_cwd(mut self, cwd: Utf8PathBuf) -> Self {
        self.cwd = Some(cwd);
        self
    }

    /// Adds an environment variable
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Adds multiple environment variables.
    ///
    /// Accepts any iterator of key-value pairs that can be converted into strings,
    /// such as `Vec<(String, String)>`, `&[(&str, &str)]`, or `HashMap<String, String>`.
    #[must_use]
    pub fn with_envs<I, K, V>(mut self, envs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.env
            .extend(envs.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }
}

/// Result of command execution
#[derive(Debug)]
pub struct ExecutionResult {
    /// Exit status of the command (None in dry-run mode)
    pub status: Option<ExitStatus>,
}

impl ExecutionResult {
    /// Returns true if the command executed successfully.
    ///
    /// In dry-run mode (status is None), this always returns true.
    pub fn success(&self) -> bool {
        self.status.is_none_or(|s| s.success())
    }

    /// Returns the exit code if available
    pub fn code(&self) -> Option<i32> {
        self.status.and_then(|s| s.code())
    }
}

/// Trait for command execution.
///
/// Implementations must be `Send + Sync` to allow the executor to be shared
/// across threads (e.g., when used with `Arc<dyn CommandExecutor>` for
/// concurrent output streaming during command execution).
pub trait CommandExecutor: Send + Sync {
    /// Executes a command with the given specification.
    fn execute(&self, spec: &CommandSpec) -> Result<ExecutionResult>;

    /// Whether this executor only reports what it would do.
    ///
    /// The single source of that answer for a run. Isolation contexts, the mount guard and
    /// the rootfs operations all derive their behaviour from it rather than carrying their
    /// own copy, so no two layers can disagree about whether the run is a dry run.
    ///
    /// Defaults to `false` for the mock executors in tests, which are not dry runs.
    fn dry_run(&self) -> bool {
        false
    }

    /// Executes a command and returns an error for non-zero exit status.
    ///
    /// This is the preferred API for ordinary command execution paths where
    /// callers do not need to inspect the raw exit status.
    fn execute_checked(&self, spec: &CommandSpec) -> Result<()> {
        let result = self.execute(spec)?;
        match result.status {
            Some(status) if status.success() => Ok(()),
            Some(status) => Err(RsdebstrapError::execution(spec, status.to_string()).into()),
            None => Ok(()),
        }
    }
}
