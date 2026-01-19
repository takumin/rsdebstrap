use anyhow::Result;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use which::which;

/// Command specification for execution.
#[derive(Debug, Clone, Default)]
pub struct CommandSpec {
    pub command: String,
    pub args: Vec<OsString>,
    pub cwd: Option<PathBuf>,
    pub env: Vec<(String, String)>,
}

impl CommandSpec {
    pub fn new(command: impl Into<String>, args: Vec<OsString>) -> Self {
        Self {
            command: command.into(),
            args,
            cwd: None,
            env: Vec::new(),
        }
    }
}

/// Execution result containing status and captured output.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Trait for command execution
pub trait CommandExecutor {
    /// Execute a command specification
    fn execute(&self, spec: &CommandSpec) -> Result<ExecutionResult>;
}

/// Real command executor that uses std::process::Command to execute actual commands
pub struct RealCommandExecutor {
    pub dry_run: bool,
}

impl CommandExecutor for RealCommandExecutor {
    fn execute(&self, spec: &CommandSpec) -> Result<ExecutionResult> {
        if self.dry_run {
            tracing::info!(
                "dry run: {}: {:?} (cwd: {:?}, env: {:?})",
                spec.command,
                spec.args,
                spec.cwd,
                spec.env
            );
            return Ok(ExecutionResult {
                status: dry_run_status_success(),
                stdout: Vec::new(),
                stderr: Vec::new(),
            });
        }

        let cmd = match which(&spec.command) {
            Ok(p) => p,
            Err(e) => {
                anyhow::bail!("command not found: {}: {}", spec.command, e);
            }
        };
        tracing::trace!("command found: {}: {}", spec.command, cmd.to_string_lossy());

        let mut command = Command::new(cmd);
        command.args(&spec.args);
        if let Some(cwd) = &spec.cwd {
            command.current_dir(cwd);
        }
        if !spec.env.is_empty() {
            command.envs(spec.env.iter().map(|(key, value)| (key, value)));
        }

        let output = match command.output() {
            Ok(output) => output,
            Err(e) => {
                anyhow::bail!(
                    "failed to spawn command `{}` with args {:?}: {}",
                    spec.command,
                    spec.args,
                    e
                );
            }
        };
        tracing::trace!("wait command: {}: {}", spec.command, output.status.success());

        if !output.status.success() {
            anyhow::bail!(
                "{} exited with non-zero status: {} and args: {:?}",
                spec.command,
                output.status,
                spec.args
            );
        }

        Ok(ExecutionResult {
            status: output.status,
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

fn dry_run_status_success() -> ExitStatus {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(0)
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(0)
    }
}
