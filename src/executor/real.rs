//! Real command executor implementation.
//!
//! This module provides [`RealCommandExecutor`], which executes commands
//! using `std::process::Command` with real-time output streaming.

use std::process::{Child, Command, Stdio};
use std::thread;
use std::thread::JoinHandle;

use anyhow::{Context, Result};
use which::which;

use super::pipe::{StreamType, panic_message, read_pipe_to_log};
use super::{CommandExecutor, CommandSpec, ExecutionResult};

/// Cleans up a child process and its associated reader threads.
///
/// This function kills the child process, waits for it to terminate,
/// and joins all reader threads to prevent resource leaks.
///
/// Called from error paths in [`RealCommandExecutor::execute()`] to ensure
/// proper cleanup when thread spawning or process waiting fails.
fn cleanup_child_process<I>(child: &mut Child, handles: I)
where
    I: IntoIterator<Item = JoinHandle<()>>,
{
    let pid = child.id();
    if let Err(e) = child.kill() {
        tracing::debug!(pid = pid, "kill returned error (process may have already exited): {}", e);
    }
    if let Err(e) = child.wait() {
        tracing::warn!(pid = pid, "failed to wait for child process after kill: {}", e);
    }
    for handle in handles {
        if let Err(e) = handle.join() {
            tracing::warn!("reader thread panicked during cleanup: {}", panic_message(&*e));
        }
    }
}

/// Command executor that runs actual system commands.
///
/// When `dry_run` is true, commands are logged but not executed,
/// and `execute()` returns `Ok(ExecutionResult { status: None })`.
pub struct RealCommandExecutor {
    pub dry_run: bool,
}

impl CommandExecutor for RealCommandExecutor {
    fn execute(&self, spec: &CommandSpec) -> Result<ExecutionResult> {
        if self.dry_run {
            tracing::info!("dry run: {:?}", spec);
            return Ok(ExecutionResult { status: None });
        }

        let cmd =
            which(&spec.command).with_context(|| format!("command not found: {}", spec.command))?;
        tracing::trace!("command found: {}: {}", spec.command, cmd.to_string_lossy());

        let mut command = Command::new(cmd);
        command.args(&spec.args);

        if let Some(ref cwd) = spec.cwd {
            command.current_dir(cwd);
        }

        for (key, value) in &spec.env {
            command.env(key, value);
        }

        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let mut child = command.spawn().with_context(|| {
            format!("failed to spawn command `{}` with args {:?}", spec.command, spec.args)
        })?;

        tracing::trace!("spawned command: {}: pid={}", spec.command, child.id());

        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();

        // Read both stdout and stderr in separate threads with panic error propagation
        let stdout_handle = match thread::Builder::new()
            .name("stdout-reader".to_string())
            .spawn(move || read_pipe_to_log(stdout_pipe, StreamType::Stdout))
        {
            Ok(handle) => handle,
            Err(e) => {
                cleanup_child_process(&mut child, []);
                return Err(crate::error::RsdebstrapError::Execution {
                    command: format!("{} {:?}", spec.command, spec.args),
                    status: format!("failed to spawn stdout reader thread: {}", e),
                }
                .into());
            }
        };

        let stderr_handle = match thread::Builder::new()
            .name("stderr-reader".to_string())
            .spawn(move || read_pipe_to_log(stderr_pipe, StreamType::Stderr))
        {
            Ok(handle) => handle,
            Err(e) => {
                // Clean up by killing the child process and joining the stdout thread
                cleanup_child_process(&mut child, [stdout_handle]);
                return Err(crate::error::RsdebstrapError::Execution {
                    command: format!("{} {:?}", spec.command, spec.args),
                    status: format!("failed to spawn stderr reader thread: {}", e),
                }
                .into());
            }
        };

        // Wait for the child process to complete
        let status = match child.wait() {
            Ok(s) => s,
            Err(e) => {
                // If waiting fails, the process might still be running.
                // Kill it and clean up threads to prevent resource leaks.
                cleanup_child_process(&mut child, [stdout_handle, stderr_handle]);
                return Err(crate::error::RsdebstrapError::Execution {
                    command: format!("{} {:?}", spec.command, spec.args),
                    status: format!("failed to wait for command: {}", e),
                }
                .into());
            }
        };

        // Wait for reader threads to complete (with error propagation on panic)
        let mut panicked_streams = Vec::new();
        let handles = [("stdout", stdout_handle), ("stderr", stderr_handle)];
        for (name, handle) in handles {
            if let Err(e) = handle.join() {
                let msg = panic_message(&*e);
                tracing::error!(stream = name, panic = msg, "reader thread panicked");
                panicked_streams.push(format!("{}: {}", name, msg));
            }
        }

        if !panicked_streams.is_empty() {
            return Err(crate::error::RsdebstrapError::Execution {
                command: format!("{} {:?}", spec.command, spec.args),
                status: format!(
                    "reader thread(s) panicked during command execution: {}",
                    panicked_streams.join(", ")
                ),
            }
            .into());
        }

        tracing::trace!("executed command: {}: success={}", spec.command, status.success());

        Ok(ExecutionResult {
            status: Some(status),
        })
    }
}
