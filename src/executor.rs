use anyhow::{Context, Result};
use std::ffi::OsString;
use std::process::Command;
use which::which;

/// Trait for command execution
pub trait CommandExecutor {
    /// Execute a command with the given arguments
    fn execute(&self, command: &str, args: &[OsString]) -> Result<()>;
}

/// Real command executor that uses std::process::Command to execute actual commands
pub struct RealCommandExecutor;

impl CommandExecutor for RealCommandExecutor {
    fn execute(&self, command: &str, args: &[OsString]) -> Result<()> {
        let cmd = match which(command) {
            Ok(p) => p,
            Err(e) => {
                anyhow::bail!("command not found: {}: {}", command, e);
            }
        };

        let status = Command::new(cmd)
            .args(args)
            .status()
            .with_context(|| format!("failed to start {}", command))?;

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

/// Mock command executor for testing
pub struct MockCommandExecutor {
    pub expect_success: bool,
}

impl CommandExecutor for MockCommandExecutor {
    fn execute(&self, command: &str, _args: &[OsString]) -> Result<()> {
        // In a real implementation, you might want to record the command and args
        // or perform other verification logic
        // TODO: Record the command and args for verification
        if self.expect_success {
            Ok(())
        } else {
            anyhow::bail!("{} mock execution failed", command)
        }
    }
}
