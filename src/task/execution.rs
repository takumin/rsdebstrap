//! Execution utilities for task command dispatch.
//!
//! Provides command execution within isolation contexts and
//! execution result checking.

use anyhow::Result;

use crate::error::RsdebstrapError;
use crate::executor::ExecutionResult;
use crate::isolation::IsolationContext;
use crate::privilege::PrivilegeMethod;

/// Executes a command within an isolation context, preserving `RsdebstrapError` variants.
///
/// If the context returns an `anyhow::Error` that wraps a `RsdebstrapError`, the typed
/// error is preserved. Otherwise, the error is wrapped with a descriptive context message.
///
/// # Arguments
///
/// * `context` - The isolation context to execute within
/// * `command` - The command and arguments to execute
/// * `task_label` - Human-readable label used in error messages
/// * `privilege` - Optional privilege escalation method (`sudo`/`doas`) to wrap the command
pub(crate) fn execute_in_context(
    context: &dyn IsolationContext,
    command: &[String],
    task_label: &str,
    privilege: Option<PrivilegeMethod>,
) -> Result<ExecutionResult> {
    context
        .execute(command, privilege)
        .map_err(|e| match e.downcast::<RsdebstrapError>() {
            Ok(typed) => typed.into(),
            Err(e) => e.context(format!("failed to execute {}", task_label)),
        })
}

/// Executes a command within an isolation context and checks the result.
///
/// Combines [`execute_in_context()`] and [`check_execution_result()`] into
/// a single call, since these two operations always occur together in task
/// execution flows.
///
/// # Arguments
///
/// * `context` - The isolation context to execute within
/// * `command` - The command and arguments to execute
/// * `task_label` - Human-readable label used in error messages
/// * `privilege` - Optional privilege escalation method (`sudo`/`doas`) to wrap the command
pub(crate) fn execute_and_check(
    context: &dyn IsolationContext,
    command: &[String],
    task_label: &str,
    privilege: Option<PrivilegeMethod>,
) -> Result<()> {
    let result = execute_in_context(context, command, task_label, privilege)?;
    check_execution_result(&result, command, context.name(), context.dry_run())
}

/// Checks the execution result and returns an error if the command failed.
///
/// Handles three cases:
/// - Non-zero exit status: returns `Execution` error with the status code
/// - No exit status in non-dry-run mode: returns `Execution` error (e.g., killed by signal)
/// - Success or dry-run with no status: returns `Ok(())`
pub(crate) fn check_execution_result(
    result: &ExecutionResult,
    command: &[String],
    context_name: &str,
    dry_run: bool,
) -> Result<()> {
    match result.status {
        Some(status) if !status.success() => {
            Err(
                RsdebstrapError::execution_in_isolation(command, context_name, status.to_string())
                    .into(),
            )
        }
        None if !dry_run => Err(RsdebstrapError::execution_in_isolation(
            command,
            context_name,
            "process exited without status (possibly killed by signal)",
        )
        .into()),
        _ => Ok(()),
    }
}
