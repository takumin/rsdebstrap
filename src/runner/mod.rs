//! Runner module for script execution.
//!
//! This module provides abstractions for running scripts in various contexts.
//! The `ShellRunner` is the core component that can be reused by provisioners
//! and future pre/post processors.

mod shell;

pub use shell::{ScriptSource, ShellRunner};
