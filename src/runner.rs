use crate::command::{CommandExecutor, RealCommandExecutor};
use crate::config::Profile;
use anyhow::Result;
use std::ffi::OsString;
use tracing::debug;

/// Adds a flag and its corresponding value to the command arguments if the value is not empty.
///
/// # Parameters
/// - `cmd_args`: A mutable reference to the vector of command arguments.
/// - `flag`: The flag to be added (e.g., `--mode`).
/// - `value`: The value associated with the flag. This value should already be trimmed.
///
/// # Behavior
/// If `value` is an empty string, the flag and value are not added to `cmd_args`.
///
/// # Example
/// ```
/// use std::ffi::OsString;
///
/// let mut cmd_args = Vec::<OsString>::new();
/// let flag = "--example";
///
/// // This will add the flag and value
/// rsdebstrap::runner::add_flag(&mut cmd_args, flag, "value1");
/// assert_eq!(cmd_args, vec![OsString::from("--example"), OsString::from("value1")]);
///
/// // This will not add anything since the value is empty
/// rsdebstrap::runner::add_flag(&mut cmd_args, flag, "");
/// assert_eq!(cmd_args, vec![OsString::from("--example"), OsString::from("value1")]);
/// ```
pub fn add_flag(cmd_args: &mut Vec<OsString>, flag: &str, value: &str) {
    if !value.is_empty() {
        cmd_args.push(flag.into());
        cmd_args.push(value.into());
    }
}

/// Adds a flag and its associated values to the command arguments.
///
/// This function iterates over the provided `values` slice and, for each non-empty string,
/// appends the `flag` and the `value` to the `cmd_args` vector. It does not perform any
/// trimming or preprocessing on the `values`; the caller is responsible for ensuring that
/// the input is in the desired format.
///
/// # Arguments
/// * `cmd_args` - A mutable reference to the vector of command-line arguments.
/// * `flag` - The flag to be added for each value.
/// * `values` - A slice of strings representing the values to be associated with the flag.
///
/// # Example
/// ```
/// use std::ffi::OsString;
///
/// let mut cmd_args = Vec::<OsString>::new();
/// let flag = "--example";
/// let values = vec!["value1".to_string(), "".to_string(), "value2".to_string()];
/// rsdebstrap::runner::add_flags(&mut cmd_args, flag, &values);
/// assert_eq!(cmd_args, vec![OsString::from("--example"), OsString::from("value1"),
///                           OsString::from("--example"), OsString::from("value2")]);
/// ```
pub fn add_flags(cmd_args: &mut Vec<OsString>, flag: &str, values: &[String]) {
    for value in values {
        if !value.is_empty() {
            cmd_args.push(flag.into());
            cmd_args.push(value.into());
        }
    }
}

#[tracing::instrument(skip(profile, executor))]
pub fn run_mmdebstrap_exec<E: CommandExecutor>(
    profile: &Profile,
    dry_run: bool,
    executor: &E,
) -> Result<()> {
    let mut cmd_args = Vec::<OsString>::new();

    add_flag(&mut cmd_args, "--mode", &profile.mmdebstrap.mode.to_string());
    add_flag(&mut cmd_args, "--format", &profile.mmdebstrap.format.to_string());
    add_flag(&mut cmd_args, "--variant", &profile.mmdebstrap.variant.to_string());

    add_flag(&mut cmd_args, "--architectures", &profile.mmdebstrap.architectures.join(","));
    add_flag(&mut cmd_args, "--components", &profile.mmdebstrap.components.join(","));
    add_flag(&mut cmd_args, "--include", &profile.mmdebstrap.include.join(","));

    add_flags(&mut cmd_args, "--keyring", &profile.mmdebstrap.keyring);
    add_flags(&mut cmd_args, "--aptopt", &profile.mmdebstrap.aptopt);
    add_flags(&mut cmd_args, "--dpkgopt", &profile.mmdebstrap.dpkgopt);

    add_flags(&mut cmd_args, "--setup-hook", &profile.mmdebstrap.setup_hook);
    add_flags(&mut cmd_args, "--extract-hook", &profile.mmdebstrap.extract_hook);
    add_flags(&mut cmd_args, "--essential-hook", &profile.mmdebstrap.essential_hook);
    add_flags(&mut cmd_args, "--customize-hook", &profile.mmdebstrap.customize_hook);

    cmd_args.push(profile.mmdebstrap.suite.clone().into());

    cmd_args.push(
        profile
            .dir
            .join(&profile.mmdebstrap.target)
            .into_os_string(),
    );

    debug!(
        "mmdebstrap would run: mmdebstrap {}",
        cmd_args
            .iter()
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );

    if dry_run {
        return Ok(());
    }

    executor.execute("mmdebstrap", &cmd_args)
}

/// Standard function that uses the RealCommandExecutor.
/// This is the main entry point for running mmdebstrap.
#[tracing::instrument(skip(profile))]
pub fn run_mmdebstrap(profile: &Profile, dry_run: bool) -> Result<()> {
    let executor = RealCommandExecutor;
    run_mmdebstrap_exec(profile, dry_run, &executor)
}
