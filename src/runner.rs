use crate::cli::ApplyArgs;
use crate::config::Profile;
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Adds a flag and its corresponding value to the command arguments if the value is not empty.
/// 
/// # Parameters
/// - `cmd_args`: A mutable reference to the vector of command arguments.
/// - `flag`: The flag to be added (e.g., `--mode`).
/// - `value`: The value associated with the flag. This value should already be trimmed.
/// 
/// # Behavior
/// If `value` is an empty string, the flag and value are not added to `cmd_args`.
fn add_flag(cmd_args: &mut Vec<OsString>, flag: &str, value: &str) {
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
/// let mut cmd_args = Vec::new();
/// let flag = "--example";
/// let values = vec!["value1".to_string(), "".to_string(), "value2".to_string()];
/// add_flags(&mut cmd_args, flag, &values);
/// assert_eq!(cmd_args, vec!["--example", "value1", "--example", "value2"]);
/// ```
fn add_flags(cmd_args: &mut Vec<OsString>, flag: &str, values: &[String]) {
    for value in values {
        if !value.is_empty() {
            cmd_args.push(flag.into());
            cmd_args.push(value.into());
        }
    }
}

pub fn run_mmdebstrap(profile: &Profile, args: &ApplyArgs) -> Result<()> {
    let mut cmd = Command::new("mmdebstrap");
    let mut cmd_args = Vec::<OsString>::new();

    add_flag(&mut cmd_args, "--mode", profile.mmdebstrap.mode.trim());
    add_flag(&mut cmd_args, "--format", profile.mmdebstrap.format.trim());
    add_flag(
        &mut cmd_args,
        "--variant",
        profile.mmdebstrap.variant.trim(),
    );

    add_flag(
        &mut cmd_args,
        "--architectures",
        &profile.mmdebstrap.architectures.join(","),
    );
    add_flag(
        &mut cmd_args,
        "--components",
        &profile.mmdebstrap.components.join(","),
    );
    add_flag(
        &mut cmd_args,
        "--include",
        &profile.mmdebstrap.include.join(","),
    );

    add_flags(&mut cmd_args, "--keyring", &profile.mmdebstrap.keyring);
    add_flags(&mut cmd_args, "--aptopt", &profile.mmdebstrap.aptopt);
    add_flags(&mut cmd_args, "--dpkgopt", &profile.mmdebstrap.dpkgopt);

    add_flags(
        &mut cmd_args,
        "--setup-hook",
        &profile.mmdebstrap.setup_hook,
    );
    add_flags(
        &mut cmd_args,
        "--extract-hook",
        &profile.mmdebstrap.extract_hook,
    );
    add_flags(
        &mut cmd_args,
        "--essential-hook",
        &profile.mmdebstrap.essential_hook,
    );
    add_flags(
        &mut cmd_args,
        "--customize-hook",
        &profile.mmdebstrap.customize_hook,
    );

    // suite
    cmd_args.push(profile.mmdebstrap.suite.clone().into());

    // target
    let target = PathBuf::from(profile.dir.clone()).join(profile.mmdebstrap.target.clone());
    cmd_args.push(target.clone().into_os_string());

    // debug print
    let display = format!(
        "mmdebstrap {}",
        cmd_args
            .iter()
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    if args.debug || args.dry_run {
        println!("[DEBUG] would run: {}", display);
    }

    if args.dry_run {
        return Ok(());
    }

    let dir = PathBuf::from(profile.dir.clone());
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create directory: {}", dir.display()))?;
    }

    let status = cmd
        .args(&cmd_args)
        .status()
        .with_context(|| "failed to start mmdebstrap")?;
    if !status.success() {
        anyhow::bail!("mmdebstrap exited with non-zero status: {}", status);
    }

    Ok(())
}
