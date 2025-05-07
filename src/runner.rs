use crate::cli::ApplyArgs;
use crate::config::Profile;
use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

// Helper function to check if mmdebstrap is available
pub fn check_mmdebstrap_available() -> Result<bool> {
    let status = Command::new("which")
        .arg("mmdebstrap")
        .status()
        .context("Failed to execute 'which' command")?;
    Ok(status.success())
}

// Build command arguments for mmdebstrap
fn build_command_args(profile: &Profile) -> Result<Vec<OsString>> {
    let mut cmd_args = Vec::<OsString>::new();

    let mode = profile.mmdebstrap.mode.trim();
    if !mode.is_empty() {
        cmd_args.push("--mode".into());
        cmd_args.push(mode.into());
    }

    let format = profile.mmdebstrap.format.trim();
    if !format.is_empty() {
        cmd_args.push("--format".into());
        cmd_args.push(format.into());
    }

    let variant = profile.mmdebstrap.variant.trim();
    if !variant.is_empty() {
        cmd_args.push("--variant".into());
        cmd_args.push(variant.into());
    }

    if !profile.mmdebstrap.architectures.is_empty() {
        cmd_args.push("--architectures".into());
        cmd_args.push(profile.mmdebstrap.architectures.join(",").into());
    }

    if !profile.mmdebstrap.components.is_empty() {
        cmd_args.push("--components".into());
        cmd_args.push(profile.mmdebstrap.components.join(",").into());
    }

    if !profile.mmdebstrap.include.is_empty() {
        cmd_args.push("--include".into());
        cmd_args.push(profile.mmdebstrap.include.join(",").into());
    }

    if !profile.mmdebstrap.keyring.is_empty() {
        for keyring in profile.mmdebstrap.keyring.iter() {
            cmd_args.push("--keyring".into());
            cmd_args.push(keyring.into());
        }
    }

    if !profile.mmdebstrap.aptopt.is_empty() {
        for aptopt in profile.mmdebstrap.aptopt.iter() {
            cmd_args.push("--aptopt".into());
            cmd_args.push(aptopt.into());
        }
    }

    if !profile.mmdebstrap.dpkgopt.is_empty() {
        for dpkgopt in profile.mmdebstrap.dpkgopt.iter() {
            cmd_args.push("--dpkgopt".into());
            cmd_args.push(dpkgopt.into());
        }
    }

    if !profile.mmdebstrap.setup_hook.is_empty() {
        for setup_hook in profile.mmdebstrap.setup_hook.iter() {
            cmd_args.push("--setup-hook".into());
            cmd_args.push(setup_hook.into());
        }
    }

    if !profile.mmdebstrap.extract_hook.is_empty() {
        for extract_hook in profile.mmdebstrap.extract_hook.iter() {
            cmd_args.push("--extract-hook".into());
            cmd_args.push(extract_hook.into());
        }
    }

    if !profile.mmdebstrap.essential_hook.is_empty() {
        for essential_hook in profile.mmdebstrap.essential_hook.iter() {
            cmd_args.push("--essential-hook".into());
            cmd_args.push(essential_hook.into());
        }
    }

    if !profile.mmdebstrap.customize_hook.is_empty() {
        for customize_hook in profile.mmdebstrap.customize_hook.iter() {
            cmd_args.push("--customize-hook".into());
            cmd_args.push(customize_hook.into());
        }
    }

    // suite
    cmd_args.push(profile.mmdebstrap.suite.clone().into());

    // target
    let target = PathBuf::from(profile.dir.clone()).join(profile.mmdebstrap.target.clone());
    cmd_args.push(target.clone().into_os_string());

    Ok(cmd_args)
}

pub fn run_mmdebstrap_with_checker<F>(profile: &Profile, args: &ApplyArgs, checker: F) -> Result<()>
where
    F: FnOnce() -> Result<bool>,
{
    // Check if mmdebstrap is available
    if !checker()? {
        bail!("mmdebstrap command not found. Please install mmdebstrap first.");
    }

    // Skip execution in dry run mode
    if args.dry_run {
        // Build the command for display only
        let cmd_args = build_command_args(profile)?;

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

        return Ok(());
    }

    let mut cmd = Command::new("mmdebstrap");
    let cmd_args = build_command_args(profile)?;

    // debug print
    let display = format!(
        "mmdebstrap {}",
        cmd_args
            .iter()
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    if args.debug {
        println!("[DEBUG] would run: {}", display);
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
        bail!("mmdebstrap exited with non-zero status: {}", status);
    }

    Ok(())
}

pub fn run_mmdebstrap(profile: &Profile, args: &ApplyArgs) -> Result<()> {
    run_mmdebstrap_with_checker(profile, args, check_mmdebstrap_available)
}
