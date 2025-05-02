use crate::cli::ApplyArgs;
use crate::config::Profile;
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

pub fn run_mmdebstrap(profile: &Profile, args: &ApplyArgs) -> Result<()> {
    let mut cmd = Command::new("mmdebstrap");
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

    if !profile.mmdebstrap.components.is_empty() {
        cmd_args.push("--components".into());
        cmd_args.push(profile.mmdebstrap.components.join(",").into());
    }

    if !profile.mmdebstrap.architectures.is_empty() {
        cmd_args.push("--architectures".into());
        cmd_args.push(profile.mmdebstrap.architectures.join(",").into());
    }

    if !profile.mmdebstrap.include.is_empty() {
        cmd_args.push("--include".into());
        cmd_args.push(profile.mmdebstrap.include.join(",").into());
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
        fs::create_dir_all(dir).expect("failed to create directory");
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
