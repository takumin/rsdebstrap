use anyhow::Result;
use rsdebstrap::cli::ApplyArgs;
use rsdebstrap::config::{Mmdebstrap, Profile};
use rsdebstrap::runner::run_mmdebstrap;

#[test]
fn test_run_mmdebstrap_dry_run() -> Result<()> {
    let profile = Profile {
        dir: "/tmp/test-dry-run".to_string(),
        mmdebstrap: Mmdebstrap {
            suite: "bookworm".to_string(),
            target: "rootfs.tar.zst".to_string(),
            mode: "auto".to_string(),
            format: "auto".to_string(),
            variant: "apt".to_string(),
            components: vec!["main".to_string(), "contrib".to_string()],
            architectures: vec!["amd64".to_string()],
            include: vec!["curl".to_string(), "ca-certificates".to_string()],
        },
    };

    let args = ApplyArgs {
        file: Some("test.yml".to_string()),
        dry_run: true,
        debug: true,
    };

    // This should succeed as we're not actually running mmdebstrap
    let result = run_mmdebstrap(&profile, &args);
    assert!(result.is_ok());

    Ok(())
}

// Skip this test by default since it would require mmdebstrap to be installed
#[test]
#[ignore]
fn test_run_mmdebstrap_command_building() -> Result<()> {
    let profile = Profile {
        dir: "/tmp/test-run".to_string(),
        mmdebstrap: Mmdebstrap {
            suite: "bookworm".to_string(),
            target: "rootfs.tar.zst".to_string(),
            mode: "auto".to_string(),
            format: "auto".to_string(),
            variant: "apt".to_string(),
            components: vec!["main".to_string(), "contrib".to_string()],
            architectures: vec!["amd64".to_string()],
            include: vec!["curl".to_string(), "ca-certificates".to_string()],
        },
    };

    let args = ApplyArgs {
        file: Some("test.yml".to_string()),
        dry_run: true,
        debug: false,
    };

    let result = run_mmdebstrap(&profile, &args);
    assert!(result.is_ok());

    Ok(())
}
