use anyhow::Result;
use camino::Utf8PathBuf;
use rsdebstrap::cli::ApplyArgs;
use rsdebstrap::config::{Format, Mmdebstrap, Mode, Profile, Variant};
use rsdebstrap::runner::run_mmdebstrap;

#[test]
fn test_run_mmdebstrap_dry_run() -> Result<()> {
    let profile = Profile {
        dir: Utf8PathBuf::from("/tmp/test-dry-run"),
        mmdebstrap: Mmdebstrap {
            suite: "bookworm".to_string(),
            target: "rootfs.tar.zst".to_string(),
            mode: Mode::Auto,
            format: Format::Auto,
            variant: Variant::Debootstrap,
            components: vec!["main".to_string(), "contrib".to_string()],
            architectures: vec!["amd64".to_string()],
            include: vec!["curl".to_string(), "ca-certificates".to_string()],
            keyring: vec![],
            aptopt: vec![],
            dpkgopt: vec![],
            setup_hook: vec![],
            extract_hook: vec![],
            essential_hook: vec![],
            customize_hook: vec![],
        },
    };

    let args = ApplyArgs {
        file: Utf8PathBuf::from("test.yml"),
        dry_run: true,
        debug: true,
    };

    // This should succeed as we're not actually running mmdebstrap
    let result = run_mmdebstrap(&profile, args.dry_run, args.debug);
    assert!(result.is_ok());

    Ok(())
}

// Skip this test by default since it would require mmdebstrap to be installed
#[test]
#[ignore]
fn test_run_mmdebstrap_command_building() -> Result<()> {
    let profile = Profile {
        dir: Utf8PathBuf::from("/tmp/test-run"),
        mmdebstrap: Mmdebstrap {
            suite: "bookworm".to_string(),
            target: "rootfs.tar.zst".to_string(),
            mode: Mode::Auto,
            format: Format::Auto,
            variant: Variant::Debootstrap,
            components: vec!["main".to_string(), "contrib".to_string()],
            architectures: vec!["amd64".to_string()],
            include: vec!["curl".to_string(), "ca-certificates".to_string()],
            keyring: vec![],
            aptopt: vec![],
            dpkgopt: vec![],
            setup_hook: vec![],
            extract_hook: vec![],
            essential_hook: vec![],
            customize_hook: vec![],
        },
    };

    let args = ApplyArgs {
        file: Utf8PathBuf::from("test.yml"),
        dry_run: true,
        debug: false,
    };

    let result = run_mmdebstrap(&profile, args.dry_run, args.debug);
    assert!(result.is_ok());

    Ok(())
}
