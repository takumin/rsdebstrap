use anyhow::Result;
use camino::Utf8PathBuf;
use rsdebstrap::builder::build_mmdebstrap_args;
use rsdebstrap::config::{Format, Mmdebstrap, Mode, Profile, Variant};
use rsdebstrap::executor::{CommandExecutor, RealCommandExecutor};

#[test]
fn test_run_mmdebstrap_with_mock_success() -> Result<()> {
    let profile = Profile {
        dir: Utf8PathBuf::from("/tmp/test-success"),
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

    // Create a mock executor that will "succeed"
    let executor = RealCommandExecutor { dry_run: false };

    // This should succeed because our mock is configured to succeed
    let result = executor.execute("echo", &build_mmdebstrap_args(&profile));
    assert!(result.is_ok());

    Ok(())
}

#[test]
fn test_run_mmdebstrap_with_mock_failure() -> Result<()> {
    let profile = Profile {
        dir: Utf8PathBuf::from("/tmp/test-failure"),
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

    // Create a mock executor that will "fail"
    let executor = RealCommandExecutor { dry_run: false };

    // This should fail because our mock is configured to fail
    let result = executor.execute("false", &build_mmdebstrap_args(&profile));
    assert!(result.is_err());

    Ok(())
}
