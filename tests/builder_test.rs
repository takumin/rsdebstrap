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
            mirrors: vec![],
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
            mirrors: vec![],
        },
    };

    // Create a mock executor that will "fail"
    let executor = RealCommandExecutor { dry_run: false };

    // This should fail because our mock is configured to fail
    let result = executor.execute("false", &build_mmdebstrap_args(&profile));
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_build_mmdebstrap_args_with_mirrors() -> Result<()> {
    let profile = Profile {
        dir: Utf8PathBuf::from("/tmp/test-mirrors"),
        mmdebstrap: Mmdebstrap {
            suite: "bookworm".to_string(),
            target: "rootfs.tar.zst".to_string(),
            mode: Mode::Auto,
            format: Format::Auto,
            variant: Variant::Debootstrap,
            components: vec![],
            architectures: vec![],
            include: vec![],
            keyring: vec![],
            aptopt: vec![],
            dpkgopt: vec![],
            setup_hook: vec![],
            extract_hook: vec![],
            essential_hook: vec![],
            customize_hook: vec![],
            mirrors: vec![
                "http://ftp.jp.debian.org/debian".to_string(),
                "http://security.debian.org/debian-security".to_string(),
            ],
        },
    };

    let args = build_mmdebstrap_args(&profile);

    // Convert OsString to Vec<String> for easier assertion
    let args_str: Vec<String> = args.iter().map(|s| s.to_string_lossy().to_string()).collect();

    // Check that mirrors are included as positional arguments after suite and target
    assert!(args_str.contains(&"bookworm".to_string()));
    assert!(args_str.contains(&"/tmp/test-mirrors/rootfs.tar.zst".to_string()));
    assert!(args_str.contains(&"http://ftp.jp.debian.org/debian".to_string()));
    assert!(args_str.contains(&"http://security.debian.org/debian-security".to_string()));

    // Verify the order: suite comes before target, target comes before mirrors
    let suite_pos = args_str
        .iter()
        .position(|s| s == "bookworm")
        .expect("suite should be in args");
    let target_pos = args_str
        .iter()
        .position(|s| s == "/tmp/test-mirrors/rootfs.tar.zst")
        .expect("target should be in args");
    let mirror1_pos = args_str
        .iter()
        .position(|s| s == "http://ftp.jp.debian.org/debian")
        .expect("first mirror should be in args");
    let mirror2_pos = args_str
        .iter()
        .position(|s| s == "http://security.debian.org/debian-security")
        .expect("second mirror should be in args");

    assert!(suite_pos < target_pos, "suite should come before target");
    assert!(target_pos < mirror1_pos, "target should come before first mirror");
    assert!(mirror1_pos < mirror2_pos, "mirrors should maintain order");

    Ok(())
}
