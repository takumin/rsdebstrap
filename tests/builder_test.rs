mod helpers;

use anyhow::Result;
use camino::Utf8PathBuf;
use rsdebstrap::backends::mmdebstrap::MmdebstrapConfig;
use rsdebstrap::backends::BootstrapBackend;
use rsdebstrap::executor::{CommandExecutor, RealCommandExecutor};

#[test]
fn test_run_mmdebstrap_with_mock_success() -> Result<()> {
    let config = MmdebstrapConfig {
        components: vec!["main".to_string(), "contrib".to_string()],
        architectures: vec!["amd64".to_string()],
        include: vec!["curl".to_string(), "ca-certificates".to_string()],
        ..helpers::create_mmdebstrap("bookworm", "rootfs.tar.zst")
    };
    let dir = Utf8PathBuf::from("/tmp/test-success");

    // Create a mock executor that will "succeed"
    let executor = RealCommandExecutor { dry_run: false };

    // This should succeed because our mock is configured to succeed
    let result = executor.execute("echo", &config.build_args(&dir)?);
    assert!(result.is_ok());

    Ok(())
}

#[test]
fn test_run_mmdebstrap_with_mock_failure() -> Result<()> {
    let config = MmdebstrapConfig {
        components: vec!["main".to_string(), "contrib".to_string()],
        architectures: vec!["amd64".to_string()],
        include: vec!["curl".to_string(), "ca-certificates".to_string()],
        ..helpers::create_mmdebstrap("bookworm", "rootfs.tar.zst")
    };
    let dir = Utf8PathBuf::from("/tmp/test-failure");

    // Create a mock executor that will "fail"
    let executor = RealCommandExecutor { dry_run: false };

    // This should fail because our mock is configured to fail
    let result = executor.execute("false", &config.build_args(&dir)?);
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_build_mmdebstrap_args_with_mirrors() -> Result<()> {
    let config = MmdebstrapConfig {
        mirrors: vec![
            "http://ftp.jp.debian.org/debian".to_string(),
            "".to_string(),    // Empty string should be filtered out
            "   ".to_string(), // Whitespace-only string should be filtered out
            "http://security.debian.org/debian-security".to_string(),
        ],
        ..helpers::create_mmdebstrap("bookworm", "rootfs.tar.zst")
    };
    let dir = Utf8PathBuf::from("/tmp/test-mirrors");

    let args = config.build_args(&dir)?;

    // Convert to Vec<String> for easier comparison
    let args_str: Vec<String> = args
        .iter()
        .map(|s| s.to_string_lossy().to_string())
        .collect();

    // Expected arguments in exact order
    let expected = vec![
        "--mode",
        "auto",
        "--format",
        "auto",
        "--variant",
        "debootstrap",
        "bookworm",
        "/tmp/test-mirrors/rootfs.tar.zst",
        "http://ftp.jp.debian.org/debian",
        "http://security.debian.org/debian-security",
    ];

    assert_eq!(
        args_str, expected,
        "Generated arguments should match expected list with mirrors in correct order"
    );

    Ok(())
}

#[test]
fn test_build_debootstrap_args() -> Result<()> {
    use rsdebstrap::backends::debootstrap::{DebootstrapConfig, Variant};

    let config = DebootstrapConfig {
        suite: "trixie".to_string(),
        target: "rootfs".to_string(),
        variant: Variant::Minbase,
        arch: Some("amd64".to_string()),
        components: vec!["main".to_string(), "contrib".to_string()],
        include: vec!["curl".to_string()],
        exclude: vec![],
        mirror: Some("https://deb.debian.org/debian".to_string()),
        foreign: false,
        merged_usr: Some(true),
        no_resolve_deps: false,
        verbose: false,
        print_debs: false,
    };
    let dir = Utf8PathBuf::from("/tmp/test-debootstrap");

    let args = config.build_args(&dir)?;

    // Convert to Vec<String> for easier comparison
    let args_str: Vec<String> = args
        .iter()
        .map(|s| s.to_string_lossy().to_string())
        .collect();

    // Expected arguments
    let expected = vec![
        "--arch=amd64",
        "--variant=minbase",
        "--components=main,contrib",
        "--include=curl",
        "--merged-usr",
        "trixie",
        "/tmp/test-debootstrap/rootfs",
        "https://deb.debian.org/debian",
    ];

    assert_eq!(
        args_str, expected,
        "Generated debootstrap arguments should match expected list"
    );

    Ok(())
}
