mod helpers;

use anyhow::Result;
use camino::Utf8PathBuf;
use rsdebstrap::backends::BootstrapBackend;
use rsdebstrap::backends::mmdebstrap::MmdebstrapConfig;
use rsdebstrap::executor::{CommandExecutor, CommandSpec, RealCommandExecutor};

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
    let spec = CommandSpec::new("echo", config.build_args(&dir)?);
    let result = executor.execute(&spec);
    assert!(result.is_ok());
    assert!(result.unwrap().success());

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

    // This should succeed in execution but return non-zero status
    let spec = CommandSpec::new("false", config.build_args(&dir)?);
    let result = executor.execute(&spec);
    assert!(result.is_ok());
    assert!(!result.unwrap().success());

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
    // Note: --mode, --format, and --variant are omitted as they are all default values
    let expected = vec![
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
    // Note: --variant is omitted as it's the default value (minbase)
    let expected = vec![
        "--arch=amd64",
        "--components=main,contrib",
        "--include=curl",
        "--merged-usr",
        "trixie",
        "/tmp/test-debootstrap/rootfs",
        "https://deb.debian.org/debian",
    ];

    assert_eq!(args_str, expected, "Generated debootstrap arguments should match expected list");

    Ok(())
}

#[test]
fn test_build_mmdebstrap_args_with_non_default_values() -> Result<()> {
    use rsdebstrap::backends::mmdebstrap::{Format, Mode, Variant};

    let config = MmdebstrapConfig {
        suite: "bookworm".to_string(),
        target: "rootfs.tar.zst".to_string(),
        mode: Mode::Sudo,
        format: Format::TarZst,
        variant: Variant::Apt,
        architectures: vec![],
        components: vec![],
        include: vec![],
        keyring: vec![],
        aptopt: vec![],
        dpkgopt: vec![],
        setup_hook: vec![],
        extract_hook: vec![],
        essential_hook: vec![],
        customize_hook: vec![],
        mirrors: vec![],
    };
    let dir = Utf8PathBuf::from("/tmp/test");

    let args = config.build_args(&dir)?;

    // Convert to Vec<String> for easier comparison
    let args_str: Vec<String> = args
        .iter()
        .map(|s| s.to_string_lossy().to_string())
        .collect();

    // Expected arguments - non-default values should be included
    let expected = vec![
        "--mode",
        "sudo",
        "--format",
        "tar.zst",
        "--variant",
        "apt",
        "bookworm",
        "/tmp/test/rootfs.tar.zst",
    ];

    assert_eq!(args_str, expected, "Non-default values should generate corresponding flags");

    Ok(())
}

#[test]
fn test_build_debootstrap_args_with_non_default_variant() -> Result<()> {
    use rsdebstrap::backends::debootstrap::{DebootstrapConfig, Variant};

    let config = DebootstrapConfig {
        suite: "bookworm".to_string(),
        target: "rootfs".to_string(),
        variant: Variant::Buildd,
        arch: None,
        components: vec![],
        include: vec![],
        exclude: vec![],
        mirror: None,
        foreign: false,
        merged_usr: None,
        no_resolve_deps: false,
        verbose: false,
        print_debs: false,
    };
    let dir = Utf8PathBuf::from("/tmp/test");

    let args = config.build_args(&dir)?;

    // Convert to Vec<String> for easier comparison
    let args_str: Vec<String> = args
        .iter()
        .map(|s| s.to_string_lossy().to_string())
        .collect();

    // Expected arguments - non-default variant should be included
    let expected = vec!["--variant=buildd", "bookworm", "/tmp/test/rootfs"];

    assert_eq!(args_str, expected, "Non-default variant should generate --variant flag");

    Ok(())
}
