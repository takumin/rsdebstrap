mod helpers;

use anyhow::Result;
use camino::Utf8PathBuf;
use rsdebstrap::bootstrap::BootstrapBackend;
use rsdebstrap::bootstrap::mmdebstrap::MmdebstrapConfig;
use rsdebstrap::executor::{CommandExecutor, CommandSpec, RealCommandExecutor};

#[test]
fn test_run_mmdebstrap_with_mock_success() -> Result<()> {
    let config = helpers::MmdebstrapConfigBuilder::new("bookworm", "rootfs.tar.zst")
        .components(["main", "contrib"])
        .architectures(["amd64"])
        .include(["curl", "ca-certificates"])
        .build();
    let dir = Utf8PathBuf::from("/tmp/test-success");

    // Create a mock executor that will "succeed"
    let executor = RealCommandExecutor { dry_run: false };

    // This should succeed because our mock is configured to succeed
    let spec = CommandSpec::new("echo", config.build_args(&dir)?);
    let result = executor.execute(&spec)?;
    assert!(result.success());

    Ok(())
}

#[test]
fn test_run_mmdebstrap_with_mock_failure() -> Result<()> {
    let config = helpers::MmdebstrapConfigBuilder::new("bookworm", "rootfs.tar.zst")
        .components(["main", "contrib"])
        .architectures(["amd64"])
        .include(["curl", "ca-certificates"])
        .build();
    let dir = Utf8PathBuf::from("/tmp/test-failure");

    // Create a mock executor that will "fail"
    let executor = RealCommandExecutor { dry_run: false };

    // This should succeed in execution but return non-zero status
    let spec = CommandSpec::new("false", config.build_args(&dir)?);
    let result = executor.execute(&spec)?;
    assert!(!result.success());

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

    let args_str = args;

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
    use rsdebstrap::bootstrap::debootstrap::Variant;

    let config = helpers::DebootstrapConfigBuilder::new("trixie", "rootfs")
        .variant(Variant::Minbase)
        .arch("amd64")
        .components(["main", "contrib"])
        .include(["curl"])
        .mirror("https://deb.debian.org/debian")
        .merged_usr(true)
        .build();
    let dir = Utf8PathBuf::from("/tmp/test-debootstrap");

    let args = config.build_args(&dir)?;

    let args_str = args;

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
    use rsdebstrap::bootstrap::mmdebstrap::{Format, Mode, Variant};

    let config = helpers::MmdebstrapConfigBuilder::new("bookworm", "rootfs.tar.zst")
        .mode(Mode::Sudo)
        .format(Format::TarZst)
        .variant(Variant::Apt)
        .build();
    let dir = Utf8PathBuf::from("/tmp/test");

    let args = config.build_args(&dir)?;

    let args_str = args;

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
    use rsdebstrap::bootstrap::debootstrap::Variant;

    let config = helpers::DebootstrapConfigBuilder::new("bookworm", "rootfs")
        .variant(Variant::Buildd)
        .build();
    let dir = Utf8PathBuf::from("/tmp/test");

    let args = config.build_args(&dir)?;

    let args_str = args;

    // Expected arguments - non-default variant should be included
    let expected = vec!["--variant=buildd", "bookworm", "/tmp/test/rootfs"];

    assert_eq!(args_str, expected, "Non-default variant should generate --variant flag");

    Ok(())
}

#[test]
fn test_build_debootstrap_args_with_all_non_default_flags() -> Result<()> {
    let config = helpers::DebootstrapConfigBuilder::new("trixie", "rootfs")
        .exclude(["systemd"])
        .foreign(true)
        .merged_usr(false)
        .no_resolve_deps(true)
        .verbose(true)
        .print_debs(true)
        .build();
    let dir = Utf8PathBuf::from("/tmp/test-debootstrap");

    let args = config.build_args(&dir)?;

    // Valued flags use `--flag=value` (Equals) style; boolean flags are bare.
    // --variant is omitted because minbase is the default.
    let expected = vec![
        "--exclude=systemd",
        "--foreign",
        "--no-merged-usr",
        "--no-resolve-deps",
        "--verbose",
        "--print-debs",
        "trixie",
        "/tmp/test-debootstrap/rootfs",
    ];

    assert_eq!(
        args, expected,
        "All non-default debootstrap flags should be emitted in the expected order"
    );

    Ok(())
}

#[test]
fn test_build_debootstrap_args_filters_empty_mirror() -> Result<()> {
    let config = helpers::DebootstrapConfigBuilder::new("bookworm", "rootfs")
        .mirror("   ")
        .build();
    let dir = Utf8PathBuf::from("/tmp/test-debootstrap-mirror");

    let args = config.build_args(&dir)?;

    // A whitespace-only mirror is filtered out, leaving only the positional suite/target.
    let expected = vec!["bookworm", "/tmp/test-debootstrap-mirror/rootfs"];

    assert_eq!(
        args, expected,
        "Whitespace-only mirror should be filtered out of debootstrap arguments"
    );

    Ok(())
}
