mod helpers;

use anyhow::Result;
use camino::Utf8PathBuf;
use rsdebstrap::bootstrap::mmdebstrap::{Format, MmdebstrapConfig};
use rsdebstrap::bootstrap::{BootstrapBackend, RootfsOutput};

#[test]
fn test_mmdebstrap_rootfs_output_directory_format() -> Result<()> {
    let config = MmdebstrapConfig {
        format: Format::Directory,
        ..helpers::create_mmdebstrap("bookworm", "rootfs")
    };
    let output_dir = Utf8PathBuf::from("/tmp/rootfs-output");

    let output = config.rootfs_output(&output_dir)?;
    if let RootfsOutput::Directory(path) = output {
        assert_eq!(path, output_dir.join("rootfs"));
    } else {
        panic!("expected directory output, got {output:?}");
    }

    Ok(())
}

#[test]
fn test_mmdebstrap_rootfs_output_auto_archive_extension() -> Result<()> {
    let config = MmdebstrapConfig {
        format: Format::Auto,
        ..helpers::create_mmdebstrap("bookworm", "rootfs.tar.zst")
    };
    let output_dir = Utf8PathBuf::from("/tmp/rootfs-output");

    let output = config.rootfs_output(&output_dir)?;
    if let RootfsOutput::NonDirectory { reason } = output {
        assert!(
            reason.contains("archive format detected based on extension: zst"),
            "unexpected reason: {reason}"
        );
    } else {
        panic!("expected non-directory output, got {output:?}");
    }

    Ok(())
}

#[test]
fn test_mmdebstrap_rootfs_output_auto_archive_dotfile() -> Result<()> {
    let config = MmdebstrapConfig {
        format: Format::Auto,
        ..helpers::create_mmdebstrap("bookworm", ".squashfs")
    };
    let output_dir = Utf8PathBuf::from("/tmp/rootfs-output");

    let output = config.rootfs_output(&output_dir)?;
    if let RootfsOutput::NonDirectory { reason } = output {
        assert!(
            reason.contains("archive format detected based on extension: squashfs"),
            "unexpected reason: {reason}"
        );
    } else {
        panic!("expected non-directory output, got {output:?}");
    }

    Ok(())
}

#[test]
fn test_mmdebstrap_rootfs_output_auto_directory_when_unknown_extension() -> Result<()> {
    let config = MmdebstrapConfig {
        format: Format::Auto,
        ..helpers::create_mmdebstrap("bookworm", "rootfs.dir")
    };
    let output_dir = Utf8PathBuf::from("/tmp/rootfs-output");

    let output = config.rootfs_output(&output_dir)?;
    if let RootfsOutput::Directory(path) = output {
        assert_eq!(path, output_dir.join("rootfs.dir"));
    } else {
        panic!("expected directory output, got {output:?}");
    }

    Ok(())
}

#[test]
fn test_mmdebstrap_rootfs_output_non_directory_format() -> Result<()> {
    let config = MmdebstrapConfig {
        format: Format::TarGz,
        ..helpers::create_mmdebstrap("bookworm", "rootfs.tar.gz")
    };
    let output_dir = Utf8PathBuf::from("/tmp/rootfs-output");

    let output = config.rootfs_output(&output_dir)?;
    if let RootfsOutput::NonDirectory { reason } = output {
        assert!(
            reason.contains("non-directory format specified: tar.gz"),
            "unexpected reason: {reason}"
        );
    } else {
        panic!("expected non-directory output, got {output:?}");
    }

    Ok(())
}

#[test]
fn test_debootstrap_rootfs_output_directory() -> Result<()> {
    let config = helpers::create_debootstrap("trixie", "rootfs");
    let output_dir = Utf8PathBuf::from("/tmp/rootfs-output");

    let output = config.rootfs_output(&output_dir)?;
    if let RootfsOutput::Directory(path) = output {
        assert_eq!(path, output_dir.join("rootfs"));
    } else {
        panic!("expected directory output, got {output:?}");
    }

    Ok(())
}
