mod helpers;

use anyhow::Result;
use camino::Utf8PathBuf;
use rsdebstrap::backends::debootstrap::DebootstrapConfig;
use rsdebstrap::backends::mmdebstrap::{Format, MmdebstrapConfig};
use rsdebstrap::backends::{BootstrapBackend, RootfsOutput};

#[test]
fn test_mmdebstrap_rootfs_output_directory_format() -> Result<()> {
    let config = MmdebstrapConfig {
        format: Format::Directory,
        ..helpers::create_mmdebstrap("bookworm", "rootfs")
    };
    let output_dir = Utf8PathBuf::from("/tmp/rootfs-output");

    match config.rootfs_output(&output_dir)? {
        RootfsOutput::Directory(path) => {
            assert_eq!(path, output_dir.join("rootfs"));
        }
        RootfsOutput::NonDirectory { reason } => {
            panic!("expected directory output, got non-directory: {reason}");
        }
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

    match config.rootfs_output(&output_dir)? {
        RootfsOutput::NonDirectory { reason } => {
            assert!(
                reason.contains("archive format detected based on extension: zst"),
                "unexpected reason: {reason}"
            );
        }
        RootfsOutput::Directory(path) => {
            panic!("expected non-directory output, got directory: {path}");
        }
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

    match config.rootfs_output(&output_dir)? {
        RootfsOutput::Directory(path) => {
            assert_eq!(path, output_dir.join("rootfs.dir"));
        }
        RootfsOutput::NonDirectory { reason } => {
            panic!("expected directory output, got non-directory: {reason}");
        }
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

    match config.rootfs_output(&output_dir)? {
        RootfsOutput::NonDirectory { reason } => {
            assert!(
                reason.contains("non-directory format specified: tar.gz"),
                "unexpected reason: {reason}"
            );
        }
        RootfsOutput::Directory(path) => {
            panic!("expected non-directory output, got directory: {path}");
        }
    }

    Ok(())
}

#[test]
fn test_debootstrap_rootfs_output_directory() -> Result<()> {
    let config = DebootstrapConfig {
        suite: "trixie".to_string(),
        target: "rootfs".to_string(),
        variant: Default::default(),
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
    let output_dir = Utf8PathBuf::from("/tmp/rootfs-output");

    match config.rootfs_output(&output_dir)? {
        RootfsOutput::Directory(path) => {
            assert_eq!(path, output_dir.join("rootfs"));
        }
        RootfsOutput::NonDirectory { reason } => {
            panic!("expected directory output, got non-directory: {reason}");
        }
    }

    Ok(())
}
