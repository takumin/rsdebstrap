//! Tests for command executors

use anyhow::Result;
use camino::Utf8Path;
use rsdebstrap::executor::{ChrootExecutor, CommandExecutor, RealCommandExecutor};
use std::ffi::OsString;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_real_executor_dry_run() {
    let executor = RealCommandExecutor { dry_run: true };
    let args: Vec<OsString> = vec!["--version".into()];

    // Should succeed in dry-run mode without actually executing
    assert!(executor.execute("ls", &args).is_ok());
}

#[test]
fn test_real_executor_nonexistent_command() {
    let executor = RealCommandExecutor { dry_run: false };
    let args: Vec<OsString> = vec![];

    // Should fail when command doesn't exist
    let result = executor.execute("nonexistent_command_xyz", &args);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("command not found")
    );
}

#[test]
fn test_chroot_executor_new() {
    let rootfs = Utf8Path::new("/tmp/test-rootfs");
    let executor = ChrootExecutor::new(rootfs, false);

    assert_eq!(executor.rootfs, rootfs);
    assert!(!executor.dry_run);
}

#[test]
fn test_chroot_executor_dry_run() {
    let rootfs = Utf8Path::new("/tmp/test-rootfs");
    let executor = ChrootExecutor::new(rootfs, true);
    let args: Vec<OsString> = vec!["-c".into(), "echo hello".into()];

    // Should succeed in dry-run mode without validating rootfs
    assert!(executor.execute("/bin/sh", &args).is_ok());
}

#[test]
fn test_chroot_executor_validate_rootfs_not_exists() {
    let rootfs = Utf8Path::new("/nonexistent/path/to/rootfs");
    let executor = ChrootExecutor::new(rootfs, false);

    // Should fail when rootfs doesn't exist
    let result = executor.validate_rootfs();
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("failed to read rootfs metadata")
    );
}

#[test]
fn test_chroot_executor_validate_rootfs_not_directory() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let file_path = temp_dir.path().join("not-a-directory");
    fs::write(&file_path, "test")?;

    let rootfs = Utf8Path::from_path(&file_path).unwrap();
    let executor = ChrootExecutor::new(rootfs, false);

    // Should fail when rootfs is a file, not a directory
    let result = executor.validate_rootfs();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not a directory"));

    Ok(())
}

#[test]
fn test_chroot_executor_validate_rootfs_success() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let rootfs = Utf8Path::from_path(temp_dir.path()).unwrap();
    let executor = ChrootExecutor::new(rootfs, false);

    // Should succeed when rootfs is a valid directory
    assert!(executor.validate_rootfs().is_ok());

    Ok(())
}

#[test]
fn test_chroot_executor_dry_run_skips_validation() {
    let rootfs = Utf8Path::new("/nonexistent/path");
    let executor = ChrootExecutor::new(rootfs, true);

    // Should succeed even with invalid rootfs in dry-run mode
    assert!(executor.validate_rootfs().is_ok());
}

#[test]
fn test_chroot_executor_execute_validates_rootfs() {
    let rootfs = Utf8Path::new("/nonexistent/rootfs");
    let executor = ChrootExecutor::new(rootfs, false);
    let args: Vec<OsString> = vec![];

    // Should fail validation before attempting execution
    let result = executor.execute("ls", &args);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("rootfs validation failed")
            || err_msg.contains("failed to read rootfs metadata"),
        "Expected rootfs validation error, got: {}",
        err_msg
    );
}

#[cfg(unix)]
#[test]
#[ignore] // This test requires root privileges to actually execute chroot
fn test_chroot_executor_execute_real() -> Result<()> {
    use std::process::Command;

    // Check if running as root
    let output = Command::new("id").arg("-u").output()?;
    let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if uid != "0" {
        println!("Skipping test - requires root privileges");
        return Ok(());
    }

    // Create a minimal rootfs with /bin/sh
    let temp_dir = TempDir::new()?;
    let rootfs = Utf8Path::from_path(temp_dir.path()).unwrap();
    fs::create_dir(rootfs.join("bin"))?;

    // Copy /bin/sh to the rootfs
    fs::copy("/bin/sh", rootfs.join("bin/sh"))?;

    let executor = ChrootExecutor::new(rootfs, false);
    let args: Vec<OsString> = vec!["-c".into(), "exit 0".into()];

    // Should execute successfully
    assert!(executor.execute("/bin/sh", &args).is_ok());

    Ok(())
}

#[test]
fn test_chroot_executor_trait_object() {
    let rootfs = Utf8Path::new("/tmp/test");
    let executor = ChrootExecutor::new(rootfs, true);

    // Should be usable as a trait object
    let executor_trait: &dyn CommandExecutor = &executor;
    let args: Vec<OsString> = vec!["test".into()];

    // Should work through trait object in dry-run mode
    assert!(executor_trait.execute("echo", &args).is_ok());
}
