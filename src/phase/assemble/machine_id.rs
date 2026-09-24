//! machine_id task implementation for the assemble phase.
//!
//! Resets `/etc/machine-id` in the final rootfs so every machine booted from the image
//! generates its own ID, instead of sharing the one the build left behind.

use std::borrow::Cow;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use strum::Display;
use tracing::info;

use crate::error::RsdebstrapError;
use crate::isolation::RootfsContext;
use crate::phase::{AssembleItem, PhaseItem};
use crate::rootfs::{FileMode, RelPath};

/// What `/etc/machine-id` is reset to, per machine-id(5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum MachineId {
    /// The string `uninitialized`: the next boot is the first boot (`ConditionFirstBoot=`
    /// holds, so presets apply), and the ID generated then is committed to disk.
    Uninitialized,
    /// An empty file: an ID is generated at every boot and committed if `/etc` is
    /// writable, but no boot counts as the first one. Suits a read-only root.
    Empty,
}

impl MachineId {
    // 0444 is what systemd-machine-id-setup creates. The file is not removed instead: with
    // a read-only root, systemd can only bind-mount the generated ID over an existing file.
    const MODE: u32 = 0o444;

    fn content(self) -> &'static [u8] {
        match self {
            Self::Uninitialized => b"uninitialized\n",
            Self::Empty => b"",
        }
    }

    /// Executes the assemble machine_id task.
    ///
    /// `/var/lib/dbus/machine-id` is left alone: Debian ships it as a symlink to
    /// `/etc/machine-id`, so it follows this reset.
    pub fn execute(self, ctx: &dyn RootfsContext) -> anyhow::Result<()> {
        let rootfs = ctx.rootfs();
        if ctx.dry_run() {
            info!("would reset /etc/machine-id to {} in {}", self, rootfs);
            return Ok(());
        }
        ctx.rootfs_ops().write_file(
            &RelPath::parse("/etc/machine-id")?,
            self.content(),
            FileMode::new(Self::MODE),
        )?;
        info!("reset /etc/machine-id to {} in {}", self, rootfs);
        Ok(())
    }
}

impl PhaseItem for MachineId {
    fn name(&self) -> Cow<'_, str> {
        Cow::Owned(format!("machine_id:{self}"))
    }

    fn validate(&self) -> Result<(), RsdebstrapError> {
        Ok(())
    }
}

impl AssembleItem for MachineId {
    fn execute(&self, ctx: &dyn RootfsContext) -> anyhow::Result<()> {
        MachineId::execute(*self, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::PlainRootfsContext;
    use camino::{Utf8Path, Utf8PathBuf};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    // The state a build that installed systemd leaves: a real ID, and dbus's link to it.
    fn built_rootfs() -> (tempfile::TempDir, Utf8PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();
        std::fs::create_dir_all(rootfs.join("var/lib/dbus")).unwrap();
        std::fs::write(rootfs.join("etc/machine-id"), b"0123456789abcdef0123456789abcdef\n")
            .unwrap();
        std::os::unix::fs::symlink("/etc/machine-id", rootfs.join("var/lib/dbus/machine-id"))
            .unwrap();
        (temp, rootfs)
    }

    fn context(rootfs: &Utf8Path, dry_run: bool) -> PlainRootfsContext {
        let ops = crate::rootfs::LocalRootfsOps::open(rootfs).expect("fixture rootfs opens");
        PlainRootfsContext::new(rootfs, Arc::new(ops), dry_run)
    }

    #[test]
    fn execute_uninitialized_writes_the_first_boot_marker() {
        let (_temp, rootfs) = built_rootfs();

        MachineId::Uninitialized
            .execute(&context(&rootfs, false))
            .unwrap();

        assert_eq!(std::fs::read(rootfs.join("etc/machine-id")).unwrap(), b"uninitialized\n");
        let mode = std::fs::metadata(rootfs.join("etc/machine-id"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o444);
    }

    #[test]
    fn execute_empty_leaves_an_empty_file() {
        let (_temp, rootfs) = built_rootfs();

        MachineId::Empty.execute(&context(&rootfs, false)).unwrap();

        assert_eq!(std::fs::read(rootfs.join("etc/machine-id")).unwrap(), b"");
    }

    #[test]
    fn execute_leaves_the_dbus_link_in_place() {
        let (_temp, rootfs) = built_rootfs();

        MachineId::Empty.execute(&context(&rootfs, false)).unwrap();

        assert_eq!(
            std::fs::read_link(rootfs.join("var/lib/dbus/machine-id")).unwrap(),
            std::path::Path::new("/etc/machine-id")
        );
    }

    #[test]
    fn execute_dry_run_leaves_the_id() {
        let (_temp, rootfs) = built_rootfs();

        MachineId::Uninitialized
            .execute(&context(&rootfs, true))
            .unwrap();

        assert_eq!(
            std::fs::read(rootfs.join("etc/machine-id")).unwrap(),
            b"0123456789abcdef0123456789abcdef\n"
        );
    }

    // The write replaces the entry rather than writing through it, so a symlink planted at
    // /etc/machine-id cannot redirect it outside the rootfs.
    #[test]
    fn execute_replaces_a_symlink_instead_of_following_it() {
        let (temp, rootfs) = built_rootfs();
        let outside = temp.path().join("outside");
        std::fs::write(&outside, b"precious").unwrap();
        std::fs::remove_file(rootfs.join("etc/machine-id")).unwrap();
        std::os::unix::fs::symlink(&outside, rootfs.join("etc/machine-id")).unwrap();

        MachineId::Uninitialized
            .execute(&context(&rootfs, false))
            .unwrap();

        assert_eq!(std::fs::read(&outside).unwrap(), b"precious");
        assert!(
            !std::fs::symlink_metadata(rootfs.join("etc/machine-id"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn name_carries_the_variant() {
        assert_eq!(PhaseItem::name(&MachineId::Uninitialized), "machine_id:uninitialized");
        assert_eq!(PhaseItem::name(&MachineId::Empty), "machine_id:empty");
    }
}
