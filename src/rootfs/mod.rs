//! Filesystem operations anchored to a rootfs directory descriptor.
//!
//! Every mutation inside a rootfs goes through [`RootfsOps`]. Paths are
//! [`RelPath`] values that cannot name anything outside the rootfs, and the
//! implementations resolve them one component at a time with `O_NOFOLLOW`, so a
//! symlink planted anywhere along the path is an error rather than a redirect.
//!
//! This exists because the operations it replaces — `sudo mv`, `sudo cp`, `sudo
//! chmod` — take path *strings*. Between the check that a path was safe and the
//! moment `cp` resolved it, an attacker with write access to the rootfs could
//! swap a component for a symlink and have root write through it. Anchoring to a
//! descriptor removes the window: the descriptor names an inode, not a path.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use std::sync::Arc;

use camino::{Utf8Path, Utf8PathBuf};
use rustix::fs::{self as rfs, AtFlags, CWD, FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};

pub mod helper;

use crate::error::RsdebstrapError;
use crate::privilege::PrivilegeMethod;

type Result<T> = std::result::Result<T, RsdebstrapError>;

/// Refuses to buffer an entry larger than this when detaching it with
/// [`RootfsOps::take`]. The entries this module detaches are config files a few
/// hundred bytes long; anything at this size is a sign the path is not what the
/// caller thinks it is.
const MAX_TAKE_SIZE: u64 = 1 << 20;

/// A path relative to a rootfs root, guaranteed to stay inside it.
///
/// Absolute paths, `.`, `..`, and empty components are rejected at construction,
/// so no combination of `RelPath` values can escape the rootfs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelPath {
    components: Vec<String>,
}

impl RelPath {
    /// Parses a rootfs-relative path.
    ///
    /// A leading `/` is accepted and stripped: profile fields spell rootfs paths
    /// absolutely (`/etc/resolv.conf`) because that is how they read inside the
    /// rootfs, but they denote the same location.
    ///
    /// # Errors
    ///
    /// Returns `RsdebstrapError::Validation` if the path is empty or contains a
    /// `.` or `..` component.
    pub fn parse(path: &str) -> Result<Self> {
        let trimmed = path.trim_start_matches('/');
        let mut components = Vec::new();
        for part in trimmed.split('/') {
            match part {
                "" => continue,
                "." | ".." => {
                    return Err(RsdebstrapError::Validation(format!(
                        "rootfs path {:?} must not contain '{}' components",
                        path, part
                    )));
                }
                name => components.push(name.to_string()),
            }
        }
        if components.is_empty() {
            return Err(RsdebstrapError::Validation(format!(
                "rootfs path {:?} does not name an entry",
                path
            )));
        }
        Ok(Self { components })
    }

    /// The components this path is made of, each guaranteed free of separators.
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// True when `self` names this path or anything beneath it.
    ///
    /// Compares component-wise rather than by string prefix, so `/dev` does not appear to
    /// contain `/devices`.
    pub fn starts_with(&self, prefix: &Self) -> bool {
        self.components.len() >= prefix.components.len()
            && self.components[..prefix.components.len()] == prefix.components[..]
    }

    /// Renders this path against a host-side root directory.
    ///
    /// Only for handing a path to a program that takes one (`mount`, `umount`). Filesystem
    /// mutation goes through [`RootfsOps`], which never renders a path at all.
    pub fn to_host_path(&self, root: &Utf8Path) -> Utf8PathBuf {
        let mut out = root.to_path_buf();
        for component in &self.components {
            out.push(component);
        }
        out
    }

    /// The final component — the entry this path names within its parent.
    fn file_name(&self) -> &str {
        self.components.last().expect("RelPath is never empty")
    }

    /// The components leading up to (but not including) [`file_name`](Self::file_name).
    fn parent_components(&self) -> &[String] {
        &self.components[..self.components.len() - 1]
    }
}

impl std::fmt::Display for RelPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "/{}", self.components.join("/"))
    }
}

impl serde::Serialize for RelPath {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RelPath {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// An entry detached from the rootfs by [`RootfsOps::take`], held in memory.
///
/// Nothing on disk represents a taken entry. A backup *file* would survive a
/// crash as an orphan the operator has to clean up by hand, and its path would
/// be one more thing an attacker could pre-create; holding the content in the
/// parent process makes both impossible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TakenEntry {
    /// A regular file, with the mode it carried.
    File { content: Vec<u8>, mode: u32 },
    /// A symlink, with the target it pointed at. Whether that target resolved is
    /// deliberately not consulted: a dangling `/etc/resolv.conf` is the normal
    /// state of a systemd rootfs before `systemd-resolved` runs, and it must be
    /// restored exactly as found.
    Symlink { target: String },
}

/// Mutations inside a rootfs.
///
/// Implemented in-process by [`LocalRootfsOps`] and, when the rootfs needs root
/// to modify, by a helper process holding the elevated descriptor.
pub trait RootfsOps: Send + Sync {
    /// Replaces `path` with a regular file, atomically.
    fn write_file(&self, path: &RelPath, content: &[u8], mode: u32) -> Result<()>;

    /// Replaces `path` with a symlink to `target`, atomically.
    fn write_symlink(&self, path: &RelPath, target: &str) -> Result<()>;

    /// Copies a host file into the rootfs at `path`, atomically.
    fn import_file(&self, host_src: &Utf8Path, path: &RelPath, mode: u32) -> Result<()>;

    /// Removes `path`. Succeeds if it does not exist; never follows a symlink.
    fn remove(&self, path: &RelPath) -> Result<()>;

    /// Detaches `path`, returning its contents, or `None` if it did not exist.
    ///
    /// After this returns, nothing exists at `path`.
    fn take(&self, path: &RelPath) -> Result<Option<TakenEntry>>;

    /// Writes a previously taken entry back to `path`, atomically.
    fn put_back(&self, path: &RelPath, entry: &TakenEntry) -> Result<()> {
        match entry {
            TakenEntry::File { content, mode } => self.write_file(path, content, *mode),
            TakenEntry::Symlink { target } => self.write_symlink(path, target),
        }
    }
}

/// [`RootfsOps`] performed directly by this process.
pub struct LocalRootfsOps {
    root: OwnedFd,
    /// Rendered only in error messages; resolution never consults it.
    display_root: String,
}

impl LocalRootfsOps {
    /// Opens `rootfs` and anchors subsequent operations to the directory it
    /// names at this moment.
    ///
    /// # Errors
    ///
    /// Returns `RsdebstrapError::Isolation` if `rootfs` is a symlink or not a
    /// directory.
    pub fn open(rootfs: &Utf8Path) -> Result<Self> {
        let root = rfs::openat(
            CWD,
            rootfs.as_str(),
            OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| open_error(e, rootfs.as_str()))?;
        Ok(Self {
            root,
            display_root: rootfs.to_string(),
        })
    }

    /// Walks to the directory holding `path`'s final component.
    ///
    /// Each component is opened with `O_NOFOLLOW`, so a symlink anywhere along
    /// the way fails instead of redirecting the operation.
    fn parent_dir(&self, path: &RelPath) -> Result<ParentDir<'_>> {
        let mut current: Option<OwnedFd> = None;
        for (depth, component) in path.parent_components().iter().enumerate() {
            let dir = current.as_ref().map_or(self.root.as_fd(), AsFd::as_fd);
            let next = rfs::openat(
                dir,
                component.as_str(),
                OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| {
                let so_far = path.components[..=depth].join("/");
                open_error(e, &format!("{}/{}", self.display_root, so_far))
            })?;
            current = Some(next);
        }
        Ok(ParentDir {
            owned: current,
            root: self.root.as_fd(),
        })
    }

    /// Creates a uniquely named sibling of `name` in `dir`.
    ///
    /// A sibling (rather than a path under `/tmp`) so that the `renameat` that
    /// promotes it is a same-directory rename, which the kernel performs
    /// atomically. The name is unique per call, so a stale entry left by an
    /// interrupted run can never be the one promoted.
    fn staging_name(name: &str) -> String {
        format!(".{}.rsdebstrap-{}", name, uuid::Uuid::new_v4().simple())
    }

    fn promote(&self, dir: BorrowedFd<'_>, staging: &str, target: &str) -> Result<()> {
        rfs::renameat(dir, staging, dir, target).map_err(|e| {
            let _ = rfs::unlinkat(dir, staging, AtFlags::empty());
            RsdebstrapError::io(
                format!("failed to install {}/{}", self.display_root, target),
                std::io::Error::from(e),
            )
        })
    }
}

/// The directory holding the entry an operation targets.
struct ParentDir<'a> {
    owned: Option<OwnedFd>,
    root: BorrowedFd<'a>,
}

impl ParentDir<'_> {
    fn fd(&self) -> BorrowedFd<'_> {
        self.owned.as_ref().map_or(self.root, AsFd::as_fd)
    }
}

fn open_error(e: rustix::io::Errno, what: &str) -> RsdebstrapError {
    match e {
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => RsdebstrapError::Isolation(format!(
            "{} is a symlink or not a directory, refusing to operate on it \
            (possible symlink attack)",
            what
        )),
        _ => RsdebstrapError::io(format!("failed to open {}", what), std::io::Error::from(e)),
    }
}

impl RootfsOps for LocalRootfsOps {
    fn write_file(&self, path: &RelPath, content: &[u8], mode: u32) -> Result<()> {
        let parent = self.parent_dir(path)?;
        let dir = parent.fd();
        let name = path.file_name();
        let staging = Self::staging_name(name);

        let fd = rfs::openat(
            dir,
            staging.as_str(),
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::from_raw_mode(mode),
        )
        .map_err(|e| {
            RsdebstrapError::io(
                format!("failed to stage {}{}", self.display_root, path),
                std::io::Error::from(e),
            )
        })?;

        let write = (|| {
            let mut file = File::from(fd);
            file.write_all(content)?;
            file.sync_all()
        })();
        if let Err(e) = write {
            let _ = rfs::unlinkat(dir, staging.as_str(), AtFlags::empty());
            return Err(RsdebstrapError::io(
                format!("failed to write {}{}", self.display_root, path),
                e,
            ));
        }

        self.promote(dir, &staging, name)
    }

    fn write_symlink(&self, path: &RelPath, target: &str) -> Result<()> {
        let parent = self.parent_dir(path)?;
        let dir = parent.fd();
        let name = path.file_name();
        let staging = Self::staging_name(name);

        rfs::symlinkat(target, dir, staging.as_str()).map_err(|e| {
            RsdebstrapError::io(
                format!("failed to stage symlink {}{}", self.display_root, path),
                std::io::Error::from(e),
            )
        })?;

        self.promote(dir, &staging, name)
    }

    fn import_file(&self, host_src: &Utf8Path, path: &RelPath, mode: u32) -> Result<()> {
        let content = std::fs::read(host_src)
            .map_err(|e| RsdebstrapError::io(format!("failed to read {}", host_src), e))?;
        self.write_file(path, &content, mode)
    }

    fn remove(&self, path: &RelPath) -> Result<()> {
        let parent = self.parent_dir(path)?;
        match rfs::unlinkat(parent.fd(), path.file_name(), AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(e) => Err(RsdebstrapError::io(
                format!("failed to remove {}{}", self.display_root, path),
                std::io::Error::from(e),
            )),
        }
    }

    fn take(&self, path: &RelPath) -> Result<Option<TakenEntry>> {
        let parent = self.parent_dir(path)?;
        let dir = parent.fd();
        let name = path.file_name();

        // symlink_metadata semantics: a dangling symlink is an entry that exists
        // and must be preserved, not an absent one.
        let stat = match rfs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(e) => {
                return Err(RsdebstrapError::io(
                    format!("failed to stat {}{}", self.display_root, path),
                    std::io::Error::from(e),
                ));
            }
        };

        let entry = match FileType::from_raw_mode(stat.st_mode as rfs::RawMode) {
            FileType::Symlink => {
                let target = rfs::readlinkat(dir, name, Vec::new()).map_err(|e| {
                    RsdebstrapError::io(
                        format!("failed to read symlink {}{}", self.display_root, path),
                        std::io::Error::from(e),
                    )
                })?;
                TakenEntry::Symlink {
                    target: target.to_string_lossy().into_owned(),
                }
            }
            FileType::RegularFile => {
                if stat.st_size as u64 > MAX_TAKE_SIZE {
                    return Err(RsdebstrapError::Isolation(format!(
                        "{}{} is {} bytes, refusing to detach an entry over {} bytes",
                        self.display_root, path, stat.st_size, MAX_TAKE_SIZE
                    )));
                }
                let fd = rfs::openat(
                    dir,
                    name,
                    OFlags::NOFOLLOW | OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|e| open_error(e, &format!("{}{}", self.display_root, path)))?;
                let mut content = Vec::new();
                File::from(fd).read_to_end(&mut content).map_err(|e| {
                    RsdebstrapError::io(format!("failed to read {}{}", self.display_root, path), e)
                })?;
                TakenEntry::File {
                    content,
                    mode: stat.st_mode & 0o7777,
                }
            }
            other => {
                return Err(RsdebstrapError::Isolation(format!(
                    "{}{} is a {:?}, refusing to detach it",
                    self.display_root, path, other
                )));
            }
        };

        rfs::unlinkat(dir, name, AtFlags::empty()).map_err(|e| {
            RsdebstrapError::io(
                format!("failed to detach {}{}", self.display_root, path),
                std::io::Error::from(e),
            )
        })?;
        Ok(Some(entry))
    }
}

/// [`RootfsOps`] that reports what it would do and changes nothing.
pub struct DryRunRootfsOps {
    rootfs: Utf8PathBuf,
}

impl DryRunRootfsOps {
    pub fn new(rootfs: &Utf8Path) -> Self {
        Self {
            rootfs: rootfs.to_owned(),
        }
    }
}

impl RootfsOps for DryRunRootfsOps {
    fn write_file(&self, path: &RelPath, content: &[u8], mode: u32) -> Result<()> {
        tracing::info!(
            "dry run: write {}{} ({} bytes, mode {:o})",
            self.rootfs,
            path,
            content.len(),
            mode
        );
        Ok(())
    }

    fn write_symlink(&self, path: &RelPath, target: &str) -> Result<()> {
        tracing::info!("dry run: symlink {}{} -> {}", self.rootfs, path, target);
        Ok(())
    }

    fn import_file(&self, host_src: &Utf8Path, path: &RelPath, mode: u32) -> Result<()> {
        tracing::info!("dry run: copy {} to {}{} (mode {:o})", host_src, self.rootfs, path, mode);
        Ok(())
    }

    fn remove(&self, path: &RelPath) -> Result<()> {
        tracing::info!("dry run: remove {}{}", self.rootfs, path);
        Ok(())
    }

    fn take(&self, path: &RelPath) -> Result<Option<TakenEntry>> {
        tracing::info!("dry run: detach {}{}", self.rootfs, path);
        // Nothing was detached, so nothing is restored on teardown — which is
        // what a dry run should leave behind.
        Ok(None)
    }
}

/// Opens the [`RootfsOps`] implementation matching the run's privilege setting.
///
/// Escalation happens here and only here: one helper per build, spawned before
/// any phase runs, rather than one per filesystem operation.
pub fn open(
    rootfs: &Utf8Path,
    privilege: Option<PrivilegeMethod>,
    dry_run: bool,
) -> Result<Arc<dyn RootfsOps>> {
    if dry_run {
        return Ok(Arc::new(DryRunRootfsOps::new(rootfs)));
    }
    match privilege {
        Some(method) => Ok(Arc::new(helper::PrivilegedRootfsOps::spawn(rootfs, method)?)),
        None => Ok(Arc::new(LocalRootfsOps::open(rootfs)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;

    fn rootfs() -> (tempfile::TempDir, Utf8PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        (tmp, root)
    }

    #[test]
    fn rel_path_rejects_escapes() {
        for bad in ["..", "../etc", "etc/../../x", "/etc/..", "", "/", "."] {
            assert!(RelPath::parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    // The resolution walk hands each component straight to `openat`/`unlinkat`, which
    // interpret a separator as another level of path. A component carrying one would be
    // resolved without the per-component `O_NOFOLLOW` the walk relies on, so a `..` inside a
    // component escapes the rootfs. `parse` splitting on '/' is what makes that impossible,
    // and it is the only constructor.
    #[test]
    fn rel_path_components_never_carry_a_separator() {
        for form in ["/etc/resolv.conf", "a/b/c/d", "etc//x", "//a//b//"] {
            let path = RelPath::parse(form).unwrap();
            assert!(
                path.components.iter().all(|c| !c.contains('/')),
                "{form:?} produced a component containing a separator: {:?}",
                path.components
            );
        }
    }

    #[test]
    fn rel_path_normalizes_leading_slash_and_empty_components() {
        let expected = RelPath::parse("etc/resolv.conf").unwrap();
        for form in ["/etc/resolv.conf", "etc//resolv.conf", "//etc/resolv.conf"] {
            assert_eq!(RelPath::parse(form).unwrap(), expected);
        }
        assert_eq!(expected.to_string(), "/etc/resolv.conf");
    }

    #[test]
    fn write_file_then_take_roundtrips_content_and_mode() {
        let (_tmp, root) = rootfs();
        let ops = LocalRootfsOps::open(&root).unwrap();
        let path = RelPath::parse("/etc/resolv.conf").unwrap();

        ops.write_file(&path, b"nameserver 1.1.1.1\n", 0o644)
            .unwrap();
        let taken = ops.take(&path).unwrap().unwrap();

        assert_eq!(
            taken,
            TakenEntry::File {
                content: b"nameserver 1.1.1.1\n".to_vec(),
                mode: 0o644
            }
        );
        assert!(!root.join("etc/resolv.conf").exists());

        ops.put_back(&path, &taken).unwrap();
        assert_eq!(std::fs::read(root.join("etc/resolv.conf")).unwrap(), b"nameserver 1.1.1.1\n");
    }

    #[test]
    fn take_preserves_a_dangling_symlink() {
        let (_tmp, root) = rootfs();
        let ops = LocalRootfsOps::open(&root).unwrap();
        let path = RelPath::parse("/etc/resolv.conf").unwrap();
        std::os::unix::fs::symlink(
            "../run/systemd/resolve/stub-resolv.conf",
            root.join("etc/resolv.conf"),
        )
        .unwrap();

        let taken = ops.take(&path).unwrap().unwrap();
        assert_eq!(
            taken,
            TakenEntry::Symlink {
                target: "../run/systemd/resolve/stub-resolv.conf".to_string()
            }
        );

        ops.put_back(&path, &taken).unwrap();
        let restored = std::fs::symlink_metadata(root.join("etc/resolv.conf")).unwrap();
        assert!(restored.file_type().is_symlink());
        assert_eq!(
            std::fs::read_link(root.join("etc/resolv.conf"))
                .unwrap()
                .to_str()
                .unwrap(),
            "../run/systemd/resolve/stub-resolv.conf"
        );
    }

    #[test]
    fn take_reports_absent_entry_as_none() {
        let (_tmp, root) = rootfs();
        let ops = LocalRootfsOps::open(&root).unwrap();
        assert_eq!(
            ops.take(&RelPath::parse("/etc/resolv.conf").unwrap())
                .unwrap(),
            None
        );
    }

    // The attack the fd anchoring exists to stop: `/etc` replaced by a symlink
    // pointing outside the rootfs. A path-string `cp` would write through it.
    #[test]
    fn a_symlinked_parent_directory_is_refused() {
        let (_tmp, root) = rootfs();
        let outside = root.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::remove_dir(root.join("etc")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("etc")).unwrap();

        let ops = LocalRootfsOps::open(&root).unwrap();
        let err = ops
            .write_file(&RelPath::parse("/etc/resolv.conf").unwrap(), b"x", 0o644)
            .unwrap_err();

        assert!(err.to_string().contains("symlink"), "unexpected error: {err}");
        assert!(!outside.join("resolv.conf").exists(), "wrote through the symlink");
    }

    // The final component being a symlink is not an attack — it is Debian's
    // default resolv.conf — so writing must replace the link, not follow it.
    #[test]
    fn write_replaces_a_symlink_target_rather_than_following_it() {
        let (_tmp, root) = rootfs();
        let elsewhere = root.join("etc/elsewhere");
        std::fs::write(&elsewhere, b"untouched").unwrap();
        std::os::unix::fs::symlink("elsewhere", root.join("etc/resolv.conf")).unwrap();

        let ops = LocalRootfsOps::open(&root).unwrap();
        ops.write_file(&RelPath::parse("/etc/resolv.conf").unwrap(), b"new", 0o644)
            .unwrap();

        assert_eq!(std::fs::read(&elsewhere).unwrap(), b"untouched");
        assert_eq!(std::fs::read(root.join("etc/resolv.conf")).unwrap(), b"new");
    }

    #[test]
    fn remove_is_idempotent_and_does_not_follow_symlinks() {
        let (_tmp, root) = rootfs();
        let target = root.join("etc/target");
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink("target", root.join("etc/link")).unwrap();

        let ops = LocalRootfsOps::open(&root).unwrap();
        let link = RelPath::parse("/etc/link").unwrap();
        ops.remove(&link).unwrap();
        ops.remove(&link).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }

    #[test]
    fn opening_a_symlinked_rootfs_is_refused() {
        let (_tmp, root) = rootfs();
        let link = root.join("link-to-etc");
        std::os::unix::fs::symlink(root.join("etc"), &link).unwrap();
        assert!(LocalRootfsOps::open(&link).is_err());
    }
}
