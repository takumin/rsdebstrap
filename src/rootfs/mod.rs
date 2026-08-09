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
use rustix::fs::{self as rfs, AtFlags, CWD, FileType, Gid, Mode, OFlags, Uid};
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

/// Serde codec for a file payload crossing the helper pipe.
///
/// JSON has no binary type, and `serde_json` renders a `Vec<u8>` as a decimal array:
/// `[104,101,...]`, about 4.6 bytes of text per byte of file. Staging a mitamae binary is
/// the case that matters — tens of megabytes become hundreds, held in full on both sides,
/// and the helper then parses one integer per byte. Base64 is 1.33x and decodes in a pass.
///
/// A length-prefixed raw frame would be 1.0x, but it would also make the payload the one
/// part of the protocol that is not self-delimiting: a desynchronised reader would resume
/// mid-payload and hand whatever it found to `serde_json`, in a process running as root.
/// The 33% buys back a protocol where every frame is one line.
pub(crate) mod payload {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(d)?;
        STANDARD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// The permission bits an entry carries.
///
/// A `u32` at these call sites is ambiguous: it is either the `st_mode` a `stat`
/// returned, whose high bits encode the file type, or the permissions to apply.
/// Handing the first to `chmod` would try to set the type bits. Construction
/// masks them off, so only the second can exist.
///
/// The bits are applied exactly. `openat`'s mode argument is subject to the
/// process umask, so [`RootfsOps::write_file`] cannot rely on it alone — see the
/// `fchmod` in [`LocalRootfsOps::write_file`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FileMode(u32);

impl FileMode {
    /// The permission bits of `bits`, which may be a full `st_mode`.
    pub const fn new(bits: u32) -> Self {
        Self(bits & 0o7777)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for FileMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:o}", self.0)
    }
}

/// The uid and gid an entry carried when it was detached.
///
/// Restored explicitly because [`RootfsOps::put_back`] installs a *new* inode: the
/// staging entry belongs to whoever wrote it, which is root for the whole of a run the
/// privileged helper serves. A rootfs bootstrapped unprivileged owns its files as the
/// calling user, so without this its `/etc/resolv.conf` comes back owned by root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
}

impl Owner {
    fn of(stat: &rfs::Stat) -> Self {
        Self {
            uid: stat.st_uid,
            gid: stat.st_gid,
        }
    }
}

/// An entry detached from the rootfs by [`RootfsOps::take`], held in memory.
///
/// Nothing on disk represents a taken entry. A backup *file* would survive a
/// crash as an orphan the operator has to clean up by hand, and its path would
/// be one more thing an attacker could pre-create; holding the content in the
/// parent process makes both impossible.
///
/// What it holds is what an `/etc/resolv.conf` needs to come back unchanged: the
/// content, the mode, and the owner. Timestamps, xattrs, ACLs and hard-link identity are
/// not carried, and the last of those no in-memory representation could carry -- the
/// entry is reinstalled as a new inode either way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TakenEntry {
    /// A regular file, with the mode and owner it carried.
    File {
        #[serde(with = "payload")]
        content: Vec<u8>,
        mode: FileMode,
        owner: Owner,
    },
    /// A symlink, with the target it pointed at. Whether that target resolved is
    /// deliberately not consulted: a dangling `/etc/resolv.conf` is the normal
    /// state of a systemd rootfs before `systemd-resolved` runs, and it must be
    /// restored exactly as found.
    Symlink { target: String, owner: Owner },
}

/// Mutations inside a rootfs.
///
/// Implemented in-process by [`LocalRootfsOps`] and, when the rootfs needs root
/// to modify, by a helper process holding the elevated descriptor.
pub trait RootfsOps: Send + Sync {
    /// Replaces `path` with a regular file carrying exactly `mode`, atomically.
    fn write_file(&self, path: &RelPath, content: &[u8], mode: FileMode) -> Result<()>;

    /// Replaces `path` with a symlink to `target`, atomically.
    fn write_symlink(&self, path: &RelPath, target: &str) -> Result<()>;

    /// Removes `path`. Succeeds if it does not exist; never follows a symlink.
    fn remove(&self, path: &RelPath) -> Result<()>;

    /// Detaches `path`, returning its contents, or `None` if it did not exist.
    ///
    /// After this returns, nothing exists at `path`.
    fn take(&self, path: &RelPath) -> Result<Option<TakenEntry>>;

    /// Writes a previously taken entry back to `path`, atomically, carrying back the
    /// mode and owner it was detached with.
    ///
    /// Required rather than defaulted to [`RootfsOps::write_file`]: that default
    /// reinstalled the entry as a file owned by whoever was writing it, and nothing in
    /// the signature said the owner had been dropped on the way.
    fn put_back(&self, path: &RelPath, entry: &TakenEntry) -> Result<()>;
}

/// [`RootfsOps`] performed directly by this process.
#[derive(Debug)]
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

    /// The rootfs directory this instance is anchored to.
    ///
    /// Only for asking questions *about* the anchor — `helper::CheckedAnchor` compares its
    /// inode against the live system's. Resolution inside the rootfs never goes through it.
    pub(crate) fn root(&self) -> BorrowedFd<'_> {
        self.root.as_fd()
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

    /// Reads the entry `detached` names in `dir`, which [`RootfsOps::take`] has already
    /// renamed out of the way.
    ///
    /// Everything the returned entry carries comes off one descriptor. The rename is what
    /// takes the caller's name out of play, but it does not hide the new one -- a watcher
    /// on the directory is told the name a rename lands on -- so classifying by `statat`
    /// and then opening by name would still be two resolutions, free to disagree about the
    /// type, the size, the mode and the owner.
    ///
    /// `path` is only for error messages: it is the name the caller asked about, which is
    /// no longer the name being read.
    fn read_detached(
        &self,
        dir: BorrowedFd<'_>,
        detached: &str,
        path: &RelPath,
    ) -> Result<TakenEntry> {
        // `O_NONBLOCK` because opening a FIFO for reading otherwise waits for a writer that
        // is never coming -- for the privileged helper, that is the build hanging with no
        // output. It is `fstat` below, not this open, that refuses one.
        let opened = rfs::openat(
            dir,
            detached,
            OFlags::NOFOLLOW | OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        );

        let fd = match opened {
            Ok(fd) => fd,
            // The one type that cannot be opened for reading, and the reason the caller's
            // `/etc/resolv.conf` is being detached at all half the time.
            Err(rustix::io::Errno::LOOP) => return self.read_detached_symlink(dir, detached, path),
            Err(e) => return Err(open_error(e, &format!("{}{}", self.display_root, path))),
        };

        let stat = rfs::fstat(&fd).map_err(|e| {
            RsdebstrapError::io(
                format!("failed to stat {}{}", self.display_root, path),
                std::io::Error::from(e),
            )
        })?;
        let kind = FileType::from_raw_mode(stat.st_mode as rfs::RawMode);
        if kind != FileType::RegularFile {
            return Err(RsdebstrapError::Isolation(format!(
                "{}{} is a {:?}, refusing to detach it",
                self.display_root, path, kind
            )));
        }
        if stat.st_size as u64 > MAX_TAKE_SIZE {
            return Err(RsdebstrapError::Isolation(format!(
                "{}{} is {} bytes, refusing to detach an entry over {} bytes",
                self.display_root, path, stat.st_size, MAX_TAKE_SIZE
            )));
        }

        // Bounded on top of the size just read from this same inode: a descriptor opened
        // before the rename still writes to it, and an unbounded `read_to_end` would follow
        // the file as far as that writer takes it. The limit is what keeps a detached entry
        // small enough to hold in memory and to serialize over the helper channel.
        let mut content = Vec::new();
        File::from(fd)
            .take(MAX_TAKE_SIZE + 1)
            .read_to_end(&mut content)
            .map_err(|e| {
                RsdebstrapError::io(format!("failed to read {}{}", self.display_root, path), e)
            })?;
        if content.len() as u64 > MAX_TAKE_SIZE {
            return Err(RsdebstrapError::Isolation(format!(
                "{}{} grew past {} bytes while it was being read, refusing to detach it",
                self.display_root, path, MAX_TAKE_SIZE
            )));
        }

        Ok(TakenEntry::File {
            content,
            mode: FileMode::new(stat.st_mode),
            owner: Owner::of(&stat),
        })
    }

    /// Reads the symlink `detached` names, on a descriptor for the link itself.
    ///
    /// `O_PATH | O_NOFOLLOW` is the one way to hold a symlink open, and an empty path to
    /// `readlinkat` is how the target is read back off it. Whether that target resolves is
    /// deliberately not consulted: a dangling `/etc/resolv.conf` is the normal state of a
    /// systemd rootfs before `systemd-resolved` runs.
    fn read_detached_symlink(
        &self,
        dir: BorrowedFd<'_>,
        detached: &str,
        path: &RelPath,
    ) -> Result<TakenEntry> {
        let fd = rfs::openat(
            dir,
            detached,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| open_error(e, &format!("{}{}", self.display_root, path)))?;

        let stat = rfs::fstat(&fd).map_err(|e| {
            RsdebstrapError::io(
                format!("failed to stat {}{}", self.display_root, path),
                std::io::Error::from(e),
            )
        })?;
        let kind = FileType::from_raw_mode(stat.st_mode as rfs::RawMode);
        if kind != FileType::Symlink {
            return Err(RsdebstrapError::Isolation(format!(
                "{}{} is a {:?}, refusing to detach it",
                self.display_root, path, kind
            )));
        }

        let target = rfs::readlinkat(&fd, "", Vec::new()).map_err(|e| {
            RsdebstrapError::io(
                format!("failed to read symlink {}{}", self.display_root, path),
                std::io::Error::from(e),
            )
        })?;

        Ok(TakenEntry::Symlink {
            target: target.to_string_lossy().into_owned(),
            owner: Owner::of(&stat),
        })
    }

    /// Takes the whole [`RelPath`] rather than the final component it renames to, so the
    /// error names the entry the caller asked for: interpolating the component alone
    /// reported `<rootfs>/resolv.conf` for a write to `/etc/resolv.conf`.
    fn promote(&self, dir: BorrowedFd<'_>, staging: &str, path: &RelPath) -> Result<()> {
        rfs::renameat(dir, staging, dir, path.file_name()).map_err(|e| {
            let _ = rfs::unlinkat(dir, staging, AtFlags::empty());
            RsdebstrapError::io(
                format!("failed to install {}{}", self.display_root, path),
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

impl LocalRootfsOps {
    fn install_file(
        &self,
        path: &RelPath,
        content: &[u8],
        mode: FileMode,
        owner: Option<Owner>,
    ) -> Result<()> {
        let parent = self.parent_dir(path)?;
        let dir = parent.fd();
        let name = path.file_name();
        let staging = Self::staging_name(name);

        // Created owner-only rather than at `mode`: the staging entry is readable
        // at its own name for as long as the write takes, and nothing should be
        // able to read a half-written file that is about to become, say, a 0644
        // /etc/resolv.conf. `fchmod` below widens it once the content is final.
        let fd = rfs::openat(
            dir,
            staging.as_str(),
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
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
            if let Some(owner) = owner
                && Owner::of(&rfs::fstat(&file)?) != owner
            {
                rfs::fchown(&file, Some(Uid::from_raw(owner.uid)), Some(Gid::from_raw(owner.gid)))?;
            }
            // `openat`'s mode argument is masked by the process umask, so the mode
            // has to be set on the descriptor to land exactly. It also has to be set
            // *after* the write and the chown: both clear a file's setuid/setgid bits,
            // so a `put_back` restoring a setgid entry would silently drop them.
            rfs::fchmod(&file, Mode::from_raw_mode(mode.bits()))?;
            file.sync_all()?;
            Ok::<(), std::io::Error>(())
        })();
        if let Err(e) = write {
            let _ = rfs::unlinkat(dir, staging.as_str(), AtFlags::empty());
            return Err(RsdebstrapError::io(
                format!("failed to write {}{}", self.display_root, path),
                e,
            ));
        }

        self.promote(dir, &staging, path)
    }

    fn install_symlink(&self, path: &RelPath, target: &str, owner: Option<Owner>) -> Result<()> {
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

        // By name rather than by descriptor because a symlink cannot be opened to hold
        // one. The name is this call's own staging name, which no one else knows.
        if let Some(owner) = owner {
            let chowned = self.chown_if_different(dir, staging.as_str(), owner);
            if let Err(e) = chowned {
                let _ = rfs::unlinkat(dir, staging.as_str(), AtFlags::empty());
                return Err(RsdebstrapError::io(
                    format!("failed to restore ownership of {}{}", self.display_root, path),
                    std::io::Error::from(e),
                ));
            }
        }

        self.promote(dir, &staging, path)
    }

    /// Chowns the staged entry `name` in `dir` to `owner`, if it is not already there.
    ///
    /// The comparison is not an optimization. A setgid directory hands a staged entry the
    /// directory's group, which the caller need not be a member of, and `chown` refuses a
    /// group the caller cannot give away even when the call would change nothing. Asking
    /// only when the owner actually differs keeps that case out of the error path -- and
    /// leaves every `EPERM` that does reach it meaning what it says: the recorded owner
    /// was not restored, which `put_back` must not report as success.
    fn chown_if_different(
        &self,
        dir: BorrowedFd<'_>,
        name: &str,
        owner: Owner,
    ) -> rustix::io::Result<()> {
        let stat = rfs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if Owner::of(&stat) == owner {
            return Ok(());
        }
        rfs::chownat(
            dir,
            name,
            Some(Uid::from_raw(owner.uid)),
            Some(Gid::from_raw(owner.gid)),
            AtFlags::SYMLINK_NOFOLLOW,
        )
    }
}

impl RootfsOps for LocalRootfsOps {
    fn write_file(&self, path: &RelPath, content: &[u8], mode: FileMode) -> Result<()> {
        self.install_file(path, content, mode, None)
    }

    fn write_symlink(&self, path: &RelPath, target: &str) -> Result<()> {
        self.install_symlink(path, target, None)
    }

    fn put_back(&self, path: &RelPath, entry: &TakenEntry) -> Result<()> {
        match entry {
            TakenEntry::File {
                content,
                mode,
                owner,
            } => self.install_file(path, content, *mode, Some(*owner)),
            TakenEntry::Symlink { target, owner } => {
                self.install_symlink(path, target, Some(*owner))
            }
        }
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
        let detached = Self::staging_name(name);

        // Detach first, read second: this takes the caller's name out of play in one
        // syscall, so nothing that follows can be tricked into acting on whatever appears
        // at `/etc/resolv.conf` next. It does not make the new name secret -- a watcher on
        // the directory is told where a rename lands -- which is why `read_detached` binds
        // itself to a descriptor rather than trusting the name it was given. A `renameat`
        // on a missing entry is also how "it was not there" is reported, which keeps that
        // answer on the same syscall as the detach.
        match rfs::renameat(dir, name, dir, detached.as_str()) {
            Ok(()) => {}
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(e) => {
                return Err(RsdebstrapError::io(
                    format!("failed to detach {}{}", self.display_root, path),
                    std::io::Error::from(e),
                ));
            }
        }

        match self.read_detached(dir, &detached, path) {
            Ok(entry) => {
                rfs::unlinkat(dir, detached.as_str(), AtFlags::empty()).map_err(|e| {
                    RsdebstrapError::io(
                        format!(
                            "detached {}{} but failed to remove it from {}/{}",
                            self.display_root, path, self.display_root, detached
                        ),
                        std::io::Error::from(e),
                    )
                })?;
                Ok(Some(entry))
            }
            // Refusing to detach has to mean nothing was detached, so the rename goes back.
            // If that fails too, the entry exists only under a name the caller has never
            // seen, so the error has to name it.
            Err(refusal) => match rfs::renameat(dir, detached.as_str(), dir, name) {
                Ok(()) => Err(refusal),
                Err(e) => Err(RsdebstrapError::Isolation(format!(
                    "{refusal}; it is left detached at {}/{} because putting it back \
                    failed: {e}",
                    self.display_root, detached
                ))),
            },
        }
    }
}

/// [`RootfsOps`] that reports what it would do and changes nothing.
#[derive(Debug)]
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
    fn write_file(&self, path: &RelPath, content: &[u8], mode: FileMode) -> Result<()> {
        tracing::info!(
            "dry run: write {}{} ({} bytes, mode {})",
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

    fn remove(&self, path: &RelPath) -> Result<()> {
        tracing::info!("dry run: remove {}{}", self.rootfs, path);
        Ok(())
    }

    fn put_back(&self, path: &RelPath, _entry: &TakenEntry) -> Result<()> {
        tracing::info!("dry run: restore {}{}", self.rootfs, path);
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

    // Whoever runs the test owns what it creates, but a setgid directory would hand the
    // file a different group, so the expectation comes from the entry itself.
    fn owner_of(path: &Utf8Path) -> Owner {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(path).unwrap();
        Owner {
            uid: meta.uid(),
            gid: meta.gid(),
        }
    }

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

    // `openat`/`unlinkat` read a separator as another level of path and apply `O_NOFOLLOW`
    // only to the last one, so a component carrying one would escape the walk. `parse`
    // splitting on '/' is what makes that impossible, and it is the only constructor.
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

        ops.write_file(&path, b"nameserver 1.1.1.1\n", FileMode::new(0o644))
            .unwrap();
        let owner = owner_of(&root.join("etc/resolv.conf"));
        let taken = ops.take(&path).unwrap().unwrap();

        assert_eq!(
            taken,
            TakenEntry::File {
                content: b"nameserver 1.1.1.1\n".to_vec(),
                mode: FileMode::new(0o644),
                owner
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

        let owner = owner_of(&root.join("etc/resolv.conf"));
        let taken = ops.take(&path).unwrap().unwrap();
        assert_eq!(
            taken,
            TakenEntry::Symlink {
                target: "../run/systemd/resolve/stub-resolv.conf".to_string(),
                owner
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

    // Refusing has to leave the entry where it was found, under the name the caller knows
    // -- `take` detaches by renaming first, so a refusal is a rollback, not a no-op.
    fn etc_entries(root: &Utf8Path) -> Vec<String> {
        std::fs::read_dir(root.join("etc"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn take_refuses_an_oversized_file() {
        let (_tmp, root) = rootfs();
        let ops = LocalRootfsOps::open(&root).unwrap();
        let path = RelPath::parse("/etc/resolv.conf").unwrap();
        std::fs::write(root.join("etc/resolv.conf"), vec![b'x'; (MAX_TAKE_SIZE + 1) as usize])
            .unwrap();

        let err = ops.take(&path).unwrap_err().to_string();

        assert!(err.contains("refusing to detach"), "unexpected error: {err}");
        assert_eq!(etc_entries(&root), ["resolv.conf"], "refused but still detached");
    }

    // Anything that is not a regular file or a symlink has no in-memory representation
    // here, and a FIFO would additionally block the read it is opened for.
    #[test]
    fn take_refuses_a_fifo() {
        let (_tmp, root) = rootfs();
        let ops = LocalRootfsOps::open(&root).unwrap();
        rfs::mknodat(
            CWD,
            root.join("etc/resolv.conf").as_str(),
            FileType::Fifo,
            Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();

        let err = ops
            .take(&RelPath::parse("/etc/resolv.conf").unwrap())
            .unwrap_err()
            .to_string();

        assert!(err.contains("refusing to detach"), "unexpected error: {err}");
        assert_eq!(etc_entries(&root), ["resolv.conf"], "refused but still detached");
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
            .write_file(&RelPath::parse("/etc/resolv.conf").unwrap(), b"x", FileMode::new(0o644))
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
        ops.write_file(&RelPath::parse("/etc/resolv.conf").unwrap(), b"new", FileMode::new(0o644))
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

    // An error naming a path that does not exist sends the reader looking in the wrong
    // place, so `promote` interpolates the whole relative path onto the rootfs, not the
    // final component.
    //
    // The rename is provoked into failing by putting a directory at the target name, which
    // `renameat` refuses to replace with a file. Chmod would do it too, but not when the
    // suite runs as root, where the permission bits are bypassed.
    #[test]
    fn a_failed_install_names_the_full_path() {
        let (_tmp, root) = rootfs();
        let ops = LocalRootfsOps::open(&root).unwrap();
        std::fs::create_dir(root.join("etc/resolv.conf")).unwrap();

        let err = ops
            .write_file(&RelPath::parse("/etc/resolv.conf").unwrap(), b"x", FileMode::new(0o644))
            .unwrap_err()
            .to_string();

        assert!(err.contains("/etc/resolv.conf"), "unexpected error: {err}");
    }
}
