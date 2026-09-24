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

use camino::{Utf8Component, Utf8Path, Utf8PathBuf};
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

/// How much of a file one [`RootfsOps::export_file`] exchange with the privileged helper
/// carries.
///
/// A kernel is tens of megabytes and an initramfs can be over a hundred, and the helper
/// protocol is one JSON line per message with the bytes in base64. Sending the file as one
/// line would hold it several times over on both sides at once; chunks keep the peak at a
/// few of these regardless of the file.
pub(crate) const EXPORT_CHUNK_SIZE: u64 = 4 << 20;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct FileMode(u32);

// Hand-written rather than derived, because a derived one would build `FileMode(raw)`
// directly and skip `new`'s masking -- and every `FileMode` that crosses the helper channel
// is built by deserializing one. `33188` (a whole `st_mode` for a 0644 regular file) would
// arrive at the helper's `fchmod` as `0o100644` with the type bits still on it, so the
// type's only stated guarantee would hold for every value except the ones from outside this
// process.
impl<'de> Deserialize<'de> for FileMode {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        u32::deserialize(deserializer).map(Self::new)
    }
}

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
    ///
    /// The target is bytes, not a `String`, because that is what a link target is: the
    /// kernel stores whatever was passed to `symlinkat`, and nothing requires it to be
    /// UTF-8. Rendering it through `to_string_lossy` on the way in would replace those
    /// bytes with U+FFFD and restore a *different* link.
    Symlink {
        #[serde(with = "payload")]
        target: Vec<u8>,
        owner: Owner,
    },
}

/// What [`RootfsOps::export_file`] copied out of the rootfs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportedFile {
    /// The permission bits the file carried, for the copy to be given the same ones. An
    /// initramfs can hold key material, and Debian's is not world-readable for that reason.
    pub mode: FileMode,
    /// How many bytes were written to the sink.
    pub size: u64,
}

/// Which file, in which state, one [`Request::ReadChunk`](helper::Request::ReadChunk) read.
///
/// The helper resolves the path again for every chunk, because it holds no state between
/// requests. The stamp is what ties the chunks together: the parent sends back the one the
/// first chunk carried, and a later chunk whose file differs in any of these is refused
/// instead of spliced into the copy.
///
/// The change time is in it because the inode number alone is not an identity here. No
/// descriptor is held open between chunks, so a file removed and recreated can be handed
/// the same number -- and at the same size, nothing else would tell them apart. The kernel
/// sets the change time on every write and on creation, and a caller cannot set it back.
/// That narrows the case rather than closing it: the change time is only as fine as the
/// filesystem's timestamps, so a same-sized file recreated within one tick still matches.
/// What would close it is a descriptor held across requests, which is state the helper
/// does not keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStamp {
    dev: u64,
    ino: u64,
    size: u64,
    ctime: (i64, i64),
}

impl FileStamp {
    fn of(stat: &rfs::Stat) -> Self {
        Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
            size: stat.st_size as u64,
            // The field types differ between targets (the nanoseconds are unsigned on some),
            // so the casts are a no-op only on some of them.
            #[allow(clippy::unnecessary_cast)]
            ctime: (stat.st_ctime as i64, stat.st_ctime_nsec as i64),
        }
    }

    /// The file's size when it was stamped.
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// One piece of a file read for [`RootfsOps::export_file`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportChunk {
    pub stamp: FileStamp,
    pub mode: FileMode,
    #[serde(with = "payload")]
    pub data: Vec<u8>,
}

/// Mutations inside a rootfs.
///
/// Implemented in-process by [`LocalRootfsOps`] and, when the rootfs needs root
/// to modify, by a helper process holding the elevated descriptor.
pub trait RootfsOps: Send + Sync {
    /// Replaces `path` with a regular file carrying exactly `mode`, atomically.
    fn write_file(&self, path: &RelPath, content: &[u8], mode: FileMode) -> Result<()>;

    /// Replaces `path` with a symlink to `target`, atomically.
    ///
    /// `target` is bytes for the same reason [`TakenEntry::Symlink`] carries bytes: a link
    /// target is not required to be UTF-8, and one taken from a rootfs has to go back
    /// exactly as it came.
    fn write_symlink(&self, path: &RelPath, target: &[u8]) -> Result<()>;

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

    /// Copies the regular file `path` resolves to into `sink`, or returns `None` if it
    /// resolves to nothing.
    ///
    /// Unlike every other operation here, symlinks are followed -- `/vmlinuz` is one, and
    /// reading what it points at is the point -- but they are resolved as if the rootfs were
    /// `/`: an absolute target is reinterpreted against the rootfs and `..` at its top stays
    /// there, so no link can lead the read outside it. A dangling link is `None`, the same
    /// as an absent entry.
    ///
    /// Reads only. Nothing in the rootfs is changed, and the sink is the caller's: the copy
    /// lands wherever the caller writes it, which is outside the rootfs and so outside what
    /// a [`RelPath`] can name.
    fn export_file(&self, path: &RelPath, sink: &mut dyn Write) -> Result<Option<ExportedFile>>;

    /// Creates the directory `path` carrying exactly `mode`, unless one is already there.
    ///
    /// Returns `true` if it created the directory and `false` if a directory already
    /// existed. Anything else at `path` -- a symlink included, which is never followed -- is
    /// an error. Only the final component is created; its parent must exist.
    fn create_dir(&self, path: &RelPath, mode: FileMode) -> Result<bool>;

    /// Removes the directory `path` if it is empty.
    ///
    /// Returns `true` if it is gone (or was never there) and `false` if it still holds
    /// entries, in which case it is left alone. A symlink or a non-directory is an error.
    fn remove_dir(&self, path: &RelPath) -> Result<bool>;
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
    /// Every component is opened with `O_NOFOLLOW`, not just the last one. A single
    /// `openat` of the whole path applies `O_NOFOLLOW` to the final component only, so an
    /// intermediate directory swapped for a symlink is followed -- and this open is the one
    /// the privileged helper performs as root, on a path it was handed. Following one there
    /// anchors root inside the live system, somewhere the helper's refused-anchor list does
    /// not name: `/etc/ssh` is not `/etc`.
    ///
    /// Symlinks in the path a user configured are resolved once, without privilege, by
    /// [`rootfs::open`](open) before the helper is spawned. So refusing them here does not refuse a
    /// legitimate layout -- it refuses one that changed after that.
    ///
    /// # Errors
    ///
    /// Returns `RsdebstrapError::Isolation` if any component is a symlink or not a
    /// directory.
    pub fn open(rootfs: &Utf8Path) -> Result<Self> {
        Ok(Self {
            root: open_anchor(rootfs)?,
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

    /// Renders `path` as the operator would find it: the rootfs the way they named it,
    /// followed by the path inside it.
    fn at(&self, path: &RelPath) -> String {
        format!("{}{}", self.display_root, path)
    }

    /// Renders a staging sibling of `path`.
    ///
    /// The staging entry is created *next to* the entry it will replace, so rendering it
    /// against the rootfs root alone names a directory it was never in -- `<rootfs>/
    /// .resolv.conf.rsdebstrap-<uuid>` for a leftover that is really under `<rootfs>/etc`.
    /// These messages exist to tell an operator where the leftover is, which is the one
    /// thing that spelling cannot do.
    fn staging_at(&self, path: &RelPath, staging: &str) -> String {
        let mut out = self.display_root.clone();
        for component in path.parent_components() {
            out.push('/');
            out.push_str(component);
        }
        out.push('/');
        out.push_str(staging);
        out
    }

    /// The one place that decides how a failed syscall on a rootfs entry reads.
    fn io_err(&self, verb: &str, at: &str, e: rustix::io::Errno) -> RsdebstrapError {
        let _ = self;
        RsdebstrapError::io(format!("failed to {} {}", verb, at), std::io::Error::from(e))
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

    /// Reads the entry `name` holds in `dir`, before [`RootfsOps::take`] detaches it.
    ///
    /// Reading before the rename is what makes the rename checkable. Everything the
    /// returned entry carries comes off one descriptor, and the identity returned with it
    /// is that descriptor's -- so it names the inode that was still at the caller's name,
    /// which is the only thing a later `statat` on the detached name can honestly be
    /// compared against. Sampling the identity after the rename instead would let a watcher
    /// on the directory -- who is told where a rename lands -- substitute an entry there
    /// and have every check downstream agree about the substitute.
    ///
    /// Refusing here also refuses before anything has moved, so a FIFO or an oversized file
    /// leaves the caller's name exactly as it was, with no rollback to get wrong.
    ///
    /// That descriptor is returned along with what was read off it, because an inode number
    /// only identifies an inode while something still refers to it. With the descriptor
    /// closed, a watcher can unlink the entry, let the kernel hand the freed number to an
    /// inode it controls, and leave the `statat` in [`RootfsOps::take`] agreeing that the
    /// replacement is what was read. Holding it open is what keeps the number from being
    /// handed out again, so `take` keeps it until the entry is unlinked.
    ///
    /// `Ok(None)` is "there is nothing to take": an absent `/etc/resolv.conf` is the normal
    /// state of a fresh rootfs, not a failure.
    fn read_entry(
        &self,
        dir: BorrowedFd<'_>,
        name: &str,
        path: &RelPath,
    ) -> Result<Option<(TakenEntry, Identity, OwnedFd)>> {
        // `O_NONBLOCK` because opening a FIFO for reading otherwise waits for a writer that
        // is never coming -- for the privileged helper, that is the build hanging with no
        // output. It is `fstat` below, not this open, that refuses one.
        let opened = rfs::openat(
            dir,
            name,
            OFlags::NOFOLLOW | OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        );

        let fd = match opened {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            // The one type that cannot be opened for reading, and the reason the caller's
            // `/etc/resolv.conf` is being detached at all half the time.
            Err(rustix::io::Errno::LOOP) => return self.read_symlink(dir, name, path),
            Err(e) => return Err(open_error(e, &format!("{}{}", self.display_root, path))),
        };

        let stat = rfs::fstat(&fd).map_err(|e| self.io_err("stat", &self.at(path), e))?;
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

        // Bounded on top of the size just read from this same inode: the entry is still
        // linked at its own name here, so a writer can be appending to it, and an unbounded
        // `read_to_end` would follow the file as far as that writer takes it. The limit is
        // what keeps a detached entry small enough to hold in memory and to serialize over
        // the helper channel.
        let mut content = Vec::new();
        let mut reader = File::from(fd).take(MAX_TAKE_SIZE + 1);
        reader.read_to_end(&mut content).map_err(|e| {
            RsdebstrapError::io(format!("failed to read {}{}", self.display_root, path), e)
        })?;
        if content.len() as u64 > MAX_TAKE_SIZE {
            return Err(RsdebstrapError::Isolation(format!(
                "{}{} grew past {} bytes while it was being read, refusing to detach it",
                self.display_root, path, MAX_TAKE_SIZE
            )));
        }

        Ok(Some((
            TakenEntry::File {
                content,
                mode: FileMode::new(stat.st_mode),
                owner: Owner::of(&stat),
            },
            Identity::of(&stat),
            OwnedFd::from(reader.into_inner()),
        )))
    }

    /// Reads the symlink `name` holds, on a descriptor for the link itself.
    ///
    /// `O_PATH | O_NOFOLLOW` is the one way to hold a symlink open, and an empty path to
    /// `readlinkat` is how the target is read back off it. Whether that target resolves is
    /// deliberately not consulted: a dangling `/etc/resolv.conf` is the normal state of a
    /// systemd rootfs before `systemd-resolved` runs.
    fn read_symlink(
        &self,
        dir: BorrowedFd<'_>,
        name: &str,
        path: &RelPath,
    ) -> Result<Option<(TakenEntry, Identity, OwnedFd)>> {
        let fd = match rfs::openat(
            dir,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            // The link can have been removed between the two opens, which is the same
            // answer as its never having been there.
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(e) => return Err(open_error(e, &format!("{}{}", self.display_root, path))),
        };

        let stat = rfs::fstat(&fd).map_err(|e| self.io_err("stat", &self.at(path), e))?;
        let kind = FileType::from_raw_mode(stat.st_mode as rfs::RawMode);
        if kind != FileType::Symlink {
            return Err(RsdebstrapError::Isolation(format!(
                "{}{} is a {:?}, refusing to detach it",
                self.display_root, path, kind
            )));
        }

        let target = rfs::readlinkat(&fd, "", Vec::new())
            .map_err(|e| self.io_err("read symlink", &self.at(path), e))?;

        Ok(Some((
            TakenEntry::Symlink {
                target: target.into_bytes(),
                owner: Owner::of(&stat),
            },
            Identity::of(&stat),
            fd,
        )))
    }

    /// Publishes the staged entry under the caller's name.
    ///
    /// `staged` is a descriptor for the inode that was staged, checked against what the
    /// staging name means now. A UUID does not make the name unguessable to anyone watching
    /// the directory, and `renameat` takes names on both sides -- Linux has no
    /// rename-by-descriptor -- so this is a check rather than a binding: it narrows the
    /// window to these two calls, and what it rules out is publishing someone else's inode
    /// under a name the caller trusts.
    ///
    /// It takes the descriptor rather than an [`Identity`] the caller sampled earlier so
    /// that the caller cannot have let go of it. An inode number identifies an inode only
    /// while something refers to it: with the staged descriptor closed, a watcher could
    /// unlink the staged entry, have the freed number handed to an entry of their own, and
    /// leave the comparison below agreeing about the substitute.
    ///
    /// Takes the whole [`RelPath`] rather than the final component it renames to, so the
    /// error names the entry the caller asked for: interpolating the component alone
    /// reported `<rootfs>/resolv.conf` for a write to `/etc/resolv.conf`.
    fn promote(
        &self,
        dir: BorrowedFd<'_>,
        staging: &str,
        path: &RelPath,
        staged: BorrowedFd<'_>,
    ) -> Result<()> {
        let staged = rfs::fstat(staged)
            .map(|s| Identity::of(&s))
            .map_err(|e| self.io_err("stat the entry staged for", &self.at(path), e))?;
        let current = rfs::statat(dir, staging, AtFlags::SYMLINK_NOFOLLOW)
            .map(|current| Identity::of(&current))
            .map_err(|e| self.io_err("stat", &self.staging_at(path, staging), e))?;
        // Left in place rather than unlinked: the name means someone else's entry now, and
        // removing it is no more ours to do than publishing it was.
        if current != staged {
            return Err(RsdebstrapError::Isolation(format!(
                "{} was replaced while {} was being staged, refusing to install it",
                self.staging_at(path, staging),
                self.at(path)
            )));
        }

        rfs::renameat(dir, staging, dir, path.file_name()).map_err(|e| {
            let _ = rfs::unlinkat(dir, staging, AtFlags::empty());
            self.io_err("install", &self.at(path), e)
        })
    }
}

/// Which inode a syscall landed on.
///
/// Content and metadata always come off a descriptor, which cannot be pointed elsewhere.
/// This is for the steps that cannot: Linux has no rename-by-descriptor and no
/// unlink-by-descriptor, so `promote`'s publish and `take`'s detach and removal have to
/// name their target, and comparing what the name means now against what a descriptor
/// already established is all that is left there.
///
/// Which makes where the value is sampled the whole point. It has to come from a
/// descriptor opened before the syscall that a watcher of the directory is told about --
/// an identity read back afterwards describes whatever is there by then, and agrees with
/// itself no matter who put it there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
}

impl Identity {
    fn of(stat: &rfs::Stat) -> Self {
        Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
        }
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

/// Opens `rootfs` as a directory descriptor, following nothing on the way.
///
/// A single `openat` of a whole path applies `O_NOFOLLOW` to the final component only, so an
/// intermediate directory swapped for a symlink is followed. This is the open the privileged
/// helper performs as root on a path it was handed, and following one there anchors root
/// wherever the link points -- inside the live system at a depth the refused-anchor list,
/// which names the top of each hierarchy, does not reach.
///
/// Shared with the direct-execution backend, which walks a program inside the rootfs and
/// would otherwise start that walk from a redirected anchor.
///
/// Symlinks the invoking user legitimately has on the way are resolved by
/// [`resolve_prefix`], unprivileged, before any of this runs.
pub(crate) fn open_anchor(rootfs: &Utf8Path) -> Result<OwnedFd> {
    let mut current: Option<OwnedFd> = None;
    let mut walked = String::new();
    for component in rootfs.components() {
        let (name, flags) = match component {
            // The one component that cannot be a symlink, and the one that has to be opened
            // against `CWD` rather than against a descriptor.
            Utf8Component::RootDir => ("/", OFlags::empty()),
            Utf8Component::CurDir => continue,
            // Walked rather than refused: every descriptor in the chain was opened
            // `O_NOFOLLOW`, so `..` can only lead to the real parent of a real directory.
            Utf8Component::ParentDir => ("..", OFlags::NOFOLLOW),
            Utf8Component::Normal(name) => (name, OFlags::NOFOLLOW),
            Utf8Component::Prefix(_) => {
                return Err(RsdebstrapError::Isolation(format!(
                    "refusing to anchor to {}: it names a filesystem prefix",
                    rootfs
                )));
            }
        };
        if !walked.ends_with('/') {
            walked.push('/');
        }
        if name != "/" {
            walked.push_str(name);
        }
        let dir = current.as_ref().map_or(CWD, |fd| fd.as_fd());
        let next = rfs::openat(
            dir,
            name,
            flags | OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| open_error(e, &walked))?;
        current = Some(next);
    }

    current.ok_or_else(|| {
        RsdebstrapError::Isolation(format!("refusing to anchor to {}: it names nothing", rootfs))
    })
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
        .map_err(|e| self.io_err("stage", &self.at(path), e))?;

        // Held past `promote` rather than dropped with the write: the identity `promote`
        // checks is an inode number, and one of those names an inode only while something
        // refers to it.
        let mut file = File::from(fd);
        let write = (|| {
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

        self.promote(dir, &staging, path, file.as_fd())
    }

    fn install_symlink(&self, path: &RelPath, target: &[u8], owner: Option<Owner>) -> Result<()> {
        let parent = self.parent_dir(path)?;
        let dir = parent.fd();
        let name = path.file_name();
        let staging = Self::staging_name(name);

        rfs::symlinkat(target, dir, staging.as_str())
            .map_err(|e| self.io_err("stage symlink", &self.at(path), e))?;

        // Checked before the chown, not after. There is no syscall that creates a symlink
        // and hands back a descriptor, and the staging name is not a secret -- a watcher on
        // the directory is told about the creation -- so what sits at that name is a
        // question until this opens it. Chowning by name first would answer it with a
        // privileged mutation: a hard link planted there would be the inode whose ownership
        // changed, and the refusal would arrive after the damage.
        let (staged, stat) = self.verify_staged_symlink(dir, &staging, path, target)?;

        if let Some(owner) = owner
            && let Err(e) = Self::chown_if_different(staged.as_fd(), &stat, owner)
        {
            let _ = rfs::unlinkat(dir, staging.as_str(), AtFlags::empty());
            return Err(self.io_err("restore ownership of", &self.at(path), e));
        }

        self.promote(dir, &staging, path, staged.as_fd())
    }

    /// Checks that `staging` is the symlink this call meant to publish, and returns the
    /// descriptor it checked.
    ///
    /// `install_file` binds: `O_CREAT | O_EXCL` hands back a descriptor, and the content,
    /// the mode and the owner all land on it. Creating a symlink hands back nothing to hold,
    /// and the staging name is announced to anyone watching the directory, so an inode
    /// substituted between the `symlinkat` and here would be described by any identity
    /// sampled afterwards -- and would agree with itself all the way to the rename.
    ///
    /// What makes checking sufficient here rather than merely narrowing is that a symlink
    /// has nothing else to it. Its target is fixed at creation -- no syscall edits one in
    /// place -- so a link that is a symlink and points where this call asked is not *like*
    /// the one that was staged, it is indistinguishable from it once the owner this call
    /// restores is put on it. Both checks come off one `O_PATH | O_NOFOLLOW` descriptor,
    /// which is what the chown and then [`Self::promote`] operate through -- the descriptor
    /// rather than the identity read off it, so that the inode it names cannot be freed and
    /// its number reused between here and there.
    ///
    /// The owner is not among the checks because it is not yet established: the caller
    /// chowns *through* the descriptor this returns, and doing that first would mean a
    /// privileged mutation landing on whatever the staging name happened to mean.
    ///
    /// A mismatch leaves the entry alone: the name means someone else's link at that point,
    /// and removing it is no more this call's business than publishing it was.
    fn verify_staged_symlink(
        &self,
        dir: BorrowedFd<'_>,
        staging: &str,
        path: &RelPath,
        target: &[u8],
    ) -> Result<(OwnedFd, rfs::Stat)> {
        let mismatch = |what: &str| {
            Err(RsdebstrapError::Isolation(format!(
                "{} is not the symlink staged for {} ({}), refusing to install it",
                self.staging_at(path, staging),
                self.at(path),
                what
            )))
        };

        let fd = rfs::openat(
            dir,
            staging,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| open_error(e, &self.staging_at(path, staging)))?;

        let stat =
            rfs::fstat(&fd).map_err(|e| self.io_err("stat", &self.staging_at(path, staging), e))?;
        if FileType::from_raw_mode(stat.st_mode as rfs::RawMode) != FileType::Symlink {
            return mismatch("no longer a symlink");
        }
        let staged_target = rfs::readlinkat(&fd, "", Vec::new())
            .map_err(|e| self.io_err("read symlink", &self.staging_at(path, staging), e))?;
        if staged_target.as_bytes() != target {
            return mismatch("wrong target");
        }

        Ok((fd, stat))
    }

    /// Chowns the entry `staged` refers to, if `stat` does not already show it there.
    ///
    /// Takes the descriptor and the `fstat` already read off it rather than a name in a
    /// directory: this is a privileged mutation, and a name would let it land on an entry
    /// substituted since the checks ran. `AT_EMPTY_PATH` against an `O_PATH` descriptor is
    /// the form that operates on an inode rather than on a path.
    ///
    /// The comparison is not an optimization. A setgid directory hands a staged entry the
    /// directory's group, which the caller need not be a member of, and `chown` refuses a
    /// group the caller cannot give away even when the call would change nothing. Asking
    /// only when the owner actually differs keeps that case out of the error path -- and
    /// leaves every `EPERM` that does reach it meaning what it says: the recorded owner
    /// was not restored, which `put_back` must not report as success.
    fn chown_if_different(
        staged: BorrowedFd<'_>,
        stat: &rfs::Stat,
        owner: Owner,
    ) -> rustix::io::Result<()> {
        if Owner::of(stat) == owner {
            return Ok(());
        }
        rfs::chownat(
            staged,
            "",
            Some(Uid::from_raw(owner.uid)),
            Some(Gid::from_raw(owner.gid)),
            AtFlags::EMPTY_PATH,
        )
    }
}

impl LocalRootfsOps {
    /// Opens the regular file `path` resolves to inside the rootfs, following symlinks
    /// without letting them leave it. `None` if it resolves to nothing.
    ///
    /// `openat2` with `RESOLVE_IN_ROOT` makes the confinement the kernel's rather than a
    /// walk of ours, the same way direct execution resolves a program: the anchor is the
    /// resolution root, so an absolute link target is reinterpreted against it and `..` at
    /// the top stays there. `RESOLVE_NO_MAGICLINKS` on top, because a `/proc/self/fd` entry
    /// names an inode resolution never walked to. There is no fallback for a kernel without
    /// `openat2`: the confinement is the check, and following links without it is the thing
    /// being refused.
    ///
    /// `O_NONBLOCK` for the reason `read_entry` gives: a FIFO at the end of the link would
    /// otherwise hang the build in `open`, before `fstat` could refuse it.
    fn open_resolved(&self, path: &RelPath) -> Result<Option<(OwnedFd, rfs::Stat)>> {
        let fd = match rfs::openat2(
            &self.root,
            path.components().join("/"),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            rfs::ResolveFlags::IN_ROOT | rfs::ResolveFlags::NO_MAGICLINKS,
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(rustix::io::Errno::NOSYS) => {
                return Err(RsdebstrapError::Isolation(format!(
                    "cannot resolve {}: openat2(RESOLVE_IN_ROOT) is unavailable on this \
                    kernel (Linux 5.6 or newer), and a symlink cannot be confined to the \
                    rootfs without it",
                    self.at(path)
                )));
            }
            Err(e) => return Err(self.io_err("open", &self.at(path), e)),
        };

        let stat = rfs::fstat(&fd).map_err(|e| self.io_err("stat", &self.at(path), e))?;
        let kind = FileType::from_raw_mode(stat.st_mode as rfs::RawMode);
        if kind != FileType::RegularFile {
            return Err(RsdebstrapError::Isolation(format!(
                "{} resolves to a {:?}, refusing to export it",
                self.at(path),
                kind
            )));
        }
        Ok(Some((fd, stat)))
    }

    /// Reads up to [`EXPORT_CHUNK_SIZE`] bytes at `offset` of the file `path` resolves to.
    ///
    /// The privileged helper's side of [`RootfsOps::export_file`]. It holds nothing between
    /// requests, so each chunk resolves `path` afresh, and `expect` -- the stamp the first
    /// chunk carried -- is what keeps a file repointed or rewritten in between from being
    /// spliced into one copy.
    ///
    /// A chunk shorter than the stamped size says is an error rather than the end of the
    /// file: the size came off the descriptor this read, so fewer bytes means the file was
    /// truncated under the read.
    pub(crate) fn read_chunk(
        &self,
        path: &RelPath,
        offset: u64,
        expect: Option<FileStamp>,
    ) -> Result<Option<ExportChunk>> {
        let Some((fd, stat)) = self.open_resolved(path)? else {
            return match expect {
                None => Ok(None),
                Some(_) => Err(self.changed_under_export(path)),
            };
        };
        let stamp = FileStamp::of(&stat);
        if expect.is_some_and(|expected| expected != stamp) {
            return Err(self.changed_under_export(path));
        }

        let want = stamp.size.saturating_sub(offset).min(EXPORT_CHUNK_SIZE);
        let mut data = vec![0; want as usize];
        let mut filled = 0;
        while filled < data.len() {
            match rustix::io::pread(&fd, &mut data[filled..], offset + filled as u64) {
                Ok(0) => return Err(self.changed_under_export(path)),
                Ok(n) => filled += n,
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => return Err(self.io_err("read", &self.at(path), e)),
            }
        }

        Ok(Some(ExportChunk {
            stamp,
            mode: FileMode::new(stat.st_mode),
            data,
        }))
    }

    fn changed_under_export(&self, path: &RelPath) -> RsdebstrapError {
        RsdebstrapError::Isolation(format!(
            "{} changed while it was being exported, refusing to finish a copy of two \
            different files",
            self.at(path)
        ))
    }
}

impl RootfsOps for LocalRootfsOps {
    fn write_file(&self, path: &RelPath, content: &[u8], mode: FileMode) -> Result<()> {
        self.install_file(path, content, mode, None)
    }

    fn write_symlink(&self, path: &RelPath, target: &[u8]) -> Result<()> {
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
            Err(e) => Err(self.io_err("remove", &self.at(path), e)),
        }
    }

    fn take(&self, path: &RelPath) -> Result<Option<TakenEntry>> {
        let parent = self.parent_dir(path)?;
        let dir = parent.fd();
        let name = path.file_name();

        // Read first, detach second. The rename below is the step that takes the caller's
        // name out of play, but it is also the step a watcher on the directory is told
        // about, so it needs something to be checked against that the watcher cannot have
        // chosen: the identity of the descriptor this opened while the entry was still the
        // caller's. Every refusal is behind us by then, so there is no rollback rename to
        // aim at the wrong inode either.
        let Some((entry, taken, read_fd)) = self.read_entry(dir, name, path)? else {
            return Ok(None);
        };

        let detached = Self::staging_name(name);
        rfs::renameat(dir, name, dir, detached.as_str())
            .map_err(|e| self.io_err("detach", &self.at(path), e))?;

        // A check rather than a binding, twice over: Linux has neither rename-by-descriptor
        // nor unlink-by-descriptor, so both syscalls here can only be given a name. What
        // this rules out is the silent form -- reporting an entry as taken while a different
        // one was moved, and removing something other than what was returned. It can rule
        // that out only because `read_fd` is still open: a closed descriptor would let the
        // read inode's number be freed and handed to an entry a watcher planted here, and
        // this comparison would then agree about the wrong inode.
        //
        // Nothing is put back and nothing is removed when it does not hold: the name means
        // someone else's entry at that point, and neither publishing it under the caller's
        // name nor deleting it is ours to do.
        let current = rfs::statat(dir, detached.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map(|current| Identity::of(&current))
            .map_err(|e| self.io_err("stat", &self.staging_at(path, detached.as_str()), e))?;
        if current != taken {
            return Err(RsdebstrapError::Isolation(format!(
                "{} was replaced while it was being detached: {} is not the entry \
                that was read, so it was left there",
                self.at(path),
                self.staging_at(path, &detached)
            )));
        }

        rfs::unlinkat(dir, detached.as_str(), AtFlags::empty()).map_err(|e| {
            RsdebstrapError::io(
                format!(
                    "detached {} but failed to remove it from {}",
                    self.at(path),
                    self.staging_at(path, &detached)
                ),
                std::io::Error::from(e),
            )
        })?;

        // Held open from the read until here. Past this point the entry has no name left
        // and nothing compares its identity, so the number is free to be reused.
        drop(read_fd);
        Ok(Some(entry))
    }

    fn export_file(&self, path: &RelPath, sink: &mut dyn Write) -> Result<Option<ExportedFile>> {
        let Some((fd, stat)) = self.open_resolved(path)? else {
            return Ok(None);
        };

        // Exactly the size `fstat` reported on this descriptor, and a short read is an
        // error: a file that grows or shrinks while it is copied is not the file that was
        // opened, and a copy that silently stopped early would boot as a truncated kernel.
        let size = stat.st_size as u64;
        let copied = std::io::copy(&mut File::from(fd).take(size), sink)
            .map_err(|e| RsdebstrapError::io(format!("failed to export {}", self.at(path)), e))?;
        if copied != size {
            return Err(self.changed_under_export(path));
        }
        Ok(Some(ExportedFile {
            mode: FileMode::new(stat.st_mode),
            size,
        }))
    }

    fn create_dir(&self, path: &RelPath, mode: FileMode) -> Result<bool> {
        let parent = self.parent_dir(path)?;
        let dir = parent.fd();
        let name = path.file_name();

        if self.existing_dir(dir, name, path)? {
            return Ok(false);
        }

        // Built under a staging name and published with a no-replace rename, for the reasons
        // `install_file` stages a file: the directory never exists at its own name with a
        // mode other than `mode`, and whatever appears at that name in the meantime -- a
        // symlink planted to redirect the next write into it -- makes the rename fail
        // rather than be followed or replaced.
        let staging = Self::staging_name(name);
        rfs::mkdirat(dir, staging.as_str(), Mode::from_raw_mode(0o700))
            .map_err(|e| self.io_err("stage directory", &self.at(path), e))?;
        let chmod = rfs::openat(
            dir,
            staging.as_str(),
            OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        // `mkdirat`'s mode is masked by the umask, so it is set on the descriptor to land
        // exactly, as `install_file` does for a file.
        .and_then(|fd| rfs::fchmod(&fd, Mode::from_raw_mode(mode.bits())));
        let published = chmod.and_then(|()| {
            rfs::renameat_with(dir, staging.as_str(), dir, name, rfs::RenameFlags::NOREPLACE)
        });
        match published {
            Ok(()) => Ok(true),
            Err(e) => {
                let _ = rfs::unlinkat(dir, staging.as_str(), AtFlags::REMOVEDIR);
                // Lost a race to something created at the name after the check above: it
                // is judged the same way an entry found there up front would be.
                if e == rustix::io::Errno::EXIST && self.existing_dir(dir, name, path)? {
                    return Ok(false);
                }
                Err(self.io_err("create directory", &self.at(path), e))
            }
        }
    }

    fn remove_dir(&self, path: &RelPath) -> Result<bool> {
        let parent = self.parent_dir(path)?;
        // `AT_REMOVEDIR` does not follow a symlink at the final component; it fails with
        // `ENOTDIR` instead, which is the refusal wanted here.
        match rfs::unlinkat(parent.fd(), path.file_name(), AtFlags::REMOVEDIR) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(true),
            Err(rustix::io::Errno::NOTEMPTY | rustix::io::Errno::EXIST) => Ok(false),
            Err(e) => Err(self.io_err("remove directory", &self.at(path), e)),
        }
    }
}

impl LocalRootfsOps {
    /// Whether `name` in `dir` is an existing directory: `false` if nothing is there, an
    /// error if something other than a directory is.
    fn existing_dir(&self, dir: BorrowedFd<'_>, name: &str, path: &RelPath) -> Result<bool> {
        match rfs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => Ok(true),
                FileType::Symlink => Err(RsdebstrapError::Isolation(format!(
                    "{} is a symlink, refusing to use it as a directory \
                    (possible symlink attack)",
                    self.at(path)
                ))),
                _ => Err(RsdebstrapError::Isolation(format!(
                    "{} exists and is not a directory",
                    self.at(path)
                ))),
            },
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(e) => Err(self.io_err("stat", &self.at(path), e)),
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

    fn write_symlink(&self, path: &RelPath, target: &[u8]) -> Result<()> {
        // Lossy because this is the one place the target is *displayed* rather than
        // written; the byte form is what every other path carries.
        tracing::info!(
            "dry run: symlink {}{} -> {}",
            self.rootfs,
            path,
            String::from_utf8_lossy(target)
        );
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

    fn export_file(&self, path: &RelPath, _sink: &mut dyn Write) -> Result<Option<ExportedFile>> {
        // An error rather than a made-up mode and size: a dry run may have no rootfs to
        // read, and callers check `dry_run()` before exporting, so reaching this is a bug
        // that should say so rather than report a zero-byte copy as done.
        Err(RsdebstrapError::Isolation(format!(
            "dry run: refusing to export {}{}, there is nothing to read",
            self.rootfs, path
        )))
    }

    fn create_dir(&self, path: &RelPath, mode: FileMode) -> Result<bool> {
        tracing::info!("dry run: create directory {}{} (mode {})", self.rootfs, path, mode);
        // Nothing was created, so nothing is removed on teardown.
        Ok(false)
    }

    fn remove_dir(&self, path: &RelPath) -> Result<bool> {
        tracing::info!("dry run: remove directory {}{}", self.rootfs, path);
        Ok(true)
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

    // The one place a symlink on the way to the rootfs is followed, and it is here rather
    // than in the helper because here is unprivileged. `/srv/build` may legitimately be
    // reached through a symlinked `/home`; what must not happen is root resolving that
    // indirection, where a component swapped since bootstrap redirects the anchor into the
    // live system. So the *prefix* is resolved once, here, and `LocalRootfsOps::open` --
    // which is what runs as root -- follows nothing.
    //
    // The final component is left unresolved on purpose. A rootfs that is itself a symlink
    // is refused, as it always has been: resolving it here would turn that refusal into a
    // redirection, and the helper's refused-anchor list names the top of the live system,
    // not every directory under it.
    let resolved = resolve_prefix(rootfs);

    match privilege {
        Some(method) => Ok(Arc::new(helper::PrivilegedRootfsOps::spawn(&resolved, method)?)),
        None => Ok(Arc::new(LocalRootfsOps::open(&resolved)?)),
    }
}

/// Resolves everything in `rootfs` except its final component.
///
/// Returns the path unchanged when there is nothing to resolve or the prefix cannot be
/// resolved -- a rootfs that has not been bootstrapped yet is the ordinary case of the
/// latter, and a dry run never creates one. Failing here would turn "the directory is not
/// there" into an error raised before the phase that would have said so.
///
/// Giving up is safe because it is not what enforces anything: [`open_anchor`] refuses a
/// symlink either way. All this decides is whether a link the user legitimately has on the
/// way is honoured or refused, and an unresolvable prefix is refused.
pub(crate) fn resolve_prefix(rootfs: &Utf8Path) -> Utf8PathBuf {
    let (Some(parent), Some(name)) = (rootfs.parent(), rootfs.file_name()) else {
        return rootfs.to_owned();
    };
    // `Utf8Path::parent` of a bare `rootfs` is the empty path, which names nothing.
    let parent = if parent.as_str().is_empty() {
        Utf8Path::new(".")
    } else {
        parent
    };
    match parent.canonicalize_utf8() {
        Ok(resolved) => resolved.join(name),
        Err(e) => {
            tracing::debug!("leaving rootfs {} unresolved: {}", rootfs, e);
            rootfs.to_owned()
        }
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
    fn create_dir_creates_the_directory_once() {
        let (_tmp, root) = rootfs();
        let ops = LocalRootfsOps::open(&root).unwrap();
        let path = RelPath::parse("/etc/keyrings").unwrap();

        assert!(ops.create_dir(&path, FileMode::new(0o755)).unwrap());
        assert!(root.join("etc/keyrings").is_dir());
        assert!(
            !ops.create_dir(&path, FileMode::new(0o755)).unwrap(),
            "an existing directory is reported as not created"
        );
        let leftovers: Vec<_> = std::fs::read_dir(root.join("etc"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, ["keyrings"], "no staging entry may be left behind");
    }

    // The case the operation exists to get right under privilege: adopting the link as the
    // directory would send every write into it wherever the link points.
    #[test]
    fn create_dir_refuses_a_symlink_at_the_name() {
        let (tmp, root) = rootfs();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join("etc/keyrings")).unwrap();
        let ops = LocalRootfsOps::open(&root).unwrap();

        let err = ops
            .create_dir(&RelPath::parse("/etc/keyrings").unwrap(), FileMode::new(0o755))
            .unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[test]
    fn create_dir_refuses_a_file_at_the_name() {
        let (_tmp, root) = rootfs();
        std::fs::write(root.join("etc/keyrings"), b"").unwrap();
        let ops = LocalRootfsOps::open(&root).unwrap();

        let err = ops
            .create_dir(&RelPath::parse("/etc/keyrings").unwrap(), FileMode::new(0o755))
            .unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err}");
    }

    #[test]
    fn create_dir_refuses_a_symlink_on_the_way() {
        let (tmp, root) = rootfs();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join("etc/apt")).unwrap();
        let ops = LocalRootfsOps::open(&root).unwrap();

        assert!(
            ops.create_dir(&RelPath::parse("/etc/apt/keyrings").unwrap(), FileMode::new(0o755))
                .is_err()
        );
        assert!(!elsewhere.join("keyrings").exists());
    }

    #[test]
    fn remove_dir_removes_only_an_empty_directory() {
        let (_tmp, root) = rootfs();
        let ops = LocalRootfsOps::open(&root).unwrap();
        let path = RelPath::parse("/etc/keyrings").unwrap();
        std::fs::create_dir(root.join("etc/keyrings")).unwrap();
        std::fs::write(root.join("etc/keyrings/k.asc"), b"").unwrap();

        assert!(!ops.remove_dir(&path).unwrap(), "a non-empty directory is left alone");
        assert!(root.join("etc/keyrings/k.asc").exists());

        std::fs::remove_file(root.join("etc/keyrings/k.asc")).unwrap();
        assert!(ops.remove_dir(&path).unwrap());
        assert!(!root.join("etc/keyrings").exists());
        assert!(ops.remove_dir(&path).unwrap(), "an absent directory counts as removed");
    }

    #[test]
    fn remove_dir_refuses_a_symlink() {
        let (tmp, root) = rootfs();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join("etc/keyrings")).unwrap();
        let ops = LocalRootfsOps::open(&root).unwrap();

        assert!(
            ops.remove_dir(&RelPath::parse("/etc/keyrings").unwrap())
                .is_err()
        );
        assert!(elsewhere.exists());
        assert!(std::fs::symlink_metadata(root.join("etc/keyrings")).is_ok());
    }

    // `O_NOFOLLOW` on a whole-path `openat` covers the final component only, so this walks
    // them. The helper performs this open as root on a path handed to it, and a component
    // swapped for a symlink would otherwise anchor root wherever it points -- inside the
    // live system at a path the refused-anchor list does not name.
    #[test]
    fn open_refuses_a_symlink_in_the_middle_of_the_anchor() {
        let tmp = tempfile::tempdir().unwrap();
        let base = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(base.join("real/rootfs")).unwrap();
        std::os::unix::fs::symlink("real", base.join("link")).unwrap();

        let err = LocalRootfsOps::open(&base.join("link/rootfs")).unwrap_err();

        assert!(err.to_string().contains("symlink"), "unexpected error: {err}");
        assert!(
            err.to_string().contains("/link"),
            "the error should name the component that was refused: {err}"
        );
    }

    // The refusal above is not a restriction on what a user may configure: `open` resolves
    // the prefix once, unprivileged, before spawning the helper that cannot resolve it.
    #[test]
    fn open_resolves_a_symlinked_anchor_before_anchoring_to_it() {
        let tmp = tempfile::tempdir().unwrap();
        let base = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(base.join("real/rootfs/etc")).unwrap();
        std::os::unix::fs::symlink("real", base.join("link")).unwrap();

        let ops = open(&base.join("link/rootfs"), None, false).unwrap();
        ops.write_file(
            &RelPath::parse("/etc/resolv.conf").unwrap(),
            b"nameserver 1.1.1.1\n",
            FileMode::new(0o644),
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(base.join("real/rootfs/etc/resolv.conf")).unwrap(),
            "nameserver 1.1.1.1\n"
        );
    }

    // Only the prefix, though. Resolving the last component too would turn the refusal that
    // `opening_a_symlinked_rootfs_is_refused` pins into a redirection -- and a link aimed
    // one level inside the live system lands somewhere the refused-anchor list, which names
    // only the top of each hierarchy, would let through.
    #[test]
    fn open_does_not_resolve_a_rootfs_that_is_itself_a_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let base = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(base.join("real")).unwrap();
        std::os::unix::fs::symlink("real", base.join("rootfs")).unwrap();

        let Err(err) = open(&base.join("rootfs"), None, false) else {
            panic!("a rootfs that is a symlink should be refused, not followed");
        };

        assert!(err.to_string().contains("symlink"), "unexpected error: {err}");
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
                target: b"../run/systemd/resolve/stub-resolv.conf".to_vec(),
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

    // A link target is whatever bytes were handed to `symlinkat`, and the kernel does not
    // ask for UTF-8. Carrying it as a `String` meant `to_string_lossy` replaced anything
    // else with U+FFFD, so `put_back` restored a different link than the one taken.
    #[test]
    fn take_preserves_a_symlink_target_that_is_not_utf8() {
        use std::os::unix::ffi::OsStrExt;

        let (_tmp, root) = rootfs();
        let ops = LocalRootfsOps::open(&root).unwrap();
        let path = RelPath::parse("/etc/resolv.conf").unwrap();
        let target = b"../run/\xff\xfe/resolv.conf";
        std::os::unix::fs::symlink(
            std::ffi::OsStr::from_bytes(target),
            root.join("etc/resolv.conf"),
        )
        .unwrap();

        let taken = ops.take(&path).unwrap().unwrap();
        ops.put_back(&path, &taken).unwrap();

        let restored = std::fs::read_link(root.join("etc/resolv.conf")).unwrap();
        assert_eq!(restored.as_os_str().as_bytes(), target);
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

    // Every `FileMode` the privileged helper acts on is decoded from the channel, and a
    // derived `Deserialize` would build one without going through `new` -- so a whole
    // `st_mode` would arrive with its type bits still set. `33188` is `0o100644`: a regular
    // file at 0644.
    //
    // The kernel masks `chmod` to the permission bits, so nothing lands wrong today. What
    // this pins is the guarantee the type states, which any `bits()` consumer that is not
    // `chmod` would otherwise inherit as false -- `DryRunRootfsOps::write_file` already
    // prints it.
    #[test]
    fn a_file_mode_decoded_from_a_whole_st_mode_keeps_only_its_permission_bits() {
        let decoded: FileMode = serde_json::from_str("33188").expect("a mode is a u32");

        assert_eq!(decoded, FileMode::new(0o644));
        assert_eq!(format!("{decoded}"), "644");
    }

    // And the round trip a request really makes is lossless for a value that was already
    // permissions, setuid and sticky bits included -- `new` masks off the type bits, not
    // these.
    #[test]
    fn a_file_mode_round_trips_through_the_channel_encoding() {
        let mode = FileMode::new(0o4755);
        let encoded = serde_json::to_string(&mode).unwrap();

        assert_eq!(serde_json::from_str::<FileMode>(&encoded).unwrap(), mode);
    }

    // Debian's kernel packages leave `/vmlinuz` as a link to the versioned image in `/boot`,
    // relative on current releases and absolute on older ones. Both have to reach the file.
    #[test]
    fn export_follows_a_link_to_the_versioned_kernel() {
        let (_tmp, root) = rootfs();
        std::fs::create_dir(root.join("boot")).unwrap();
        std::fs::write(root.join("boot/vmlinuz-6.12.0-amd64"), b"kernel image").unwrap();
        std::os::unix::fs::symlink("boot/vmlinuz-6.12.0-amd64", root.join("vmlinuz")).unwrap();
        std::os::unix::fs::symlink("/boot/vmlinuz-6.12.0-amd64", root.join("vmlinuz.old")).unwrap();
        let ops = LocalRootfsOps::open(&root).unwrap();

        for link in ["/vmlinuz", "/vmlinuz.old"] {
            let mut sink = Vec::new();
            let exported = ops
                .export_file(&RelPath::parse(link).unwrap(), &mut sink)
                .unwrap()
                .expect("the link resolves to a file");
            assert_eq!(sink, b"kernel image", "{link}");
            assert_eq!(exported.size, 12);
        }
    }

    // The confinement is what makes following links acceptable here at all: a link that
    // climbs out of the rootfs, or names an absolute host path, has to land inside it.
    #[test]
    fn export_resolves_links_as_if_the_rootfs_were_root() {
        let outer = tempfile::tempdir().unwrap();
        let outer_root = Utf8PathBuf::from_path_buf(outer.path().to_path_buf()).unwrap();
        std::fs::write(outer_root.join("secret"), b"host file").unwrap();
        let root = outer_root.join("rootfs");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("secret"), b"rootfs file").unwrap();
        std::os::unix::fs::symlink("../../../../secret", root.join("etc/climb")).unwrap();
        std::os::unix::fs::symlink(outer_root.join("secret"), root.join("etc/absolute")).unwrap();
        let ops = LocalRootfsOps::open(&root).unwrap();

        let mut sink = Vec::new();
        ops.export_file(&RelPath::parse("/etc/climb").unwrap(), &mut sink)
            .unwrap()
            .unwrap();
        assert_eq!(sink, b"rootfs file");

        // The absolute target names a host path, which inside the rootfs does not exist.
        let mut sink = Vec::new();
        let absolute = ops
            .export_file(&RelPath::parse("/etc/absolute").unwrap(), &mut sink)
            .unwrap();
        assert_eq!(absolute, None);
        assert!(sink.is_empty());
    }

    #[test]
    fn export_reports_a_dangling_link_as_absent() {
        let (_tmp, root) = rootfs();
        std::os::unix::fs::symlink("boot/vmlinuz-gone", root.join("vmlinuz")).unwrap();
        let ops = LocalRootfsOps::open(&root).unwrap();

        let mut sink = Vec::new();
        let exported = ops
            .export_file(&RelPath::parse("/vmlinuz").unwrap(), &mut sink)
            .unwrap();
        assert_eq!(exported, None);
    }

    #[test]
    fn export_refuses_what_is_not_a_regular_file() {
        let (_tmp, root) = rootfs();
        std::os::unix::fs::symlink("etc", root.join("vmlinuz")).unwrap();
        let ops = LocalRootfsOps::open(&root).unwrap();

        let err = ops
            .export_file(&RelPath::parse("/vmlinuz").unwrap(), &mut Vec::new())
            .unwrap_err();
        assert!(err.to_string().contains("refusing to export"), "{err}");
    }

    #[test]
    fn export_carries_the_source_mode() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, root) = rootfs();
        let image = root.join("initrd.img");
        std::fs::write(&image, b"initramfs").unwrap();
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o600)).unwrap();
        let ops = LocalRootfsOps::open(&root).unwrap();

        let exported = ops
            .export_file(&RelPath::parse("/initrd.img").unwrap(), &mut Vec::new())
            .unwrap()
            .unwrap();
        assert_eq!(exported.mode, FileMode::new(0o600));
    }

    // The helper resolves the path again for every chunk, so a file replaced between two
    // of them has to be refused rather than spliced onto the first one's bytes.
    #[test]
    fn a_chunk_from_a_different_file_is_refused() {
        let (_tmp, root) = rootfs();
        let path = RelPath::parse("/etc/image").unwrap();
        std::fs::write(root.join("etc/image"), b"first").unwrap();
        let ops = LocalRootfsOps::open(&root).unwrap();

        let first = ops.read_chunk(&path, 0, None).unwrap().unwrap();
        assert_eq!(first.data, b"first");
        assert_eq!(first.stamp.size(), 5);

        // A different size, so the refusal does not depend on the filesystem's timestamp
        // granularity: a same-sized file recreated within one tick can reuse the inode
        // number and the change time both.
        std::fs::remove_file(root.join("etc/image")).unwrap();
        std::fs::write(root.join("etc/image"), b"other file").unwrap();
        let err = ops.read_chunk(&path, 0, Some(first.stamp)).unwrap_err();
        assert!(
            err.to_string()
                .contains("changed while it was being exported"),
            "{err}"
        );

        std::fs::remove_file(root.join("etc/image")).unwrap();
        let err = ops.read_chunk(&path, 0, Some(first.stamp)).unwrap_err();
        assert!(
            err.to_string()
                .contains("changed while it was being exported"),
            "{err}"
        );
    }

    #[test]
    fn a_chunk_reads_from_its_offset() {
        let (_tmp, root) = rootfs();
        let path = RelPath::parse("/etc/image").unwrap();
        std::fs::write(root.join("etc/image"), b"0123456789").unwrap();
        let ops = LocalRootfsOps::open(&root).unwrap();

        let first = ops.read_chunk(&path, 0, None).unwrap().unwrap();
        let rest = ops
            .read_chunk(&path, 4, Some(first.stamp))
            .unwrap()
            .unwrap();
        assert_eq!(rest.data, b"456789");
        let end = ops
            .read_chunk(&path, 10, Some(first.stamp))
            .unwrap()
            .unwrap();
        assert!(end.data.is_empty());
    }
}
