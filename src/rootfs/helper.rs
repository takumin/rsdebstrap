//! Privileged execution of [`RootfsOps`] in a single helper process.
//!
//! Modifying a rootfs built by `mmdebstrap` needs root, and the boundary is crossed
//! exactly once: the parent spawns one helper under `sudo`/`doas`, the helper opens the
//! rootfs descriptor and serves typed requests over a pipe, and the parent never names a
//! rootfs path to a shell command. What root will do is bounded by [`Request`] — every path
//! in it is a [`RelPath`], which cannot name anything outside the rootfs, and no variant
//! carries a host path for root to resolve. Host files are read by the parent, so what
//! crosses the boundary is bytes.
//!
//! What that bound is *relative to* is the anchor, and the anchor is a path argument from
//! the unprivileged parent. A `sudo` rule permitting this helper therefore permits root
//! writes under any directory the invoking user can name; `CheckedAnchor` only refuses the
//! live system's own hierarchy. Grant the rule accordingly.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

use camino::Utf8Path;
use rustix::fs as rfs;
use serde::{Deserialize, Serialize};

use super::{FileMode, LocalRootfsOps, RelPath, RootfsOps, TakenEntry};
use crate::error::RsdebstrapError;
use crate::privilege::PrivilegeMethod;

type Result<T> = std::result::Result<T, RsdebstrapError>;

/// The hidden subcommand the parent re-executes itself with.
pub const HELPER_SUBCOMMAND: &str = "__rootfs-helper";

/// One filesystem mutation, as sent to the privileged helper.
///
/// The set of variants *is* the privilege the helper holds: root can do nothing
/// on the parent's behalf that is not spelled out here.
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    WriteFile {
        path: RelPath,
        #[serde(with = "crate::rootfs::payload")]
        content: Vec<u8>,
        mode: FileMode,
    },
    WriteSymlink {
        path: RelPath,
        #[serde(with = "crate::rootfs::payload")]
        target: Vec<u8>,
    },
    Remove {
        path: RelPath,
    },
    Take {
        path: RelPath,
    },
    // Carries the whole entry rather than reusing `WriteFile`, because restoring one
    // sets an owner, and only the helper has the privilege to set it to anything but
    // its own.
    PutBack {
        path: RelPath,
        entry: TakenEntry,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Unit,
    Taken(Option<TakenEntry>),
    Error(String),
}

/// Directories the helper refuses to anchor to, whatever the parent asks for.
///
/// These are the live system's own hierarchy. A rootfs is never one of them. The list names
/// the *top* of each hierarchy and matches by inode, so it is a floor and not a boundary:
/// what keeps the anchor from landing at `/etc/ssh`, which no entry here names, is that
/// nothing on the way to it is followed.
const REFUSED_ANCHORS: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64", "/libx32", "/opt",
    "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var",
];

/// A rootfs the helper has opened and checked, in that order.
///
/// The anchor is the one path the helper resolves by name, and it comes from the
/// *unprivileged* parent — so a `sudo` rule permitting this helper would otherwise permit
/// root writes anywhere. Refusing the live system's own hierarchy does not make the anchor
/// trustworthy (the parent still chooses it, and any directory the invoking user could name
/// is still reachable); it puts a floor under the damage a mistake or a hijacked argv can do.
///
/// The floor only holds if the thing checked is the thing used, so the descriptor is opened
/// first and the check runs against *it*, by inode; existing only as this type means
/// [`dispatch`] cannot be reached with an unchecked one.
///
/// It also only holds if the open lands where the path says. [`LocalRootfsOps::open`] walks
/// the path a component at a time under `O_NOFOLLOW` for that reason: root must not follow a
/// symlink swapped in for an intermediate directory, which would anchor it inside the live
/// system one level below anything [`REFUSED_ANCHORS`] names. Symlinks the invoking user
/// legitimately has on the way are resolved before the helper is spawned, by the
/// unprivileged parent.
#[derive(Debug)]
struct CheckedAnchor(LocalRootfsOps);

impl CheckedAnchor {
    fn open(rootfs: &Utf8Path) -> Result<Self> {
        let ops = LocalRootfsOps::open(rootfs)?;
        let anchor = rfs::fstat(ops.root()).map_err(|e| {
            RsdebstrapError::io(
                format!("failed to stat rootfs {}", rootfs),
                std::io::Error::from(e),
            )
        })?;

        for refused in REFUSED_ANCHORS {
            // `stat`, not `lstat`: on a merged-`/usr` system `/lib` is a symlink, and an
            // anchor naming its target is the same directory by another name. Comparing
            // inodes rather than strings also catches a bind mount of one of these.
            let Ok(live) = rfs::stat(*refused) else {
                continue;
            };
            if (live.st_dev, live.st_ino) == (anchor.st_dev, anchor.st_ino) {
                return Err(RsdebstrapError::Isolation(format!(
                    "refusing to serve privileged operations against {}: it is {}, part of \
                    the live system, not a rootfs",
                    rootfs, refused
                )));
            }
        }
        Ok(Self(ops))
    }

    fn ops(&self) -> &LocalRootfsOps {
        &self.0
    }
}

/// Serves [`Request`]s on stdin against `rootfs` until stdin closes.
///
/// Runs as root in the helper process. Errors are reported to the parent as
/// [`Response::Error`] rather than terminating the loop, so one failed operation
/// does not tear down a session the parent may still need for cleanup.
pub fn serve(rootfs: &Utf8Path) -> Result<()> {
    let ops = CheckedAnchor::open(rootfs)?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = line.map_err(|e| RsdebstrapError::io("failed to read helper request", e))?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => dispatch(&ops, request),
            Err(e) => Response::Error(format!("malformed request: {e}")),
        };
        let encoded = serde_json::to_string(&response)
            .map_err(|e| RsdebstrapError::Isolation(format!("failed to encode response: {e}")))?;
        writeln!(stdout, "{encoded}")
            .and_then(|()| stdout.flush())
            .map_err(|e| RsdebstrapError::io("failed to write helper response", e))?;
    }
    Ok(())
}

fn dispatch(anchor: &CheckedAnchor, request: Request) -> Response {
    let ops = anchor.ops();
    let result = match request {
        Request::WriteFile {
            path,
            content,
            mode,
        } => ops
            .write_file(&path, &content, mode)
            .map(|()| Response::Unit),
        Request::WriteSymlink { path, target } => {
            ops.write_symlink(&path, &target).map(|()| Response::Unit)
        }
        Request::Remove { path } => ops.remove(&path).map(|()| Response::Unit),
        Request::Take { path } => ops.take(&path).map(Response::Taken),
        Request::PutBack { path, entry } => ops.put_back(&path, &entry).map(|()| Response::Unit),
    };
    result.unwrap_or_else(|e| Response::Error(e.to_string()))
}

/// [`RootfsOps`] performed by a privileged helper process.
#[derive(Debug)]
pub struct PrivilegedRootfsOps {
    // One mutex over the whole channel: a request and its response are a single
    // transaction, and interleaving two of them would pair each with the other's
    // reply. The operations are a handful per build, so the serialization costs
    // nothing.
    channel: Mutex<Channel>,
    method: PrivilegeMethod,
}

#[derive(Debug)]
struct Channel {
    child: Child,
    // Both `None` once the channel has been closed -- by `Drop`, or by `close` after a
    // failed exchange left the stream at an unknown offset.
    stdin: Option<ChildStdin>,
    stdout: Option<BufReader<ChildStdout>>,
}

impl Channel {
    fn stdin(&mut self) -> Result<&mut ChildStdin> {
        self.stdin.as_mut().ok_or_else(closed)
    }

    fn stdout(&mut self) -> Result<&mut BufReader<ChildStdout>> {
        self.stdout.as_mut().ok_or_else(closed)
    }

    /// Closes both halves, ending the helper's read loop and freeing it from a write that
    /// nothing is draining.
    ///
    /// Called on any failed exchange, because a request that did not get its whole reply
    /// leaves the stream at an unknown offset: the tail of that line is still buffered, and
    /// the next request would be answered by it. `Response::Unit` is legal for every
    /// unit-shaped request, so a stream off by one reply would go unnoticed -- the resolv.conf
    /// teardown would consume setup's stale `Unit`, mark itself done, and leave the temporary
    /// resolv.conf in the image. A closed channel makes every later request say so instead.
    fn close(&mut self) {
        drop(self.stdin.take());
        drop(self.stdout.take());
    }
}

fn closed() -> RsdebstrapError {
    RsdebstrapError::Isolation("the privileged helper channel is closed".into())
}

/// Reaping lives here, on the value that owns the child, rather than on
/// [`PrivilegedRootfsOps`], which owns it behind a `Mutex`.
///
/// The difference is what happens after a panic while the channel is locked. Reaping from
/// the outer type means taking the poisoned lock and deciding what to do about it, and the
/// obvious `let Ok(..) = .. else { return }` skips the reap in exactly the case the comment
/// below is about. Dropping a `Mutex` drops its contents whether or not it is poisoned, so
/// putting the work here means there is no lock to take and no decision to get wrong.
impl Drop for Channel {
    fn drop(&mut self) {
        // Closing stdin ends the helper's read loop, so it exits on its own and
        // `wait` reaps it. Without this the child would outlive us as a zombie
        // holding a root-owned descriptor into the rootfs.
        //
        // stdout closes too, and before the `wait`. A helper part-way through a reply larger
        // than the pipe buffer is blocked in `write`, not in the read loop, and closing only
        // stdin would leave it there with nothing draining it -- `wait` would never return.
        // Closed, its write fails with `EPIPE` and it exits. Fields drop after this body, so
        // it has to be taken here rather than left to that.
        self.close();
        match self.child.wait() {
            Ok(status) if status.success() => tracing::debug!("privileged helper exited"),
            Ok(status) => tracing::warn!("privileged helper exited with {status}"),
            Err(e) => tracing::warn!("failed to reap the privileged helper: {e}"),
        }
    }
}

impl PrivilegedRootfsOps {
    /// Spawns the helper under `method` and anchors it to `rootfs`.
    ///
    /// # Errors
    ///
    /// Returns an error if this executable's path cannot be determined or the
    /// helper cannot be spawned.
    pub fn spawn(rootfs: &Utf8Path, method: PrivilegeMethod) -> Result<Self> {
        let exe = std::env::current_exe()
            .map_err(|e| RsdebstrapError::io("failed to locate the rsdebstrap executable", e))?;
        Self::spawn_exe(&exe, rootfs, method)
    }

    /// [`spawn`](Self::spawn) with the helper executable named explicitly.
    ///
    /// `spawn` re-executes `current_exe()`, which is the right binary in
    /// production and the *test harness* binary under `cargo test`. Tests that
    /// exercise real escalation pass the built `rsdebstrap` path here.
    ///
    /// # Errors
    ///
    /// Returns an error if the helper cannot be spawned.
    pub fn spawn_exe(
        exe: &std::path::Path,
        rootfs: &Utf8Path,
        method: PrivilegeMethod,
    ) -> Result<Self> {
        let mut child = Command::new(method.command_name())
            .arg(exe)
            .arg(HELPER_SUBCOMMAND)
            .arg("--rootfs")
            .arg(rootfs.as_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| {
                RsdebstrapError::io(
                    format!("failed to spawn the privileged helper via {}", method),
                    e,
                )
            })?;

        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = BufReader::new(child.stdout.take().expect("stdout was piped"));
        tracing::debug!(pid = child.id(), "spawned privileged rootfs helper");

        Ok(Self {
            channel: Mutex::new(Channel {
                child,
                stdin: Some(stdin),
                stdout: Some(stdout),
            }),
            method,
        })
    }

    fn request(&self, request: &Request) -> Result<Response> {
        let mut channel = self.channel.lock().map_err(|_| {
            RsdebstrapError::Isolation("privileged helper channel is poisoned".into())
        })?;

        let encoded = serde_json::to_string(request)
            .map_err(|e| RsdebstrapError::Isolation(format!("failed to encode request: {e}")))?;
        let write = channel.stdin().and_then(|stdin| {
            writeln!(stdin, "{encoded}")
                .and_then(|()| stdin.flush())
                .map_err(|e| RsdebstrapError::io("failed to send request", e))
        });
        if let Err(e) = write {
            return Err(match e {
                RsdebstrapError::Io { source, .. } => self.channel_lost(&mut channel, source),
                other => other,
            });
        }

        let mut line = String::new();
        let read = channel.stdout().and_then(|stdout| {
            stdout
                .read_line(&mut line)
                .map_err(|e| RsdebstrapError::io("failed to read the response", e))
        });
        match read {
            Ok(0) => Err(self.channel_lost(
                &mut channel,
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "helper closed its output"),
            )),
            // Not this reply going wrong, but a line nothing here sent -- a `sudo` plugin
            // that prints, a shell wrapper, anything on the helper's stdout that is not a
            // response. The real reply is still buffered behind it, so leaving the channel
            // open would keep the stream one reply ahead for the rest of the run.
            Ok(_) => serde_json::from_str(&line).map_err(|e| {
                channel.close();
                RsdebstrapError::Isolation(format!("malformed response from helper: {e}"))
            }),
            Err(RsdebstrapError::Io { source, .. }) => Err(self.channel_lost(&mut channel, source)),
            Err(other) => Err(other),
        }
    }

    /// Reports a broken channel with the helper's exit status when it has one.
    ///
    /// A failed `sudo` (wrong password, no rule for this command) shows up as a
    /// closed pipe, which is unreadable on its own — the exit status is what
    /// tells the user their escalation was refused.
    ///
    /// Closes the channel on the way out: an exchange that did not complete leaves the
    /// stream at an offset nothing can recover, and reporting the failure while leaving the
    /// channel usable is how the next request comes to be answered by this one's reply.
    fn channel_lost(&self, channel: &mut Channel, cause: std::io::Error) -> RsdebstrapError {
        channel.close();
        let status = match channel.child.try_wait() {
            Ok(Some(status)) => format!(" (helper exited with {status})"),
            _ => String::new(),
        };
        RsdebstrapError::io(
            format!("lost the connection to the {} helper{}", self.method, status),
            cause,
        )
    }

    /// Reports a reply of a shape this request could not have produced, and closes the
    /// channel.
    ///
    /// The helper answers each request in turn, so a `Taken` where a `Unit` belongs is not
    /// this request's answer coming out wrong -- it is a different request's, and every
    /// later request would read the wrong one too. A `Response::Error` is not this: a
    /// refusal is the answer to *this* request, and the channel stays usable.
    fn desynchronised(&self) -> RsdebstrapError {
        // Poisoned means a panic unwound through the channel, which `Channel::drop` still
        // reaps. Nothing left to close, and no reason to panic again over it.
        if let Ok(mut channel) = self.channel.lock() {
            channel.close();
        }
        RsdebstrapError::Isolation("privileged helper answered a different request".into())
    }

    fn unit(&self, request: Request) -> Result<()> {
        match self.request(&request)? {
            Response::Unit => Ok(()),
            Response::Error(message) => Err(RsdebstrapError::Isolation(message)),
            Response::Taken(_) => Err(self.desynchronised()),
        }
    }
}

impl RootfsOps for PrivilegedRootfsOps {
    fn write_file(&self, path: &RelPath, content: &[u8], mode: FileMode) -> Result<()> {
        self.unit(Request::WriteFile {
            path: path.clone(),
            content: content.to_vec(),
            mode,
        })
    }

    fn write_symlink(&self, path: &RelPath, target: &[u8]) -> Result<()> {
        self.unit(Request::WriteSymlink {
            path: path.clone(),
            target: target.to_vec(),
        })
    }

    fn remove(&self, path: &RelPath) -> Result<()> {
        self.unit(Request::Remove { path: path.clone() })
    }

    fn put_back(&self, path: &RelPath, entry: &TakenEntry) -> Result<()> {
        self.unit(Request::PutBack {
            path: path.clone(),
            entry: entry.clone(),
        })
    }

    fn take(&self, path: &RelPath) -> Result<Option<TakenEntry>> {
        match self.request(&Request::Take { path: path.clone() })? {
            Response::Taken(entry) => Ok(entry),
            Response::Error(message) => Err(RsdebstrapError::Isolation(message)),
            Response::Unit => Err(self.desynchronised()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rootfs::Owner;

    // The helper's request loop, driven directly against a real rootfs. This is
    // the same `serve` dispatch the privileged process runs, minus the escalation
    // — which is the part a test cannot exercise without a password prompt.
    fn round_trip(anchor: &CheckedAnchor, request: Request) -> Response {
        dispatch(anchor, request)
    }

    fn rootfs() -> (tempfile::TempDir, camino::Utf8PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        (tmp, root)
    }

    #[test]
    fn requests_round_trip_through_serde() {
        let request = Request::WriteFile {
            path: RelPath::parse("/etc/resolv.conf").unwrap(),
            content: b"nameserver 1.1.1.1\n".to_vec(),
            mode: FileMode::new(0o644),
        };
        let encoded = serde_json::to_string(&request).unwrap();
        let decoded: Request = serde_json::from_str(&encoded).unwrap();
        assert!(matches!(decoded, Request::WriteFile { mode, .. } if mode == FileMode::new(0o644)));
    }

    // A request naming a path outside the rootfs must not survive decoding: the
    // helper runs as root, so this is the boundary that keeps escalation scoped.
    #[test]
    fn a_request_escaping_the_rootfs_is_rejected_before_dispatch() {
        let escape = r#"{"Remove":{"path":"/etc/../../../etc/shadow"}}"#;
        let err = serde_json::from_str::<Request>(escape).unwrap_err();
        assert!(err.to_string().contains(".."), "unexpected error: {err}");
    }

    #[test]
    fn dispatch_reports_errors_instead_of_unwinding() {
        let (_tmp, root) = rootfs();
        let anchor = CheckedAnchor::open(&root).unwrap();
        let response = round_trip(
            &anchor,
            Request::WriteFile {
                path: RelPath::parse("/missing/resolv.conf").unwrap(),
                content: b"x".to_vec(),
                mode: FileMode::new(0o644),
            },
        );
        assert!(matches!(response, Response::Error(_)), "got {response:?}");
    }

    #[test]
    fn take_and_write_round_trip_through_dispatch() {
        let (_tmp, root) = rootfs();
        let anchor = CheckedAnchor::open(&root).unwrap();
        let path = RelPath::parse("/etc/resolv.conf").unwrap();

        let written = round_trip(
            &anchor,
            Request::WriteFile {
                path: path.clone(),
                content: b"nameserver 9.9.9.9\n".to_vec(),
                mode: FileMode::new(0o644),
            },
        );
        assert!(matches!(written, Response::Unit), "got {written:?}");

        let taken = round_trip(&anchor, Request::Take { path });
        let Response::Taken(Some(TakenEntry::File { content, mode, .. })) = taken else {
            panic!("got {taken:?}");
        };
        assert_eq!(content, b"nameserver 9.9.9.9\n");
        assert_eq!(mode, FileMode::new(0o644));
    }

    // The refused set is matched by inode, not against the string the parent passed, so a
    // spelling that is not in `REFUSED_ANCHORS` but lands on the same directory is refused
    // anyway. `/..` is `/`.
    #[test]
    fn a_refused_directory_under_another_name_is_still_refused() {
        let err = CheckedAnchor::open(camino::Utf8Path::new("/..")).unwrap_err();
        assert!(err.to_string().contains("not a rootfs"), "unexpected error: {err}");
    }

    // Order matters as much as the comparison: the descriptor is opened first, so a path
    // whose final component is a symlink never reaches the inode check at all.
    #[test]
    fn a_symlinked_anchor_is_refused_before_the_inode_check() {
        let (_tmp, root) = rootfs();
        let link = root.join("link");
        std::os::unix::fs::symlink(root.join("etc"), &link).unwrap();

        let err = CheckedAnchor::open(&link).unwrap_err();
        assert!(err.to_string().contains("symlink"), "unexpected error: {err}");
    }

    // A temporary directory is not part of the live system even though it lives under
    // `/tmp`, which is: the check is about the anchor itself, not about what contains it.
    #[test]
    fn a_directory_under_a_refused_one_is_accepted() {
        let (_tmp, root) = rootfs();
        CheckedAnchor::open(&root).expect("a tempdir is not the live system");
    }

    // A panic while the channel was locked poisons the mutex, and that is precisely the
    // case that would strand a root-owned helper. Reaping lives in `Channel::drop`, which a
    // poisoned mutex still runs, rather than on `PrivilegedRootfsOps`, which would have to
    // take the poisoned lock to close stdin and `wait`.
    //
    // `cat` stands in for the helper: it reads stdin until it closes, then exits, which is
    // the same shape and needs no escalation. A still-running child and an unreaped zombie
    // both keep /proc/<pid> alive, so its absence is the whole assertion.
    #[test]
    fn a_poisoned_channel_still_reaps_the_child() {
        let mut child = Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to spawn the stand-in child");
        let pid = child.id();
        let channel = Mutex::new(Channel {
            stdin: Some(child.stdin.take().expect("stdin was piped")),
            stdout: Some(BufReader::new(child.stdout.take().expect("stdout was piped"))),
            child,
        });

        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = channel.lock().unwrap();
            panic!("poison the channel");
        }));
        assert!(poisoned.is_err(), "the panic should have unwound");
        assert!(channel.is_poisoned(), "the mutex should be poisoned");

        drop(channel);

        let proc_entry = format!("/proc/{pid}");
        assert!(
            !std::path::Path::new(&proc_entry).exists(),
            "{proc_entry} still exists: the child was left running or unreaped"
        );
    }

    // What the base64 payload encoding is for. A `Vec<u8>` rendered as a JSON decimal array
    // costs about 4.6 bytes of text per byte of file, so staging a 40 MB mitamae binary
    // meant a ~180 MB line held in full by both processes and one integer parsed per byte.
    //
    // The bound is deliberately loose — this pins the order of magnitude, not base64's exact
    // ratio — but 4/3 plus a small envelope is far below what any per-byte-token encoding
    // can reach, so a regression to one fails here.
    #[test]
    fn a_file_payload_does_not_inflate_on_the_wire() {
        let content: Vec<u8> = (0..=255u8).cycle().take(64 * 1024).collect();
        let encoded = serde_json::to_string(&Request::WriteFile {
            path: RelPath::parse("/usr/local/bin/mitamae").unwrap(),
            content: content.clone(),
            mode: FileMode::new(0o700),
        })
        .unwrap();

        assert!(
            encoded.len() < content.len() * 3 / 2,
            "{} bytes of payload became {} bytes on the wire",
            content.len(),
            encoded.len()
        );

        let Request::WriteFile { content: back, .. } =
            serde_json::from_str::<Request>(&encoded).unwrap()
        else {
            panic!("round-tripped into a different variant");
        };
        assert_eq!(back, content, "the payload did not survive the round trip");
    }

    // Every byte value has to survive, including the ones that are not valid UTF-8 and the
    // ones JSON would otherwise have to escape.
    #[test]
    fn a_taken_entry_round_trips_every_byte_value() {
        let entry = TakenEntry::File {
            content: (0..=255u8).collect(),
            mode: FileMode::new(0o600),
            owner: Owner { uid: 0, gid: 0 },
        };
        let encoded = serde_json::to_string(&entry).unwrap();
        assert_eq!(serde_json::from_str::<TakenEntry>(&encoded).unwrap(), entry);
    }

    // The same for a symlink's target, which is a path and so has no encoding either. As a
    // JSON string it could not have crossed the channel at all.
    #[test]
    fn a_taken_symlink_round_trips_a_target_that_is_not_utf8() {
        let entry = TakenEntry::Symlink {
            target: b"../run/\xff\xfe/resolv.conf".to_vec(),
            owner: Owner { uid: 0, gid: 0 },
        };
        let encoded = serde_json::to_string(&entry).unwrap();
        assert_eq!(serde_json::from_str::<TakenEntry>(&encoded).unwrap(), entry);
    }

    // A line on the helper's stdout that is not a response -- a `sudo` plugin's banner, a
    // shell wrapper's output, a stray `println!` on the helper path -- is read as this
    // request's reply, and the reply it was meant to have is still buffered behind it.
    //
    // Left usable, the channel would stay one reply ahead for the rest of the run, and
    // `Response::Unit` is legal for every unit-shaped request: `RootfsResolvConf::teardown`
    // would read the previous request's `Unit`, mark itself torn down, and the run would
    // exit successfully with the temporary provisioning resolv.conf in the image.
    //
    // The stand-in prints its banner and then answers every request with a valid `Unit`, so
    // the second call succeeds unless the first one closed the channel.
    #[test]
    fn a_stray_line_closes_the_channel_rather_than_shifting_every_reply() {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(r#"echo "sudo: a banner"; while IFS= read -r _; do echo '"Unit"'; done"#)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to spawn the stand-in helper");
        let ops = PrivilegedRootfsOps {
            channel: Mutex::new(Channel {
                stdin: Some(child.stdin.take().expect("stdin was piped")),
                stdout: Some(BufReader::new(child.stdout.take().expect("stdout was piped"))),
                child,
            }),
            method: PrivilegeMethod::Sudo,
        };
        let path = RelPath::parse("/etc/resolv.conf").unwrap();

        let first = ops.remove(&path).expect_err("a banner is not a response");
        assert!(first.to_string().contains("malformed response"), "unexpected: {first}");

        let second = ops
            .remove(&path)
            .expect_err("the channel must not still be usable");
        assert!(second.to_string().contains("closed"), "unexpected: {second}");
    }
}
