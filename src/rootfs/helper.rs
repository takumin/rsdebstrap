//! Privileged execution of [`RootfsOps`] in a single helper process.
//!
//! Modifying a rootfs built by `mmdebstrap` needs root, and the boundary is crossed
//! exactly once: the parent spawns one helper under `sudo`/`doas`, the helper opens the
//! rootfs descriptor and serves typed requests over a pipe, and the parent never names a
//! rootfs path to a shell command. What root will do is bounded by [`Request`] — no
//! request can name a path outside the rootfs, because [`RelPath`] cannot express one.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};

use super::{LocalRootfsOps, RelPath, RootfsOps, TakenEntry};
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
        content: Vec<u8>,
        mode: u32,
    },
    WriteSymlink {
        path: RelPath,
        target: String,
    },
    ImportFile {
        host_src: Utf8PathBuf,
        path: RelPath,
        mode: u32,
    },
    Remove {
        path: RelPath,
    },
    Take {
        path: RelPath,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Unit,
    Taken(Option<TakenEntry>),
    Error(String),
}

/// Serves [`Request`]s on stdin against `rootfs` until stdin closes.
///
/// Runs as root in the helper process. Errors are reported to the parent as
/// [`Response::Error`] rather than terminating the loop, so one failed operation
/// does not tear down a session the parent may still need for cleanup.
pub fn serve(rootfs: &Utf8Path) -> Result<()> {
    let ops = LocalRootfsOps::open(rootfs)?;
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

fn dispatch(ops: &LocalRootfsOps, request: Request) -> Response {
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
        Request::ImportFile {
            host_src,
            path,
            mode,
        } => ops
            .import_file(&host_src, &path, mode)
            .map(|()| Response::Unit),
        Request::Remove { path } => ops.remove(&path).map(|()| Response::Unit),
        Request::Take { path } => ops.take(&path).map(Response::Taken),
    };
    result.unwrap_or_else(|e| Response::Error(e.to_string()))
}

/// [`RootfsOps`] performed by a privileged helper process.
pub struct PrivilegedRootfsOps {
    // One mutex over the whole channel: a request and its response are a single
    // transaction, and interleaving two of them would pair each with the other's
    // reply. The operations are a handful per build, so the serialization costs
    // nothing.
    channel: Mutex<Channel>,
    method: PrivilegeMethod,
}

struct Channel {
    child: Child,
    // `None` once `Drop` has closed it to end the helper's read loop.
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl Channel {
    fn stdin(&mut self) -> Result<&mut ChildStdin> {
        self.stdin.as_mut().ok_or_else(|| {
            RsdebstrapError::Isolation("the privileged helper channel is closed".into())
        })
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
                stdout,
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
        match channel.stdout.read_line(&mut line) {
            Ok(0) => Err(self.channel_lost(
                &mut channel,
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "helper closed its output"),
            )),
            Ok(_) => serde_json::from_str(&line).map_err(|e| {
                RsdebstrapError::Isolation(format!("malformed response from helper: {e}"))
            }),
            Err(e) => Err(self.channel_lost(&mut channel, e)),
        }
    }

    /// Reports a broken channel with the helper's exit status when it has one.
    ///
    /// A failed `sudo` (wrong password, no rule for this command) shows up as a
    /// closed pipe, which is unreadable on its own — the exit status is what
    /// tells the user their escalation was refused.
    fn channel_lost(&self, channel: &mut Channel, cause: std::io::Error) -> RsdebstrapError {
        let status = match channel.child.try_wait() {
            Ok(Some(status)) => format!(" (helper exited with {status})"),
            _ => String::new(),
        };
        RsdebstrapError::io(
            format!("lost the connection to the {} helper{}", self.method, status),
            cause,
        )
    }

    fn unit(&self, request: Request) -> Result<()> {
        match self.request(&request)? {
            Response::Unit => Ok(()),
            Response::Error(message) => Err(RsdebstrapError::Isolation(message)),
            Response::Taken(_) => Err(unexpected_response()),
        }
    }
}

fn unexpected_response() -> RsdebstrapError {
    RsdebstrapError::Isolation("privileged helper answered a different request".into())
}

impl Drop for PrivilegedRootfsOps {
    fn drop(&mut self) {
        let Ok(channel) = self.channel.get_mut() else {
            return;
        };
        // Closing stdin ends the helper's read loop, so it exits on its own and
        // `wait` reaps it. Without this the child would outlive us as a zombie
        // holding a root-owned descriptor into the rootfs.
        drop(channel.stdin.take());
        match channel.child.wait() {
            Ok(status) if status.success() => tracing::debug!("privileged helper exited"),
            Ok(status) => tracing::warn!("privileged helper exited with {status}"),
            Err(e) => tracing::warn!("failed to reap the privileged helper: {e}"),
        }
    }
}

impl RootfsOps for PrivilegedRootfsOps {
    fn write_file(&self, path: &RelPath, content: &[u8], mode: u32) -> Result<()> {
        self.unit(Request::WriteFile {
            path: path.clone(),
            content: content.to_vec(),
            mode,
        })
    }

    fn write_symlink(&self, path: &RelPath, target: &str) -> Result<()> {
        self.unit(Request::WriteSymlink {
            path: path.clone(),
            target: target.to_string(),
        })
    }

    fn import_file(&self, host_src: &Utf8Path, path: &RelPath, mode: u32) -> Result<()> {
        self.unit(Request::ImportFile {
            host_src: host_src.to_owned(),
            path: path.clone(),
            mode,
        })
    }

    fn remove(&self, path: &RelPath) -> Result<()> {
        self.unit(Request::Remove { path: path.clone() })
    }

    fn take(&self, path: &RelPath) -> Result<Option<TakenEntry>> {
        match self.request(&Request::Take { path: path.clone() })? {
            Response::Taken(entry) => Ok(entry),
            Response::Error(message) => Err(RsdebstrapError::Isolation(message)),
            Response::Unit => Err(unexpected_response()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The helper's request loop, driven directly against a real rootfs. This is
    // the same `serve` dispatch the privileged process runs, minus the escalation
    // — which is the part a test cannot exercise without a password prompt.
    fn round_trip(ops: &LocalRootfsOps, request: Request) -> Response {
        dispatch(ops, request)
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
            mode: 0o644,
        };
        let encoded = serde_json::to_string(&request).unwrap();
        let decoded: Request = serde_json::from_str(&encoded).unwrap();
        assert!(matches!(decoded, Request::WriteFile { mode: 0o644, .. }));
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
        let ops = LocalRootfsOps::open(&root).unwrap();
        let response = round_trip(
            &ops,
            Request::WriteFile {
                path: RelPath::parse("/missing/resolv.conf").unwrap(),
                content: b"x".to_vec(),
                mode: 0o644,
            },
        );
        assert!(matches!(response, Response::Error(_)), "got {response:?}");
    }

    #[test]
    fn take_and_write_round_trip_through_dispatch() {
        let (_tmp, root) = rootfs();
        let ops = LocalRootfsOps::open(&root).unwrap();
        let path = RelPath::parse("/etc/resolv.conf").unwrap();

        let written = round_trip(
            &ops,
            Request::WriteFile {
                path: path.clone(),
                content: b"nameserver 9.9.9.9\n".to_vec(),
                mode: 0o644,
            },
        );
        assert!(matches!(written, Response::Unit), "got {written:?}");

        let taken = round_trip(&ops, Request::Take { path });
        let Response::Taken(Some(TakenEntry::File { content, mode })) = taken else {
            panic!("got {taken:?}");
        };
        assert_eq!(content, b"nameserver 9.9.9.9\n");
        assert_eq!(mode, 0o644);
    }
}
