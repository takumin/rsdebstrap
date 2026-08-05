// Drives the privileged helper as a real subprocess over its real protocol.
//
// The unit tests in `src/rootfs/helper.rs` call `dispatch` directly, which
// covers the operations but not the parts that only exist across a process
// boundary: that the hidden subcommand parses, that stdout carries the response
// stream uncontaminated by logging, and that the process exits when stdin
// closes. Escalation itself is not exercised — that would need a password
// prompt — so the helper is spawned directly rather than under sudo. What runs
// under sudo in production is this same binary with this same argv.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use camino::Utf8PathBuf;

fn seeded_rootfs() -> (tempfile::TempDir, Utf8PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::write(root.join("etc/resolv.conf"), b"nameserver 8.8.8.8\n").unwrap();
    (tmp, root)
}

// Sends each request, returns one response line per request, and asserts the
// helper exited cleanly once stdin closed.
fn run_session(rootfs: &Utf8PathBuf, requests: &[&str]) -> Vec<String> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rsdebstrap"))
        .arg("__rootfs-helper")
        .arg("--rootfs")
        .arg(rootfs.as_str())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn helper");

    let mut stdin = child.stdin.take().unwrap();
    for request in requests {
        writeln!(stdin, "{request}").unwrap();
    }
    stdin.flush().unwrap();
    drop(stdin);

    let responses: Vec<String> = BufReader::new(child.stdout.take().unwrap())
        .lines()
        .map(|l| l.unwrap())
        .collect();

    let status = child.wait().unwrap();
    assert!(status.success(), "helper exited with {status}");
    assert_eq!(responses.len(), requests.len(), "responses: {responses:?}");
    responses
}

#[test]
fn take_detaches_the_entry_and_returns_its_contents() {
    let (_tmp, root) = seeded_rootfs();
    let responses = run_session(&root, &[r#"{"Take":{"path":"/etc/resolv.conf"}}"#]);

    assert!(responses[0].contains("\"mode\":436"), "got {}", responses[0]);
    assert!(!root.join("etc/resolv.conf").exists(), "entry was not detached");
}

#[test]
fn write_file_installs_content_and_mode() {
    let (_tmp, root) = seeded_rootfs();
    let responses = run_session(
        &root,
        &[r#"{"WriteFile":{"path":"/etc/hosts","content":[104,105,10],"mode":420}}"#],
    );

    assert_eq!(responses[0], "\"Unit\"");
    assert_eq!(std::fs::read(root.join("etc/hosts")).unwrap(), b"hi\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(root.join("etc/hosts"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);
    }
}

// The boundary that scopes the helper's root privilege: a `..` in a request is
// refused while decoding, before any operation runs.
#[test]
fn a_request_escaping_the_rootfs_is_refused() {
    let (_tmp, root) = seeded_rootfs();
    let responses = run_session(&root, &[r#"{"Remove":{"path":"/etc/../../../etc/shadow"}}"#]);

    assert!(responses[0].contains("Error"), "got {}", responses[0]);
    assert!(responses[0].contains(".."), "got {}", responses[0]);
}

// One failed operation must not end the session: the parent may still need the
// channel to restore what it detached earlier.
#[test]
fn the_session_survives_a_failing_operation() {
    let (_tmp, root) = seeded_rootfs();
    let responses = run_session(
        &root,
        &[
            r#"{"WriteFile":{"path":"/missing/x","content":[120],"mode":420}}"#,
            r#"{"WriteFile":{"path":"/etc/hosts","content":[120],"mode":420}}"#,
        ],
    );

    assert!(responses[0].contains("Error"), "got {}", responses[0]);
    assert_eq!(responses[1], "\"Unit\"");
}

// The helper is an internal protocol between two processes of the same build,
// so it must not appear in help output as something to invoke.
#[test]
fn the_helper_subcommand_is_hidden_from_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_rsdebstrap"))
        .arg("--help")
        .output()
        .unwrap();
    let help = String::from_utf8(output.stdout).unwrap();

    assert!(!help.contains("__rootfs-helper"), "helper is listed in --help:\n{help}");
    assert!(help.contains("apply"), "sanity: apply should be listed:\n{help}");
}
