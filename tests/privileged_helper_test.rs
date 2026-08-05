// Exercises real privilege escalation: `sudo` spawning the helper, and the
// helper operating on a rootfs this user cannot touch directly.
//
// `#[ignore]`d because it needs passwordless sudo, following the convention the
// permission-rendering tests use. Run with:
//
//     cargo test --test privileged_helper_test -- --ignored
//
// `--ignored` is also run workspace-wide by `task test:non_root`, which has no
// sudo requirement of its own, so each test here re-checks the precondition and
// skips rather than hanging on a password prompt or failing on a machine that
// simply is not set up for this.
//
// The rootfs is created root-owned with mode 0700, so every assertion here would
// fail with EACCES if the helper were not actually running as root — the test
// cannot pass by accident against an unprivileged implementation.

use camino::Utf8PathBuf;
use rsdebstrap::privilege::PrivilegeMethod;
use rsdebstrap::rootfs::helper::PrivilegedRootfsOps;
use rsdebstrap::rootfs::{LocalRootfsOps, RelPath, RootfsOps, TakenEntry};

const ORIGINAL: &str = "# original, root-owned\n";

// `-n` makes sudo fail immediately instead of prompting, which is what turns an
// unconfigured machine into a skip rather than a hung test run.
fn passwordless_sudo_available() -> bool {
    std::process::Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .is_ok_and(|s| s.success())
}

macro_rules! require_sudo {
    () => {
        if !passwordless_sudo_available() {
            eprintln!("skipping: passwordless sudo is not available");
            return;
        }
    };
}

fn sudo(args: &[&str]) {
    let status = std::process::Command::new("sudo")
        .args(args)
        .status()
        .expect("failed to run sudo");
    assert!(status.success(), "sudo {args:?} failed with {status}");
}

// A rootfs owned by root with mode 0700 on `/etc`, holding a resolv.conf this
// user can neither read nor replace.
struct RootOwnedRootfs {
    _tmp: tempfile::TempDir,
    path: Utf8PathBuf,
}

impl RootOwnedRootfs {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(tmp.path().join("rootfs")).unwrap();
        let etc = path.join("etc");
        let resolv = etc.join("resolv.conf");

        sudo(&["mkdir", "-p", etc.as_str()]);
        sudo(&["sh", "-c", &format!("printf '%s' '{ORIGINAL}' > {resolv}")]);
        sudo(&["chown", "-R", "root:root", path.as_str()]);
        sudo(&["chmod", "700", etc.as_str()]);
        sudo(&["chmod", "600", resolv.as_str()]);

        Self { _tmp: tmp, path }
    }

    fn read_resolv_conf(&self) -> String {
        let out = std::process::Command::new("sudo")
            .args(["cat", self.path.join("etc/resolv.conf").as_str()])
            .output()
            .expect("failed to read back through sudo");
        assert!(out.status.success(), "reading back failed: {out:?}");
        String::from_utf8(out.stdout).unwrap()
    }

    // `test -L` rather than `stat -c %F`, whose output is localized.
    fn resolv_conf_is_symlink(&self) -> bool {
        std::process::Command::new("sudo")
            .args(["test", "-L", self.path.join("etc/resolv.conf").as_str()])
            .status()
            .expect("failed to test through sudo")
            .success()
    }
}

impl Drop for RootOwnedRootfs {
    fn drop(&mut self) {
        // The TempDir's own cleanup cannot remove root-owned entries.
        sudo(&["rm", "-rf", self.path.as_str()]);
    }
}

fn privileged(rootfs: &Utf8PathBuf) -> PrivilegedRootfsOps {
    PrivilegedRootfsOps::spawn_exe(
        std::path::Path::new(env!("CARGO_BIN_EXE_rsdebstrap")),
        rootfs,
        PrivilegeMethod::Sudo,
    )
    .expect("failed to spawn the privileged helper")
}

// Establishes that the fixture really is out of this user's reach, so the
// escalation assertions below are not passing for a trivial reason.
#[test]
#[ignore = "requires passwordless sudo"]
fn the_unprivileged_implementation_cannot_touch_a_root_owned_rootfs() {
    require_sudo!();
    let fixture = RootOwnedRootfs::new();
    let ops = LocalRootfsOps::open(&fixture.path).expect("opening the rootfs root should succeed");

    let err = ops
        .take(&RelPath::parse("/etc/resolv.conf").unwrap())
        .unwrap_err();

    assert!(
        err.to_string().contains("permission denied") || err.to_string().contains("Permission"),
        "expected a permission error, got: {err}"
    );
    assert_eq!(fixture.read_resolv_conf(), ORIGINAL);
}

#[test]
#[ignore = "requires passwordless sudo"]
fn the_helper_takes_and_restores_a_root_owned_entry() {
    require_sudo!();
    let fixture = RootOwnedRootfs::new();
    let ops = privileged(&fixture.path);
    let path = RelPath::parse("/etc/resolv.conf").unwrap();

    let taken = ops
        .take(&path)
        .unwrap()
        .expect("the entry should have been there");
    assert_eq!(
        taken,
        TakenEntry::File {
            content: ORIGINAL.as_bytes().to_vec(),
            mode: 0o600,
        }
    );

    ops.write_file(&path, b"nameserver 1.1.1.1\n", 0o644)
        .unwrap();
    assert_eq!(fixture.read_resolv_conf(), "nameserver 1.1.1.1\n");

    ops.put_back(&path, &taken).unwrap();
    assert_eq!(fixture.read_resolv_conf(), ORIGINAL);
}

#[test]
#[ignore = "requires passwordless sudo"]
fn the_helper_installs_a_symlink_over_a_root_owned_file() {
    require_sudo!();
    let fixture = RootOwnedRootfs::new();
    let ops = privileged(&fixture.path);
    let path = RelPath::parse("/etc/resolv.conf").unwrap();

    ops.write_symlink(&path, "../run/systemd/resolve/stub-resolv.conf")
        .unwrap();

    assert!(fixture.resolv_conf_is_symlink(), "the entry is not a symlink");
}

// The escalation is scoped by the request type, not by what root could reach:
// even running as root, the helper will not accept a path outside its rootfs.
#[test]
#[ignore = "requires passwordless sudo"]
fn the_helper_refuses_to_escape_its_rootfs_even_as_root() {
    require_sudo!();
    let fixture = RootOwnedRootfs::new();
    let ops = privileged(&fixture.path);

    let err = RelPath::parse("/etc/../../../../etc/shadow").unwrap_err();

    assert!(err.to_string().contains(".."), "unexpected error: {err}");
    // And nothing in the fixture changed while proving it.
    drop(ops);
    assert_eq!(fixture.read_resolv_conf(), ORIGINAL);
}

// Closing the channel must end the helper, or a root-owned process holding a
// descriptor into the rootfs would outlive the build.
#[test]
#[ignore = "requires passwordless sudo"]
fn the_helper_exits_when_the_parent_drops_it() {
    require_sudo!();
    let fixture = RootOwnedRootfs::new();
    let before = helper_process_count();

    {
        let ops = privileged(&fixture.path);
        ops.write_file(&RelPath::parse("/etc/resolv.conf").unwrap(), b"x\n", 0o644)
            .unwrap();
        assert!(helper_process_count() > before, "the helper does not appear to be running");
    }

    assert_eq!(helper_process_count(), before, "the helper outlived its parent");
}

// Matches on the process *name*, not the command line: `pgrep -f` also matches
// any shell whose own argv happens to contain the pattern, which makes the
// before/after comparison depend on how the test was invoked.
fn helper_process_count() -> usize {
    let out = std::process::Command::new("pgrep")
        .args(["-xc", "rsdebstrap"])
        .output()
        .expect("failed to run pgrep");
    String::from_utf8(out.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap_or(0)
}
