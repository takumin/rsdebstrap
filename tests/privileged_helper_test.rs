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
use rsdebstrap::rootfs::{FileMode, LocalRootfsOps, Owner, RelPath, RootfsOps, TakenEntry};

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

    fn chown_resolv_conf(&self, spec: &str) {
        sudo(&["chown", spec, self.path.join("etc/resolv.conf").as_str()]);
    }

    // Numeric `%u:%g` rather than the name form, which needs the ids to resolve to a
    // passwd entry and is localized when they do not.
    fn resolv_conf_owner(&self) -> String {
        let out = std::process::Command::new("sudo")
            .args([
                "stat",
                "-c",
                "%u:%g",
                self.path.join("etc/resolv.conf").as_str(),
            ])
            .output()
            .expect("failed to stat through sudo");
        assert!(out.status.success(), "stat failed: {out:?}");
        String::from_utf8(out.stdout).unwrap().trim().to_string()
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
            mode: FileMode::new(0o600),
            owner: Owner { uid: 0, gid: 0 },
        }
    );

    ops.write_file(&path, b"nameserver 1.1.1.1\n", FileMode::new(0o644))
        .unwrap();
    assert_eq!(fixture.read_resolv_conf(), "nameserver 1.1.1.1\n");

    ops.put_back(&path, &taken).unwrap();
    assert_eq!(fixture.read_resolv_conf(), ORIGINAL);
}

// `put_back` reinstalls the entry as a new inode, and the process writing it is root for
// the whole of a privileged run, so an owner that is not root survives only if the entry
// carried it. A root-owned original would pass either way; this one cannot. The id is
// unlikely to resolve to a passwd entry, which is fine -- `chown` takes it numerically,
// and so does the assertion.
#[test]
#[ignore = "requires passwordless sudo"]
fn the_helper_restores_an_owner_that_is_not_its_own() {
    require_sudo!();
    let fixture = RootOwnedRootfs::new();
    fixture.chown_resolv_conf("12345:12345");
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
            mode: FileMode::new(0o600),
            owner: Owner {
                uid: 12345,
                gid: 12345
            },
        }
    );

    ops.write_file(&path, b"nameserver 1.1.1.1\n", FileMode::new(0o644))
        .unwrap();
    assert_eq!(
        fixture.resolv_conf_owner(),
        "0:0",
        "the helper's own write should belong to root, or the test proves nothing"
    );

    ops.put_back(&path, &taken).unwrap();
    assert_eq!(fixture.resolv_conf_owner(), "12345:12345");
    assert_eq!(fixture.read_resolv_conf(), ORIGINAL);
}

#[test]
#[ignore = "requires passwordless sudo"]
fn the_helper_installs_a_symlink_over_a_root_owned_file() {
    require_sudo!();
    let fixture = RootOwnedRootfs::new();
    let ops = privileged(&fixture.path);
    let path = RelPath::parse("/etc/resolv.conf").unwrap();

    ops.write_symlink(&path, b"../run/systemd/resolve/stub-resolv.conf")
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

    {
        let ops = privileged(&fixture.path);
        ops.write_file(&RelPath::parse("/etc/resolv.conf").unwrap(), b"x\n", FileMode::new(0o644))
            .unwrap();
        assert!(helper_is_running(&fixture.path), "the helper does not appear to be running");
    }

    // `Drop` reaps the helper before returning, so this needs no settling time: if
    // the process is still matched here, it was genuinely left behind.
    assert!(!helper_is_running(&fixture.path), "the helper outlived its parent");
}

// Scoped to this test's own helper by its rootfs, which the helper carries in argv.
// A machine-wide count of `rsdebstrap` processes would instead couple the result to
// the other tests in this binary: they run concurrently and spawn helpers of their
// own, so a sibling starting or exiting between two samples moves the count on its
// own. The tempdir path is unique to this fixture, which is also what makes `-f`
// safe here where a bare `rsdebstrap` pattern was not — no unrelated process, and
// no shell that happened to invoke this test, names this directory.
// `output` rather than `status` so the matched PIDs are captured instead of landing
// in the test's own stdout.
fn helper_is_running(rootfs: &camino::Utf8Path) -> bool {
    std::process::Command::new("pgrep")
        .args(["-f", &format!("__rootfs-helper --rootfs {rootfs}")])
        .output()
        .expect("failed to run pgrep")
        .status
        .success()
}

// A bind mount is a second name for a directory that no amount of path canonicalization
// reveals: `<tmpdir>` and `/etc` are different paths, resolve to themselves, and are the
// same inode. The anchor check compares the opened descriptor's device and inode against
// the live system's, so it refuses this; the string comparison it replaced did not.
//
// Needs `sudo` for the mount, not for the helper — the helper is spawned unprivileged
// here, since what is under test is the refusal, which happens before anything is served.
#[test]
#[ignore]
fn the_helper_refuses_an_anchor_bind_mounted_from_the_live_system() {
    require_sudo!();

    let tmp = tempfile::tempdir().unwrap();
    let target = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();

    sudo(&["mount", "--bind", "-o", "ro", "/etc", target.as_str()]);
    let _unmount = BindMount(target.clone());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rsdebstrap"))
        .args(["__rootfs-helper", "--rootfs", target.as_str()])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to spawn helper");

    assert!(!output.status.success(), "a bind mount of /etc should be refused");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not a rootfs"), "unexpected stderr: {stderr}");
}

// Unmounts on the way out so a failed assertion above does not leave the bind mount
// behind; the tempdir's own `Drop` would otherwise fail to remove a mounted directory.
struct BindMount(Utf8PathBuf);

impl Drop for BindMount {
    fn drop(&mut self) {
        let _ = std::process::Command::new("sudo")
            .args(["umount", self.0.as_str()])
            .status();
    }
}
