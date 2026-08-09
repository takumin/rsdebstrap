// `RootfsOps::write_file` promises the mode it is given, exactly.
//
// That promise is only observable under a umask that would mask bits off, and umask is
// per-process state: setting it inside one `#[test]` would leak into every other test
// sharing the binary. So these tests live in a binary of their own — cargo gives each
// integration test file its own process — and every test here sets the same restrictive
// value, which makes the write idempotent no matter what order they run in.
//
// Without this, an `openat(O_CREAT, …, 0o644)` under `umask 077` silently produces 0600.
// The visible damage is `put_back`: it restores a taken entry with the mode it recorded,
// so a root-only /etc/resolv.conf would be left behind in the built image.

use std::os::unix::fs::PermissionsExt;

use camino::Utf8PathBuf;
use rsdebstrap::rootfs::{FileMode, LocalRootfsOps, Owner, RelPath, RootfsOps, TakenEntry};
use rustix::fs::Mode;

// Strips group and other bits — the bits every mode asserted below wants to keep.
const RESTRICTIVE_UMASK: rustix::fs::RawMode = 0o077;

fn rootfs() -> (tempfile::TempDir, Utf8PathBuf) {
    rustix::process::umask(Mode::from_raw_mode(RESTRICTIVE_UMASK));
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
    std::fs::create_dir_all(root.join("etc")).unwrap();
    (tmp, root)
}

fn mode_of(path: &camino::Utf8Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn owner_of(path: &camino::Utf8Path) -> Owner {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path).unwrap();
    Owner {
        uid: meta.uid(),
        gid: meta.gid(),
    }
}

#[test]
fn write_file_lands_the_requested_mode_under_a_restrictive_umask() {
    let (_tmp, root) = rootfs();
    let ops = LocalRootfsOps::open(&root).unwrap();

    for requested in [0o644, 0o755, 0o600, 0o777] {
        let path = RelPath::parse(&format!("/etc/mode-{requested:o}")).unwrap();
        ops.write_file(&path, b"x", FileMode::new(requested))
            .unwrap();
        assert_eq!(
            mode_of(&root.join(format!("etc/mode-{requested:o}"))),
            requested,
            "requested {requested:o}"
        );
    }
}

// The reason the exactness matters: a resolv.conf detached from the rootfs and restored
// on teardown has to come back with the permissions it had, not with permissions the
// build process's umask happened to allow.
#[test]
fn put_back_restores_the_mode_the_entry_carried() {
    let (_tmp, root) = rootfs();
    let ops = LocalRootfsOps::open(&root).unwrap();
    let path = RelPath::parse("/etc/resolv.conf").unwrap();

    std::fs::write(root.join("etc/resolv.conf"), b"nameserver 9.9.9.9\n").unwrap();
    std::fs::set_permissions(root.join("etc/resolv.conf"), std::fs::Permissions::from_mode(0o644))
        .unwrap();

    let owner = owner_of(&root.join("etc/resolv.conf"));
    let taken = ops.take(&path).unwrap().unwrap();
    assert_eq!(
        taken,
        TakenEntry::File {
            content: b"nameserver 9.9.9.9\n".to_vec(),
            mode: FileMode::new(0o644),
            owner,
        }
    );

    ops.write_file(&path, b"nameserver 1.1.1.1\n", FileMode::new(0o644))
        .unwrap();
    ops.put_back(&path, &taken).unwrap();

    assert_eq!(mode_of(&root.join("etc/resolv.conf")), 0o644);
}

// Writing to a file clears its setuid/setgid bits, so a mode carrying them only survives
// if it is applied after the content. `take` records what it found; `put_back` must not
// quietly downgrade it.
#[test]
fn put_back_restores_setgid() {
    let (_tmp, root) = rootfs();
    let ops = LocalRootfsOps::open(&root).unwrap();
    let path = RelPath::parse("/etc/setgid-file").unwrap();

    ops.write_file(&path, b"payload", FileMode::new(0o2755))
        .unwrap();
    let owner = owner_of(&root.join("etc/setgid-file"));
    let taken = ops.take(&path).unwrap().unwrap();
    assert_eq!(
        taken,
        TakenEntry::File {
            content: b"payload".to_vec(),
            mode: FileMode::new(0o2755),
            owner,
        }
    );

    ops.put_back(&path, &taken).unwrap();
    assert_eq!(mode_of(&root.join("etc/setgid-file")), 0o2755);
}

// `take` reads a full `st_mode`, whose high bits encode the file type. Feeding those to a
// chmod would be an error; `FileMode` masks them at construction so it cannot happen.
#[test]
fn file_mode_keeps_only_permission_bits() {
    const S_IFREG: u32 = 0o100_000;
    assert_eq!(FileMode::new(S_IFREG | 0o644).bits(), 0o644);
    assert_eq!(FileMode::new(0o2755).bits(), 0o2755);
    assert_eq!(FileMode::new(S_IFREG | 0o644).to_string(), "644");
}
