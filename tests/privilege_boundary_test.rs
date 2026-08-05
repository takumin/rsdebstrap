// Guards the privilege boundary documented in `AGENTS.md` (Privilege boundary).
//
// Rationale: rootfs mutation used to run as `sudo cp` / `sudo mv` / `sudo chmod` on path
// strings, which is what made the `openat(O_NOFOLLOW)` checks unable to hold — a name
// resolved twice can name two different inodes. It now goes through `RootfsOps`, which is
// anchored to a descriptor.
//
// Nothing in the type system prevents reintroducing the old shape: `CommandSpec::new("cp",
// ...).with_privilege(...)` compiles fine and looks perfectly ordinary in review, and the
// tests of whatever task did it would pass. The regression would be invisible until
// someone re-derived the whole argument. So the boundary needs its own check.
//
// Note this is a *shape* check, not a proof. It catches the obvious way back, not a
// determined one (a command name built at runtime, say). That is the same bargain
// `comment_style_test.rs` makes.

use std::fs;
use std::path::{Path, PathBuf};

// Commands that mutate the filesystem and therefore belong to `RootfsOps`. `mount`,
// `umount`, `chroot` and the bootstrap backends are absent on purpose: they are external
// programs with no syscall equivalent here, and they legitimately escalate per command.
const FILESYSTEM_COMMANDS: &[&str] = &["cp", "mv", "rm", "ln", "chmod", "chown", "mkdir", "touch"];

fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("cannot read directory entry").path();
        if path.is_dir() {
            found.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
    found.sort();
    found
}

// Line index where test code starts, or `None` when the file has no test module.
// Mirrors `comment_style_test.rs`: every `#[cfg(test)]` in `src/` is a trailing module at
// column 0, so anything below the first one is test code.
fn test_region_start(contents: &str) -> Option<usize> {
    contents
        .lines()
        .position(|line| line.trim_start().starts_with("#[cfg(test)]"))
}

#[test]
fn production_code_does_not_shell_out_to_mutate_the_rootfs() {
    let mut offenders = Vec::new();

    for path in rust_sources(Path::new("src")) {
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let production_ends = test_region_start(&contents).unwrap_or(usize::MAX);

        for (index, line) in contents.lines().enumerate() {
            if index >= production_ends {
                break;
            }
            for command in FILESYSTEM_COMMANDS {
                if line.contains(&format!("CommandSpec::new(\"{command}\"")) {
                    offenders.push(format!("{}:{}: {}", path.display(), index + 1, line.trim()));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "rootfs mutation shelling out to coreutils ({} occurrence(s)):\n{}\n\n\
        Use `RootfsOps` (`src/rootfs/`) instead. It resolves each path component with \
        `O_NOFOLLOW` against a directory descriptor, so a planted symlink cannot redirect \
        the write; a path string handed to `cp` under `sudo` can. See the Privilege \
        boundary section of docs/ARCHITECTURE.md.",
        offenders.len(),
        offenders.join("\n"),
    );
}

// The check above is only meaningful if it can actually see production code — a `src/`
// that failed to enumerate, or a `#[cfg(test)]` detected at line 0, would make it vacuous.
#[test]
fn the_scan_covers_production_code() {
    let sources = rust_sources(Path::new("src"));
    assert!(sources.len() > 10, "only found {} sources under src/", sources.len());

    // `MountEntry::mount_spec` legitimately shells out to `mount`, so the scan must reach
    // it — if the region calculation excluded everything, the check above would pass by
    // seeing nothing at all.
    let config = sources
        .iter()
        .find(|p| p.ends_with("config.rs"))
        .expect("expected src/config.rs to exist");
    let contents = fs::read_to_string(config).unwrap();

    let production_ends = test_region_start(&contents).unwrap_or(usize::MAX);
    let reached = contents
        .lines()
        .take(production_ends)
        .any(|l| l.contains("CommandSpec::new(\"mount\""));
    assert!(reached, "the scan does not reach production code in {}", config.display());
}
