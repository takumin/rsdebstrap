// Backstop for the gaps the type system leaves in the privilege boundary.
//
// Most of it is closed by types. `CommandSpec`'s fields are private and privilege is only
// reachable through `CommandSpec::privileged`, which takes a closed `PrivilegedProgram`
// enum, so every form the old privileged `cp` could take fails to compile:
//
//     CommandSpec::new("cp", args).with_privilege(p)          // no such method
//     CommandSpec { command: "cp".into(), privilege: p, .. }  // private fields
//     CommandSpec::privileged(PrivilegedProgram::Cp, ..)      // no such variant
//
// A phase task cannot run a spec at all: `IsolationContext` no longer hands out a
// `CommandExecutor`, so `ctx.executor().execute(&spec)` does not compile either. Building
// a spec inside a phase is inert.
//
// Nor can every phase reach `ctx.execute(argv, privilege)`. Only `ProvisionItem::execute`
// receives an `IsolationContext`; `AssembleItem::execute` receives a `RootfsContext`, which
// has no `execute` method. The assemble unit tests in `src/phase/assemble/resolv_conf.rs`
// pin that from the other side: their mock context implements `RootfsContext` and nothing
// else, so widening the signature back would stop compiling.
//
// One thing is still expressible and is not worth contorting the design to forbid:
// `CommandSpec::for_task_command`, which runs the program a provision task declared and so
// takes a name from the profile. Only `DirectContext` should call it, but Rust cannot
// restrict a constructor to one module — `pub(crate)` is the whole crate, and `pub(in path)`
// only restricts to ancestor modules, which `isolation` is not to `executor`. This file
// guards it.

use std::fs;
use std::path::{Path, PathBuf};

// Commands that mutate the filesystem and therefore belong to `RootfsOps`.
const FILESYSTEM_COMMANDS: &[&str] = &["cp", "mv", "rm", "ln", "chmod", "chown", "mkdir", "touch"];

const TASK_CONSTRUCTOR: &str = "for_task_command";

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

// Line index where test code starts, or `None` when the file has no test module. Every
// `#[cfg(test)]` in `src/` is a trailing module at column 0, so anything below the first
// one is test code.
fn test_region_start(contents: &str) -> Option<usize> {
    contents
        .lines()
        .position(|line| line.trim_start().starts_with("#[cfg(test)]"))
}

#[test]
fn the_task_command_constructor_is_not_used_to_mutate_the_rootfs() {
    let mut offenders = Vec::new();

    for path in rust_sources(Path::new("src")) {
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let production_ends = test_region_start(&contents).unwrap_or(usize::MAX);
        let lines: Vec<&str> = contents.lines().collect();

        for (index, line) in lines.iter().enumerate() {
            if index >= production_ends || !line.contains(TASK_CONSTRUCTOR) {
                continue;
            }
            // The argv may be built across several lines, so look at a window: a call is
            // suspicious if a coreutils name appears near the constructor.
            let window = lines[index..lines.len().min(index + 6)].join(" ");
            for command in FILESYSTEM_COMMANDS {
                if window.contains(&format!("\"{command}\"")) {
                    offenders.push(format!("{}:{}: {}", path.display(), index + 1, line.trim()));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a filesystem command reached `{TASK_CONSTRUCTOR}` ({} occurrence(s)):\n{}\n\n\
        That constructor is for the program a provision task declared. To modify the \
        rootfs, use `RootfsOps` (`src/rootfs/`): it resolves each path component with \
        `O_NOFOLLOW` against a directory descriptor, so a planted symlink cannot redirect \
        the write — which a path string handed to `cp` under `sudo` can. See the Privilege \
        boundary section of docs/ARCHITECTURE.md.",
        offenders.len(),
        offenders.join("\n"),
    );
}

// The check above is vacuous if the scan cannot see production code, and it would stay
// green forever if the constructor were renamed. Pin both.
#[test]
fn the_scan_reaches_production_code_and_the_constructor_still_exists() {
    let sources = rust_sources(Path::new("src"));
    assert!(sources.len() > 10, "only found {} sources under src/", sources.len());

    let direct = sources
        .iter()
        .find(|p| p.ends_with("isolation/direct.rs"))
        .expect("expected src/isolation/direct.rs to exist");
    let contents = fs::read_to_string(direct).unwrap();
    let production_ends = test_region_start(&contents).unwrap_or(usize::MAX);

    let reached = contents
        .lines()
        .take(production_ends)
        .any(|l| l.contains(TASK_CONSTRUCTOR));
    assert!(
        reached,
        "`{TASK_CONSTRUCTOR}` is not called in the production half of {} — either the scan \
        is not reaching production code, or the constructor was renamed and this guard is \
        now checking for a name that no longer exists",
        direct.display()
    );
}
