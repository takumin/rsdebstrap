// Guards the test-comment convention documented in `AGENTS.md` (Code Comments).
//
// Rationale: doc comments are product surface in this repo — on config types they
// become JSON Schema `description` fields, and in `src/cli.rs` they become `--help`
// text. Test code reaches neither schemars, nor clap, nor rustdoc, so the doc-comment
// form carries no meaning there and only makes maintainer-only rationale look like
// published documentation. Nothing in the compiler or clippy rejects it (the
// `unused_doc_comments` lint fires on statements and expressions, not on items), so
// the convention needs its own check or it drifts back one PR at a time.

use std::fs;
use std::path::{Path, PathBuf};

// Both doc-comment forms, checked with the marker split out so this file does not
// trip its own scan.
const OUTER_DOC: &str = "///";
const INNER_DOC: &str = "//!";

// `.rs` files under `dir`, recursively.
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
// Every `#[cfg(test)]` in `src/` is a trailing test module at column 0; a nested or
// mid-file one would silently widen this range, so reject that shape outright.
fn test_region_start(path: &Path, contents: &str) -> Option<usize> {
    let lines: Vec<&str> = contents.lines().collect();
    let mut markers = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.trim_start().starts_with("#[cfg(test)]"));
    let (first, _) = markers.next()?;
    assert!(
        markers.next().is_none(),
        concat!(
            "{}: multiple `#[cfg(test)]` attributes. This check assumes a single trailing ",
            "test module; extend it before introducing a second one, or it will scan ",
            "production code as if it were test code."
        ),
        path.display(),
    );

    // An outer doc comment above the attribute documents the test module itself, so the
    // region has to start there or the convention check misses it. Blank lines between
    // the comment and the item do not break that attachment, so walk past them too --
    // but only commit to an earlier start once a doc line is actually found, otherwise a
    // blank line alone would drag production code into the scanned region.
    let mut start = first;
    let mut cursor = first;
    while cursor > 0 {
        cursor -= 1;
        let trimmed = lines[cursor].trim_start();
        if trimmed.starts_with(OUTER_DOC) {
            start = cursor;
        } else if !trimmed.is_empty() {
            break;
        }
    }
    Some(start)
}

fn doc_comments_in(path: &Path, contents: &str, from_line: usize) -> Vec<String> {
    contents
        .lines()
        .enumerate()
        .skip(from_line)
        .filter(|(_, line)| {
            let trimmed = line.trim_start();
            trimmed.starts_with(OUTER_DOC) || trimmed.starts_with(INNER_DOC)
        })
        .map(|(index, line)| format!("{}:{}: {}", path.display(), index + 1, line.trim()))
        .collect()
}

#[test]
fn test_code_uses_plain_comments() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let mut violations = Vec::new();

    // Integration tests are test code end to end.
    for path in rust_sources(&root.join("tests")) {
        let contents = fs::read_to_string(&path).expect("cannot read test source");
        violations.extend(doc_comments_in(&path, &contents, 0));
    }

    // Unit tests start at the `#[cfg(test)]` module; everything above it is the
    // production surface where doc comments belong.
    for path in rust_sources(&root.join("src")) {
        let contents = fs::read_to_string(&path).expect("cannot read source");
        if let Some(start) = test_region_start(&path, &contents) {
            violations.extend(doc_comments_in(&path, &contents, start));
        }
    }

    assert!(
        violations.is_empty(),
        concat!(
            "doc comments in test code ({} occurrence(s)):\n{}\n\n",
            "Use plain `//` comments in test code. `///` and `//!` are product surface ",
            "(JSON Schema descriptions, `--help` text) and render as nothing here."
        ),
        violations.len(),
        violations.join("\n"),
    );
}
