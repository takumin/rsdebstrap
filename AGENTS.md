# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Build and Development Commands

```bash
# Measure code coverage (cargo-llvm-cov). Opt-in — not part of `task all`; rebuilds
# the workspace with instrumentation and prints a per-file + TOTAL table. CI runs it
# via aqua as an informational (non-gating) job (.github/workflows/wc-coverage.yml).
# Run the command directly rather than `task coverage` in environments where aqua
# cannot fetch GitHub Releases (e.g. Claude Code on the web) — install from crates.io:
cargo install cargo-llvm-cov --version 0.8.7 --locked  # once; matches the aqua pin
cargo llvm-cov --workspace

# Check for errors without building
cargo check --all-targets --quiet

# Tests requiring passwordless sudo are #[ignore]d and skip themselves without it.
# They cover real privilege escalation (see Privilege boundary below).
cargo test --workspace -- --ignored

# Generate the profile JSON Schema (derived from the Rust config types).
# Regenerate the committed copy after any config-type change, or `cargo test` fails.
# The autofix.ci workflow also runs this on PRs and auto-commits any drift.
task schema  # equivalent to: cargo run -- schema > schema/rsdebstrap.schema.json
```

## Architecture Overview

**For internal design rationale, invariants (TOCTOU/RAII), and the testing approach,
see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).** Read it before changing the
resolution model, the phase pipeline, isolation/privilege plumbing, or the
filesystem-safety code — it captures decisions that are not obvious from the source.

## Privilege boundary

**Never mutate the rootfs by running a command.** `cp`/`mv`/`rm`/`ln`/`chmod` under
`sudo` take path *strings*, so a name checked once and resolved again can name two
different inodes — a symlink planted in between redirects a privileged write. Use
[`RootfsOps`](src/rootfs/) instead: it resolves each path component with `O_NOFOLLOW`
against a directory descriptor, and its `RelPath` cannot express a path outside the
rootfs. Escalation happens once per run, in the helper process `rootfs::open()` spawns.

`tests/privilege_boundary_test.rs` fails on the obvious way back. External programs with
no syscall equivalent (`mount`, `umount`, `chroot`, the bootstrap backends) legitimately
escalate per command and are exempt.

Corollary: privilege for rootfs mutation is a property of the *run*, not of a task, so
resist adding a per-task `privilege` key to anything that only writes files — it cannot
be honored. See the Privilege boundary section of
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Code Comments

- Write `//` comments only for what the code cannot say: rationale, constraints,
  invariants, platform quirks, rejected alternatives, ordering requirements, and
  external tool contracts. Never write a comment that restates what the adjacent code
  does — it adds nothing and goes stale when the code changes. Delete such comments on
  sight.
- In tests, comments that explain scenario choreography (which mock call fails and why,
  what an expected argv shape maps to, why a fixture deliberately omits something) are
  valuable; comments that restate the assertion below them are not.
- `///` doc comments are product surface, not commentary: on config types they become
  `description` fields in the generated JSON Schema, and in `src/cli.rs` they become
  `--help` text. Keep maintainer-only notes in plain `//` comments so they do not leak
  into schema or help output.
- Test code uses `//` only — never `///` or `//!`, and no exception for test modules
  being invisible to schema and `--help`. Enforced by `tests/comment_style_test.rs`,
  which explains the reasoning when it fires.
- Prefer moving a claim into a test over arguing it in a comment. Several long notes here
  were replaced that way: the serde `deny_unknown_fields` behaviour, the phase ordering
  (now carried by the `Provisioned`/`Restored` tokens), and the rule above.

## Profile Structure (YAML)

A machine-readable JSON Schema for this format is committed at
[`schema/rsdebstrap.schema.json`](schema/rsdebstrap.schema.json) (usable for editor
completion/validation). It is generated from the Rust config types — regenerate it with
`task schema` (or `cargo run -- schema > schema/rsdebstrap.schema.json`) after any
config-type change; the autofix.ci workflow also regenerates it and auto-commits drift
to pull requests (see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#json-schema-generation)).

**For the profile format — the pipeline fields' meaning, the YAML scalar/null rules, the
four-state `privilege` / `isolation` resolution, and the `mount` / `resolv_conf`
invariants — see [`docs/PROFILE.md`](docs/PROFILE.md)** (the backend-specific keys inside
`bootstrap:` are documented by the generated schema, not there). Read it before writing
or reviewing a profile, changing `src/config.rs`, or touching profile validation; those
rules are not all recoverable from the schema alone.
