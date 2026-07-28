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
cargo check --all-targets --all-features --quiet

# Also check the schema-less build: schema generation lives behind the default-on
# `schema` cargo feature, and a missed `cfg_attr` gate only surfaces here.
cargo check --all-targets --no-default-features --quiet

# Generate the profile JSON Schema (derived from the Rust config types).
# Regenerate the committed copy after any config-type change, or `cargo test` fails.
# The autofix.ci workflow also runs this on PRs and auto-commits any drift.
task schema  # equivalent to: cargo run -- schema > schema/rsdebstrap.schema.json

# Formal verification (Verus for src/domain/, Kani for the pure kernels in the
# infrastructure layer). Opt-in — not part of `task all`, and non-gating in CI
# (.github/workflows/wc-verify.yml). Neither tool is aqua-pinned and both install
# from GitHub Releases, so this cannot run in environments without github.com
# egress; `task verify` reports that rather than appearing to pass. The same
# properties are checked over a finite domain by `cargo test`, which does gate.
task verify  # see docs/FORMAL_METHODS.md before touching src/domain/
```

## Architecture Overview

**For internal design rationale, invariants (TOCTOU/RAII), and the testing approach,
see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).** Read it before changing the
resolution model, the phase pipeline, isolation/privilege plumbing, or the
filesystem-safety code — it captures decisions that are not obvious from the source.

**For the verification layering — which layer is proved with which tool, the properties
the resolution model is held to, and what is deliberately left unproved — see
[`docs/FORMAL_METHODS.md`](docs/FORMAL_METHODS.md).** `src/domain/` is subject to a hard
dependency rule (no I/O, no `serde`, no other module in this crate); read that document
before adding anything to it or changing `Privilege`/`TaskIsolation` resolution.

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

## Profile Structure (YAML)

A machine-readable JSON Schema for this format is committed at
[`schema/rsdebstrap.schema.json`](schema/rsdebstrap.schema.json) (usable for editor
completion/validation). It is generated from the Rust config types — regenerate it with
`task schema` (or `cargo run -- schema > schema/rsdebstrap.schema.json`) after any
config-type change; the autofix.ci workflow also regenerates it and auto-commits drift
to pull requests (see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#json-schema-generation)).

**For the full profile format — every field's meaning, the YAML scalar/null rules, the
`privilege` and `isolation` tri-states, and the `mount` / `resolv_conf` invariants — see
[`docs/PROFILE.md`](docs/PROFILE.md).** Read it before writing or reviewing a profile,
changing `src/config.rs`, or touching profile validation; those rules are not all
recoverable from the schema alone.
