# Contributing to rsdebstrap

Thanks for your interest in contributing! This is a quickstart; for the full
command set and architecture, see [`AGENTS.md`](AGENTS.md) and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Prerequisites

- A Rust toolchain matching the project's MSRV (see `rust-version` in
  `Cargo.toml`; a pinned `rust-toolchain.toml` is provided).
- Optional: [`task`](https://taskfile.dev/) (go-task) to run the same pipeline
  CI uses.

## Build, test, lint, format

```bash
# Build
cargo build

# Run the test suite
cargo test

# Lint (CI fails on any warning)
cargo clippy --all-targets --all-features

# Format
cargo fmt --all
```

To run the full local pipeline the way CI does:

```bash
task all
```

## JSON Schema

The profile JSON Schema at `schema/rsdebstrap.schema.json` is generated from the
Rust config types. After changing any config type, regenerate it:

```bash
cargo run -- schema > schema/rsdebstrap.schema.json
```

CI enforces that the committed schema is up to date.

## Submitting a pull request

- Branch off `main`.
- Make sure `cargo test` passes and `cargo clippy` / `cargo fmt` are clean.
- Regenerate the schema (`cargo run -- schema > schema/rsdebstrap.schema.json`) if
  you changed any config type.
- Add an entry under `[Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md) for
  user-visible changes.
- Open the PR against `main` and fill in the pull request template.

For deeper design rationale and invariants, read
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
