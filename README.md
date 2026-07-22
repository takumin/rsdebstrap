# rsdebstrap

> A declarative CLI tool to build Debian-based rootfs images using mmdebstrap and YAML manifests

[![CI](https://github.com/takumin/rsdebstrap/actions/workflows/ci.yml/badge.svg)](https://github.com/takumin/rsdebstrap/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

rsdebstrap builds Debian/Ubuntu root filesystems from a single declarative YAML
profile. It wraps the standard bootstrap tools (`mmdebstrap`, `debootstrap`) and
adds a post-bootstrap provisioning pipeline — mounts, DNS setup, shell scripts,
and [mitamae](https://github.com/itamae-kitchen/mitamae) recipes — each step run
in its own isolation context with optional privilege escalation.

Instead of a bespoke build script per image, you describe the whole build once
and run `rsdebstrap apply`.

## Features

- **Declarative** — the entire rootfs build lives in one YAML profile.
- **Multiple backends** — `mmdebstrap` or `debootstrap`.
- **Three-phase pipeline** — `prepare` → `provision` → `assemble`, run in order.
- **Provisioners** — inline or external shell scripts and mitamae recipes.
- **Per-task isolation & privilege** — chroot isolation by default, with optional
  `sudo`/`doas` escalation, both overridable per task.
- **JSON Schema** — a committed schema for editor completion and validation.
- **Shell completions** — bash, zsh, fish, powershell, elvish.

## Requirements

At runtime rsdebstrap invokes external tools, so at least one bootstrap backend
must be on your `PATH`:

- **`mmdebstrap`** or **`debootstrap`** — the bootstrap backend (required; the
  chosen backend is checked on `PATH` before running).
- **`sudo`** or **`doas`** — only when a profile requests privilege escalation
  (required when mounts are configured).
- A **`mitamae`** binary — only when a profile uses the `mitamae` provisioner.

Building from source additionally requires **Rust 1.97+** (edition 2024). This
minimum supported version is declared as `rust-version` in `Cargo.toml`, so
`cargo` and downstream packagers can read it directly.

## Installation

rsdebstrap is not yet published to crates.io, and no prebuilt binaries are
available yet — install from source for now.

With cargo, install the latest directly from Git:

```sh
cargo install --git https://github.com/takumin/rsdebstrap
```

Or build a local checkout:

```sh
git clone https://github.com/takumin/rsdebstrap
cd rsdebstrap
cargo build --release
# binary at target/release/rsdebstrap
```

Prebuilt, signed binaries for multiple Linux targets (gnu/musl across x86_64,
i686, aarch64, armv7) are attached to GitHub Releases once a version is tagged.

## Usage

From a checkout, try it against the bundled example profile:

```sh
# Validate a profile (syntax + schema, no bootstrap)
cargo run -- validate -f examples/debian_trixie_mmdebstrap.yml

# Preview the bootstrap command without executing it
cargo run -- apply -f examples/debian_trixie_mmdebstrap.yml --dry-run
```

With the installed binary, the core commands are:

```sh
# Validate, then dry-run, then build for real
rsdebstrap validate -f profile.yml
rsdebstrap apply -f profile.yml --dry-run
rsdebstrap apply -f profile.yml
```

`-f`/`--file` defaults to `profile.yml`, and `-l`/`--log-level` controls
verbosity (`trace`, `debug`, `info`, `warn`, `error`; default `info`).

### Shell completions

```sh
# bash (add to ~/.bashrc)
eval "$(rsdebstrap completions bash)"

# zsh (save to a completion directory)
rsdebstrap completions zsh > ~/.zsh/completion/_rsdebstrap
```

Completions are available for bash, zsh, fish, powershell, and elvish.

### JSON Schema

Print the profile schema (generated from the Rust config types) — useful for
editor completion and validation:

```sh
rsdebstrap schema > rsdebstrap.schema.json
```

## Profile format

A profile declares an output directory, optional `defaults`, a `bootstrap`
backend, and the `prepare` / `provision` / `assemble` pipeline phases:

```yaml
dir: /tmp/debian-trixie
bootstrap:
  type: mmdebstrap
  suite: trixie
  target: rootfs
provision:
  - type: shell
    content: |-
      #!/bin/sh
      set -e
      apt-get update && apt-get install -y vim
```

- Full annotated example: [`examples/debian_trixie_mmdebstrap.yml`](examples/debian_trixie_mmdebstrap.yml)
- Machine-readable schema: [`schema/rsdebstrap.schema.json`](schema/rsdebstrap.schema.json)
- Field-by-field reference: [`AGENTS.md`](AGENTS.md)
- Internal design and invariants: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

## Contributing

Contributions are welcome. Build with `cargo build`, run the test suite with
`cargo test --workspace`, and see [`AGENTS.md`](AGENTS.md) and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the development commands and
architecture before making changes. After changing any config type, regenerate
the committed schema with `task schema` (CI enforces this).

## License

Licensed under the [Apache License 2.0](LICENSE).
