# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

```bash
# Build
cargo build

# Run tests
cargo test

# Run a single test
cargo test <test_name>

# Run tests with output
cargo test -- --nocapture

# Check for errors without building
cargo check

# Lint
cargo clippy

# Format
cargo fmt

# Run the CLI
cargo run -- <command>

# Examples
cargo run -- apply -f examples/debian_trixie_mmdebstrap.yml --dry-run
cargo run -- validate -f examples/debian_trixie_mmdebstrap.yml
```

## Architecture Overview

rsdebstrap is a declarative CLI tool for building Debian-based rootfs images using YAML manifest files. It wraps bootstrap tools (mmdebstrap, debootstrap) and provides post-bootstrap provisioning.

### Core Flow

1. **CLI** (`src/cli.rs`) - Parses arguments using clap, provides `apply`, `validate`, and `completions` subcommands
2. **Config** (`src/config.rs`) - Loads and validates YAML profiles, resolves relative paths
3. **Bootstrap** (`src/bootstrap/`) - Executes bootstrap backends to create the rootfs
4. **Provisioners** (`src/provisioners/`) - Runs post-bootstrap configuration scripts

### Key Abstractions

- **`BootstrapBackend`** trait (`src/bootstrap/mod.rs`) - Interface for bootstrap tools
  - `MmdebstrapConfig` - mmdebstrap implementation
  - `DebootstrapConfig` - debootstrap implementation
  - Each backend builds command arguments and determines output type (directory vs archive)

- **`Provisioner`** trait (`src/provisioners/mod.rs`) - Interface for post-bootstrap steps
  - `ShellProvisioner` - Runs shell scripts in chroot via `chroot` command

- **`CommandExecutor`** trait (`src/executor.rs`) - Abstracts command execution
  - `RealCommandExecutor` - Actual execution with dry-run support
  - Tests use mock executors to verify command construction without running real commands

### Profile Structure (YAML)

```yaml
dir: /output/path           # Base output directory
bootstrap:
  type: mmdebstrap          # Backend type: mmdebstrap | debootstrap
  suite: trixie             # Debian suite
  target: rootfs            # Output name (directory or archive)
  # Backend-specific options...
provisioners:               # Optional post-bootstrap steps
  - type: shell
    content: "..."          # Inline script
    # OR
    script: ./script.sh     # External script path
```

### Testing Pattern

Tests use a mock executor pattern defined in `tests/helpers/mod.rs`. Tests verify that the correct command arguments are generated without executing actual bootstrap commands.
