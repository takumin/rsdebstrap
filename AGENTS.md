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
4. **Pipeline** (`src/pipeline.rs`) - Orchestrates pre-processors, provisioners, and post-processors in order

### Key Abstractions

- **`BootstrapBackend`** trait (`src/bootstrap/mod.rs`) - Interface for bootstrap tools
  - `MmdebstrapConfig` - mmdebstrap implementation
  - `DebootstrapConfig` - debootstrap implementation
  - Each backend builds command arguments and determines output type (directory vs archive)

- **`TaskDefinition`** enum (`src/task/mod.rs`) - Declarative task definition for pipeline steps
  - `ShellTask` (`src/task/shell.rs`) - Runs shell scripts within an isolation context
  - Enum-based dispatch with compile-time exhaustive matching

- **`Pipeline`** struct (`src/pipeline.rs`) - Orchestrates task execution in three phases
  - Manages isolation context lifecycle (setup/teardown)
  - Executes pre-processors, provisioners, post-processors in order
  - Guarantees teardown even on phase errors

- **`IsolationProvider`** / **`IsolationContext`** traits (`src/isolation/mod.rs`) - Isolation backends
  - `ChrootProvider` / `ChrootContext` - chroot-based isolation

- **`CommandExecutor`** trait (`src/executor/mod.rs`) - Abstracts command execution
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
pre_processors:             # Optional pre-provisioning steps
  - type: shell
    content: "..."
provisioners:               # Optional main provisioning steps
  - type: shell
    content: "..."          # Inline script
    # OR
    script: ./script.sh     # External script path
post_processors:            # Optional post-provisioning steps
  - type: shell
    script: ./cleanup.sh
```

### Testing Pattern

Tests use a mock executor pattern defined in `tests/helpers/mod.rs`. Tests verify that the correct command arguments are generated without executing actual bootstrap commands.
