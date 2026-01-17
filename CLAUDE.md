# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

rsdebstrap is a declarative CLI tool for building Debian-based rootfs images using mmdebstrap and YAML manifests. It provides a Rust wrapper around the mmdebstrap utility, allowing users to define bootstrap configurations in YAML files.

## Development Commands

This project uses Task (taskfile.dev) for workflow automation. The main Taskfile is at the root, with included task files in the `tasks/` directory.

### Common Commands

```bash
# Run all checks (format, lint, test, build)
task

# Build the project
task build

# Run tests
task test

# Format code
task format

# Lint/Review
task reviewdog

# Run the CLI
cargo run -- apply -f examples/debian_trixie.yml --dry-run
cargo run -- validate -f examples/debian_trixie.yml
cargo run -- completions bash
```

### Build Targets

The project supports multiple Linux targets via cargo-zigbuild:
- x86_64-unknown-linux-gnu / musl
- i686-unknown-linux-gnu / musl
- aarch64-unknown-linux-gnu / musl
- armv7-unknown-linux-gnueabihf / musleabihf

```bash
# Build for specific target
BUILD_TARGET=aarch64-unknown-linux-musl task build:build

# Build release for specific target
BUILD_PROFILE=release BUILD_TARGET=x86_64-unknown-linux-gnu task build:build
```

## Architecture

### Module Structure

The codebase follows a clean separation of concerns:

- **cli.rs**: Command-line interface definitions using clap. Defines the `Cli`, `Commands` enum (Apply, Validate, Completions), and their associated argument structs.

- **config.rs**: Configuration data structures and YAML deserialization. Core types:
  - `Profile`: Top-level configuration with `dir` (output directory) and `mmdebstrap` settings
  - `Mmdebstrap`: Contains all mmdebstrap configuration (suite, target, mode, format, variant, hooks, etc.)
  - Enums: `Variant` (package selection strategy), `Mode` (execution mode), `Format` (output format)
  - `load_profile()`: Loads and validates YAML configuration files

- **builder.rs**: Translates `Profile` configuration into mmdebstrap command-line arguments. The `build_mmdebstrap_args()` function converts structured config into the flat argument list that mmdebstrap expects.

- **executor.rs**: Command execution abstraction. Provides the `CommandExecutor` trait and `RealCommandExecutor` implementation for running external commands (mmdebstrap). Handles dry-run mode and command validation via `which`.

- **main.rs**: Entry point that orchestrates the flow:
  1. Parse CLI arguments
  2. Set up tracing/logging
  3. Load profile configuration
  4. Build mmdebstrap arguments
  5. Execute command

### Data Flow

1. User provides YAML profile (e.g., `examples/debian_trixie.yml`)
2. `config::load_profile()` deserializes YAML into `Profile` struct
3. `builder::build_mmdebstrap_args()` converts `Profile` to command arguments
4. `executor::RealCommandExecutor` runs the mmdebstrap command
5. mmdebstrap creates the rootfs in the specified directory and format

### Test Helpers

The `tests/helpers/mod.rs` module provides test utilities:
- `create_mmdebstrap()`: Factory function to create `Mmdebstrap` configs with default values, simplifying test setup

### YAML Profile Structure

Example profiles in `examples/` directory show the expected YAML format:
```yaml
dir: /tmp/debian-trixie-server-amd64
mmdebstrap:
  suite: trixie
  target: rootfs.tar.zst
  mirrors:
    - https://deb.debian.org/debian
  variant: apt
  components:
    - main
    - contrib
  architectures:
    - amd64
  include:
    - curl
    - ca-certificates
```

## Key Implementation Details

### Hook Types

mmdebstrap supports multiple hook phases (defined in `config.rs`):
- `setup_hook`: Runs before package extraction
- `extract_hook`: Runs after package extraction
- `essential_hook`: Runs after essential packages are installed
- `customize_hook`: Runs before final image creation

### Argument Building

The builder uses helper functions `add_flag()` and `add_flags()` to conditionally add arguments only when values are non-empty, ensuring clean command-line argument lists.

### Logging

The application uses the `tracing` crate with configurable log levels (trace, debug, info, warn, error) via CLI flags. Completions command bypasses logging setup to produce clean output.

## Adding New Features

### Adding New mmdebstrap Options

1. Add field to `Mmdebstrap` struct in `config.rs` with `#[serde(default)]`
2. Add argument construction logic in `builder.rs` (use `add_flag` or `add_flags`)
3. Add test case in `tests/builder_test.rs` to verify argument generation
4. Update example YAML in `examples/` if applicable

### Adding New CLI Commands

1. Add variant to `Commands` enum in `cli.rs`
2. Create associated `Args` struct with command arguments
3. Handle command in `main.rs` match statement
4. Add corresponding tests in `tests/cli_test.rs`

### Testing Strategy

- Unit tests for argument building (`builder_test.rs`)
- Config parsing tests (`config_test.rs`)
- CLI argument parsing tests (`cli_test.rs`)
- Use `tests/helpers/create_mmdebstrap()` for consistent test fixtures
