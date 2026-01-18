# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

rsdebstrap is a declarative CLI tool for building Debian-based rootfs images using multiple bootstrap tools (mmdebstrap, debootstrap) and YAML manifests. It provides a Rust wrapper with a pluggable backend architecture, allowing users to define bootstrap configurations in YAML files with their choice of bootstrap tool.

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
cargo run -- apply -f examples/debian_trixie_mmdebstrap.yml --dry-run
cargo run -- apply -f examples/debian_trixie_debootstrap.yml --dry-run
cargo run -- validate -f examples/debian_trixie_mmdebstrap.yml
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

The codebase follows a clean separation of concerns with a pluggable backend architecture:

- **cli.rs**: Command-line interface definitions using clap. Defines the `Cli`, `Commands` enum (Apply, Validate, Completions), and their associated argument structs.

- **config.rs**: Configuration data structures and YAML deserialization. Core types:
  - `Profile`: Top-level configuration with `dir` (output directory) and `bootstrap` configuration
  - `Bootstrap`: Tagged union enum that holds different bootstrap backend configurations
    - `as_backend()`: Returns a `&dyn BootstrapBackend` trait object for polymorphic access
  - `load_profile()`: Loads and validates YAML configuration files

- **backends/**: Pluggable bootstrap backend implementations:
  - **mod.rs**: Defines the `BootstrapBackend` trait that all backends implement
  - **mmdebstrap.rs**: mmdebstrap backend with `MmdebstrapConfig` and implementation. Contains mmdebstrap-specific types like `Mode`, `Format`, `Variant`, and hooks configuration
  - **debootstrap.rs**: debootstrap backend with `DebootstrapConfig` and implementation. Contains debootstrap-specific types like `Variant` and options

- **executor.rs**: Command execution abstraction. Provides the `CommandExecutor` trait and `RealCommandExecutor` implementation for running external commands. Handles dry-run mode and command validation via `which`.

- **main.rs**: Entry point that orchestrates the flow:
  1. Parse CLI arguments
  2. Set up tracing/logging
  3. Load profile configuration
  4. Get backend as trait object via `as_backend()` (avoids duplicating logic per backend)
  5. Build backend-specific arguments via `build_args()`
  6. Execute command with appropriate tool

### Data Flow

1. User provides YAML profile (e.g., `examples/debian_trixie_mmdebstrap.yml`)
2. `config::load_profile()` deserializes YAML into `Profile` struct
3. YAML's `bootstrap.type` field determines which backend enum variant is used
4. Backend's `build_args()` method converts config to command arguments
5. `executor::RealCommandExecutor` runs the appropriate bootstrap command
6. Bootstrap tool creates the rootfs in the specified directory and format

### Test Helpers

The `tests/helpers/mod.rs` module provides test utilities:
- `create_mmdebstrap()`: Factory function to create `MmdebstrapConfig` with default values, simplifying test setup

### YAML Profile Structure

Example profiles in `examples/` directory show the expected YAML format:

**mmdebstrap backend:**
```yaml
dir: /tmp/debian-trixie-server-amd64
bootstrap:
  type: mmdebstrap
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

**debootstrap backend:**
```yaml
dir: /tmp/debian-trixie-debootstrap
bootstrap:
  type: debootstrap
  suite: trixie
  target: rootfs
  mirror: https://deb.debian.org/debian
  variant: minbase
  arch: amd64
  components:
    - main
    - contrib
  include:
    - curl
  merged_usr: true
```

## Key Implementation Details

### Hook Types (mmdebstrap only)

mmdebstrap supports multiple hook phases (defined in `backends/mmdebstrap.rs`):
- `setup_hook`: Runs before package extraction
- `extract_hook`: Runs after package extraction
- `essential_hook`: Runs after essential packages are installed
- `customize_hook`: Runs before final image creation

### Argument Building

Each backend uses helper functions `add_flag()` and `add_flags()` to conditionally add arguments only when values are non-empty, ensuring clean command-line argument lists. The implementation is in each backend's module.

### Trait Object Pattern

The `Bootstrap` enum provides an `as_backend()` method that returns a `&dyn BootstrapBackend` trait object. This allows the main application logic to work with backends polymorphically without matching on each variant. This pattern:
- Eliminates code duplication in error handling
- Makes adding new backends easier (only one place to update in `as_backend()`)
- Centralizes backend interaction logic

Example usage in `main.rs`:
```rust
let backend = profile.bootstrap.as_backend();
let command_name = backend.command_name();
let args = backend.build_args(&profile.dir)?;
```

### Logging

The application uses the `tracing` crate with configurable log levels (trace, debug, info, warn, error) via CLI flags. Completions command bypasses logging setup to produce clean output.

## Adding New Features

### Adding New Bootstrap Backend

1. Create new backend module in `src/backends/your_tool.rs`
2. Define backend-specific config struct (e.g., `YourToolConfig`)
3. Implement the `BootstrapBackend` trait with `command_name()` and `build_args()` methods
4. Add the new backend to `Bootstrap` enum in `src/config.rs`:
   ```rust
   #[derive(Debug, Deserialize)]
   #[serde(tag = "type", rename_all = "lowercase")]
   pub enum Bootstrap {
       Mmdebstrap(MmdebstrapConfig),
       Debootstrap(DebootstrapConfig),
       YourTool(YourToolConfig),  // Add this
   }
   ```
5. Add match arm in the `as_backend()` method to handle the new backend:
   ```rust
   pub fn as_backend(&self) -> &dyn BootstrapBackend {
       match self {
           Bootstrap::Mmdebstrap(cfg) => cfg,
           Bootstrap::Debootstrap(cfg) => cfg,
           Bootstrap::YourTool(cfg) => cfg,  // Add this
       }
   }
   ```
6. Add tests in `tests/builder_test.rs` and `tests/config_test.rs`
7. Create example YAML in `examples/`
8. Export the new module in `src/backends/mod.rs`

**Note**: No changes to `main.rs` are needed thanks to the trait object pattern!

### Adding Options to Existing Backend

1. Add field to backend config struct (e.g., `MmdebstrapConfig` in `backends/mmdebstrap.rs`) with `#[serde(default)]`
2. Add argument construction logic in backend's `build_args()` method (use `add_flag` or `add_flags`)
3. Add test case in `tests/builder_test.rs` to verify argument generation
4. Update example YAML in `examples/` if applicable

### Adding New CLI Commands

1. Add variant to `Commands` enum in `cli.rs`
2. Create associated `Args` struct with command arguments
3. Handle command in `main.rs` match statement
4. Add corresponding tests in `tests/cli_test.rs`

### Testing Strategy

- Unit tests for argument building per backend (`builder_test.rs`)
- Config parsing tests for all backends (`config_test.rs`)
- CLI argument parsing tests (`cli_test.rs`)
- Use `tests/helpers/create_mmdebstrap()` for consistent test fixtures
- Add new helper functions for additional backends as needed
