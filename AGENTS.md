# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

rsdebstrap is a declarative CLI tool for building Debian-based rootfs images using multiple bootstrap tools (mmdebstrap, debootstrap) and YAML manifests. It provides a Rust wrapper with a pluggable backend architecture, allowing users to define bootstrap configurations in YAML files with their choice of bootstrap tool. The tool supports a two-phase execution model: bootstrap (creating the base system) and provisioning (post-bootstrap configuration).

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
cargo run -- apply -f examples/debian_trixie_with_provisioners.yml --dry-run
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

The codebase follows a clean separation of concerns with a pluggable backend architecture and two-phase execution model:

- **lib.rs**: Library entry point exposing the public API:
  - `init_logging()`: Initializes tracing/logging with configurable levels
  - `run_apply()`: Executes the two-phase bootstrap + provisioning workflow
  - `run_validate()`: Validates profile configuration
  - Re-exports all public modules (bootstrap, cli, config, executor, provisioners)

- **cli.rs**: Command-line interface definitions using clap. Defines the `Cli`, `Commands` enum (Apply, Validate, Completions), and their associated argument structs.

- **config.rs**: Configuration data structures and YAML deserialization. Core types:
  - `Profile`: Top-level configuration with `dir` (output directory), `bootstrap` configuration, and `provisioners` list
  - `Bootstrap`: Tagged union enum that holds different bootstrap backend configurations
    - `as_backend()`: Returns a `&dyn BootstrapBackend` trait object for polymorphic access
  - `ProvisionerConfig`: Tagged union enum for different provisioner types
    - `as_provisioner()`: Returns a `&dyn Provisioner` trait object for polymorphic access
  - `load_profile()`: Loads and validates YAML configuration files with path resolution
  - `Profile::validate()`: Validates profile semantics including provisioner compatibility with backend output

- **bootstrap/**: Pluggable bootstrap backend implementations:
  - **mod.rs**: Defines the `BootstrapBackend` trait and `RootfsOutput` enum
    - `BootstrapBackend` trait: `command_name()`, `build_args()`, `rootfs_output()` methods
    - `RootfsOutput`: Classifies backend output as `Directory` (provisioner-compatible) or `NonDirectory`
  - **args.rs**: Shared command argument builder utilities
    - `CommandArgsBuilder`: Fluent builder for assembling command arguments consistently
    - `FlagValueStyle`: Enum defining argument rendering (Separate vs Equals style)
  - **mmdebstrap.rs**: mmdebstrap backend with `MmdebstrapConfig` and implementation. Contains mmdebstrap-specific types like `Mode`, `Format`, `Variant`, and hooks configuration
  - **debootstrap.rs**: debootstrap backend with `DebootstrapConfig` and implementation. Contains debootstrap-specific types like `Variant` and options

- **provisioners/**: Post-bootstrap configuration system:
  - **mod.rs**: Defines the `Provisioner` trait for post-bootstrap operations
  - **shell.rs**: Shell provisioner that executes scripts in chroot
    - `ShellProvisioner`: Supports both external scripts (`script` field) and inline scripts (`content` field)
    - Security features: validates /tmp is a real directory (not symlink), prevents path traversal
    - Uses UUID-based script naming and RAII cleanup guard

- **executor.rs**: Command execution abstraction:
  - `CommandExecutor` trait: Abstract interface for running commands
  - `RealCommandExecutor`: Production implementation with dry-run support
  - `CommandSpec`: Enhanced command specification with support for:
    - Command name and arguments
    - Working directory (`cwd`)
    - Environment variables (`env`)
    - Builder pattern methods: `with_cwd()`, `with_env()`, `with_envs()`

- **main.rs**: Entry point that delegates to library functions:
  1. Parse CLI arguments
  2. Handle completions command early (bypass logging)
  3. Set up tracing/logging via `init_logging()`
  4. Execute command by calling `run_apply()` or `run_validate()`

### Data Flow

**Two-Phase Execution Model:**

1. **Configuration Phase:**
   - User provides YAML profile (e.g., `examples/debian_trixie_with_provisioners.yml`)
   - `config::load_profile()` deserializes YAML into `Profile` struct
   - Relative paths in profile are resolved to profile directory
   - `Profile::validate()` validates semantics and provisioner compatibility

2. **Bootstrap Phase:**
   - YAML's `bootstrap.type` field determines which backend enum variant is used
   - Backend's `build_args()` method converts config to command arguments
   - `executor::RealCommandExecutor` runs the appropriate bootstrap command
   - Bootstrap tool creates the rootfs in the specified directory and format

3. **Provisioning Phase** (if provisioners configured):
   - Backend's `rootfs_output()` determines if output is provisioner-compatible
   - Each provisioner runs sequentially via `Provisioner::provision()`
   - Shell provisioners: copy/write scripts to /tmp, execute via chroot, cleanup

### Test Helpers

The `tests/helpers/mod.rs` module provides extensive test utilities:

**Factory Functions:**
- `create_mmdebstrap()`: Creates `MmdebstrapConfig` with minimal required fields
- `create_debootstrap()`: Creates `DebootstrapConfig` with minimal required fields

**YAML Fixtures:**
- `yaml_profile_mmdebstrap_minimal()`: Minimal mmdebstrap YAML
- `yaml_profile_debootstrap_minimal()`: Minimal debootstrap YAML
- `yaml!` macro: Dedents YAML literals for cleaner test code

**Profile Helpers:**
- `load_profile_from_yaml()`: Loads profile from YAML string via temp file
- `get_mmdebstrap_config()`: Extracts `MmdebstrapConfig` from `Profile` (panics if wrong type)
- `get_debootstrap_config()`: Extracts `DebootstrapConfig` from `Profile` (panics if wrong type)

**Test Infrastructure:**
- `CwdGuard`: RAII guard that restores current working directory on drop
- `CWD_TEST_LOCK`: Global mutex for serializing tests that modify working directory
- `dedent()`: Removes common indentation from multi-line strings

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

**With provisioners (requires directory output):**
```yaml
dir: /tmp/debian-trixie-provisioned
bootstrap:
  type: mmdebstrap
  suite: trixie
  target: rootfs  # Must be directory, not tarball
  mirrors:
    - https://deb.debian.org/debian
  variant: apt
  components:
    - main
  architectures:
    - amd64

provisioners:
  # Inline shell script
  - type: shell
    content: |
      #!/bin/sh
      set -e
      apt-get update
      apt-get install -y vim htop
    shell: /bin/sh

  # External shell script
  - type: shell
    script: ./scripts/configure-network.sh
    shell: /bin/bash
```

## Key Implementation Details

### Provisioners System

The provisioners system runs post-bootstrap configuration steps inside the bootstrapped rootfs:

**Provisioner Trait:**
- All provisioners implement the `Provisioner` trait with a single `provision()` method
- Takes rootfs path, command executor, and dry_run flag as parameters
- Returns `Result<()>` for success/failure

**Shell Provisioner:**
- Supports two mutually exclusive modes:
  - `script`: Path to external shell script file
  - `content`: Inline shell script content
- Configurable shell interpreter (default: `/bin/sh`)
- Security features:
  - Validates /tmp is a real directory, not a symlink (prevents chroot escape)
  - Validates shell path has no `..` components (prevents path traversal)
  - TOCTOU mitigation: re-validates /tmp immediately before writing
- RAII cleanup: `ScriptGuard` ensures scripts are deleted even on error
- UUID-based script naming prevents collisions

**Output Compatibility:**
- Provisioners require directory output (not tarballs)
- `RootfsOutput` enum classifies backend output:
  - `Directory(path)`: Can be used with provisioners
  - `NonDirectory { reason }`: Cannot be used with provisioners
- `Profile::validate()` enforces compatibility at validation time

### Hook Types (mmdebstrap only)

mmdebstrap supports multiple hook phases (defined in `bootstrap/mmdebstrap.rs`):
- `setup_hook`: Runs before package extraction
- `extract_hook`: Runs after package extraction
- `essential_hook`: Runs after essential packages are installed
- `customize_hook`: Runs before final image creation

Note: Hooks are backend-specific. If you need post-bootstrap steps that work across all backends, use provisioners instead.

### Argument Building

**Legacy Pattern (per-backend):**
Each backend originally had helper functions `add_flag()` and `add_flags()` to conditionally add arguments only when values are non-empty.

**Modern Pattern (shared utility):**
The `CommandArgsBuilder` in `bootstrap/args.rs` provides a consistent, fluent API:
```rust
use bootstrap::{CommandArgsBuilder, FlagValueStyle};

let mut builder = CommandArgsBuilder::new();
builder.push_arg("bookworm");
builder.push_flag_value("--arch", "amd64", FlagValueStyle::Separate);
builder.push_flag_values("--include", &packages, FlagValueStyle::Separate);
let args = builder.into_args();
```

**Migration Status:**
- New backends should use `CommandArgsBuilder`
- Existing backends may still use legacy helpers (refactoring welcomed but not required)

### Trait Object Pattern

Both `Bootstrap` and `ProvisionerConfig` enums use the trait object pattern:

**Bootstrap:**
```rust
pub fn as_backend(&self) -> &dyn BootstrapBackend {
    match self {
        Bootstrap::Mmdebstrap(cfg) => cfg,
        Bootstrap::Debootstrap(cfg) => cfg,
    }
}
```

**ProvisionerConfig:**
```rust
pub fn as_provisioner(&self) -> &dyn Provisioner {
    match self {
        ProvisionerConfig::Shell(cfg) => cfg,
    }
}
```

This allows polymorphic usage without matching on each variant:
```rust
let backend = profile.bootstrap.as_backend();
let command_name = backend.command_name();
let args = backend.build_args(&profile.dir)?;

for provisioner_config in &profile.provisioners {
    let provisioner = provisioner_config.as_provisioner();
    provisioner.provision(&rootfs, executor, dry_run)?;
}
```

Benefits:
- Eliminates code duplication in error handling
- Makes adding new backends/provisioners easier
- Centralizes polymorphic interaction logic in one place

### Logging

The application uses the `tracing` crate with configurable log levels (trace, debug, info, warn, error) via CLI flags. Completions command bypasses logging setup to produce clean output.

Logging is initialized once in `lib::init_logging()` and used throughout the codebase for structured logging.

## Adding New Features

### Adding New Bootstrap Backend

1. Create new backend module in `src/bootstrap/your_tool.rs`
2. Define backend-specific config struct (e.g., `YourToolConfig`) with serde derives
3. Implement the `BootstrapBackend` trait:
   ```rust
   impl BootstrapBackend for YourToolConfig {
       fn command_name(&self) -> &str { "yourtool" }

       fn build_args(&self, output_dir: &Utf8Path) -> Result<Vec<OsString>> {
           let mut builder = CommandArgsBuilder::new();
           // Build arguments...
           Ok(builder.into_args())
       }

       fn rootfs_output(&self, output_dir: &Utf8Path) -> Result<RootfsOutput> {
           // Determine if output is directory or not...
       }
   }
   ```
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
5. Add match arm in the `as_backend()` method:
   ```rust
   pub fn as_backend(&self) -> &dyn BootstrapBackend {
       match self {
           Bootstrap::Mmdebstrap(cfg) => cfg,
           Bootstrap::Debootstrap(cfg) => cfg,
           Bootstrap::YourTool(cfg) => cfg,  // Add this
       }
   }
   ```
6. Export the new module in `src/bootstrap/mod.rs`:
   ```rust
   pub mod your_tool;
   ```
7. Add tests in `tests/builder_test.rs` for argument building
8. Add tests in `tests/config_test.rs` for YAML deserialization
9. Add tests in `tests/rootfs_output_test.rs` for output classification
10. Create example YAML in `examples/`

**Note**: No changes to `main.rs` or `lib.rs` are needed thanks to the trait object pattern!

### Adding New Provisioner Type

1. Create new provisioner module in `src/provisioners/your_type.rs`
2. Define provisioner config struct (e.g., `YourProvisioner`) with serde derives
3. Implement the `Provisioner` trait:
   ```rust
   impl Provisioner for YourProvisioner {
       fn provision(
           &self,
           rootfs: &Utf8Path,
           executor: &dyn CommandExecutor,
           dry_run: bool,
       ) -> Result<()> {
           // Implementation...
       }
   }
   ```
4. Add validation method if needed (called during profile validation)
5. Add the new provisioner to `ProvisionerConfig` enum in `src/config.rs`:
   ```rust
   #[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
   #[serde(tag = "type", rename_all = "lowercase")]
   pub enum ProvisionerConfig {
       Shell(ShellProvisioner),
       YourType(YourProvisioner),  // Add this
   }
   ```
6. Update `as_provisioner()` and `validate()` methods:
   ```rust
   pub fn as_provisioner(&self) -> &dyn Provisioner {
       match self {
           ProvisionerConfig::Shell(cfg) => cfg,
           ProvisionerConfig::YourType(cfg) => cfg,  // Add this
       }
   }

   pub fn validate(&self) -> Result<()> {
       match self {
           ProvisionerConfig::Shell(cfg) => cfg.validate(),
           ProvisionerConfig::YourType(cfg) => cfg.validate(),  // Add this
       }
   }
   ```
7. Export the new module in `src/provisioners/mod.rs`
8. Add tests in `tests/provisioners_test.rs`
9. Update example YAML files to demonstrate usage

### Adding Options to Existing Backend

1. Add field to backend config struct (e.g., `MmdebstrapConfig` in `bootstrap/mmdebstrap.rs`) with `#[serde(default)]`
2. Add argument construction logic in backend's `build_args()` method:
   - Use `CommandArgsBuilder` for new code
   - Or use legacy `add_flag`/`add_flags` helpers if modifying existing code
3. Add test case in `tests/builder_test.rs` to verify argument generation
4. Add test case in `tests/config_test.rs` to verify YAML deserialization
5. Update example YAML in `examples/` if applicable

### Adding New CLI Commands

1. Add variant to `Commands` enum in `cli.rs`
2. Create associated `Args` struct with command arguments
3. Add corresponding function in `lib.rs` (e.g., `run_your_command()`)
4. Handle command in `main.rs` match statement
5. Add corresponding tests in `tests/cli_test.rs`

### Testing Strategy

The project has comprehensive test coverage across multiple dimensions:

**Argument Building Tests** (`tests/builder_test.rs`):
- Verify each backend generates correct command-line arguments
- Test all configuration options and their combinations
- Ensure proper handling of optional fields

**Configuration Tests** (`tests/config_test.rs`):
- Test YAML deserialization for all backends and provisioners
- Verify validation logic catches invalid configurations
- Test path resolution for relative paths

**Provisioner Tests** (`tests/provisioners_test.rs`):
- Test provisioner validation logic
- Verify mutual exclusivity of script/content fields
- Test security validations

**Rootfs Output Tests** (`tests/rootfs_output_test.rs`):
- Verify each backend correctly classifies its output type
- Test provisioner compatibility validation

**Orchestration Tests** (`tests/orchestration_test.rs`):
- Integration tests for the full two-phase workflow
- Test bootstrap + provisioner execution flow

**CLI Tests** (`tests/cli_test.rs`):
- Test argument parsing for all commands
- Verify flag combinations and defaults

**Executor Tests** (`tests/executor_test.rs`):
- Test command execution abstraction
- Verify dry-run mode behavior

**Completions Tests** (`tests/completions_test.rs`):
- Verify shell completion generation

**Best Practices:**
- Use helper functions from `tests/helpers/mod.rs` for consistent fixtures
- Add new helper functions for additional backends/provisioners
- Use the `yaml!` macro for cleaner test YAML literals
- Use `CwdGuard` for tests that modify current directory
- Use `CWD_TEST_LOCK` mutex for parallel test safety when changing directories

## Important Conventions

### Security Considerations

When implementing provisioners or backend hooks:

1. **Path Validation**: Always validate paths to prevent directory traversal attacks
   - Check for `..` components
   - Ensure paths don't escape the rootfs

2. **Symlink Safety**: Validate critical directories are not symlinks
   - Example: Shell provisioner validates /tmp is a real directory
   - Prevents attackers from writing outside chroot

3. **TOCTOU Mitigation**: Re-validate conditions immediately before use
   - Example: Shell provisioner validates /tmp twice (once early, once before writing)

4. **Cleanup**: Use RAII guards for cleanup even on error
   - Example: `ScriptGuard` ensures temporary scripts are deleted

### Error Handling

- Use `anyhow::Result` for all fallible operations
- Add context to errors with `.context()` or `.with_context()`
- Include relevant paths, commands, or configuration in error messages
- Use `anyhow::bail!` for early returns with error messages

### Code Organization

- Keep backend-specific logic in backend modules
- Keep provisioner-specific logic in provisioner modules
- Use traits for polymorphism across backends/provisioners
- Prefer composition over inheritance
- Use the builder pattern for complex construction (e.g., `CommandArgsBuilder`)

### YAML Configuration

- All optional fields must have `#[serde(default)]`
- Use tagged unions with `#[serde(tag = "type", rename_all = "lowercase")]`
- Provide clear field names that match command-line flags where applicable
- Document mutually exclusive fields in doc comments
