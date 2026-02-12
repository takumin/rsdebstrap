# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Build and Development Commands

```bash
# Build
cargo build --quiet

# Run tests
cargo test --quiet

# Check for errors without building
cargo check --all-targets --all-features --quiet

# Lint
cargo clippy --all-targets --all-features --quiet

# Format
cargo fmt --all --quiet

# Run the CLI
cargo run -- <command>

# Examples
cargo run -- apply -f examples/debian_trixie_mmdebstrap.yml --dry-run
cargo run -- validate -f examples/debian_trixie_mmdebstrap.yml
```

## Architecture Overview

rsdebstrap is a declarative CLI tool for building Debian-based rootfs images using YAML manifest files. It wraps bootstrap tools (mmdebstrap, debootstrap) and provides post-bootstrap provisioning with privilege escalation support.

### Core Flow

1. **CLI** (`src/cli.rs`) - Parses arguments using clap, provides `apply`, `validate`, and `completions` subcommands
2. **Config** (`src/config.rs`) - Loads and validates YAML profiles, resolves relative paths, applies defaults
3. **Privilege** (`src/privilege.rs`) - Privilege escalation configuration and resolution (sudo/doas)
4. **Error** (`src/error.rs`) - Typed error handling with `RsdebstrapError`
5. **Bootstrap** (`src/bootstrap/`) - Executes bootstrap backends to create the rootfs
6. **Pipeline** (`src/pipeline.rs`) - Orchestrates pre-processors, provisioners, and post-processors in order

### Key Abstractions

- **`Privilege`** enum (`src/privilege.rs`) - Privilege escalation configuration
  - `PrivilegeMethod` enum: `Sudo`, `Doas` — the actual escalation command
  - `PrivilegeDefaults` struct — default privilege settings for the profile
  - `Privilege` enum: `Inherit` (use defaults if available), `UseDefault` (require defaults), `Disabled`, `Method(PrivilegeMethod)` (explicit)
  - `resolve()` collapses against profile defaults to `Option<PrivilegeMethod>`
  - `resolve_in_place()` mutates self to `Method` or `Disabled`
  - `resolved_method()` returns `Option<PrivilegeMethod>` for already-resolved states
  - Custom Serialize/Deserialize: `true` → UseDefault, `false` → Disabled, `{ method: sudo }` → Method, absent → Inherit

- **`RsdebstrapError`** enum (`src/error.rs`) - Domain-specific typed errors
  - `#[non_exhaustive]` enum using `thiserror`, with `anyhow` at trait boundaries
  - Variants: `Validation`, `Execution`, `Isolation`, `Config`, `CommandNotFound`, `Io`
  - Factory methods: `execution(spec, status)`, `execution_in_isolation(command, name, status)`, `io(context, source)`, `command_not_found(command, label)`
  - `Io` variant uses `io_error_kind_message()` for human-readable display

- **`BootstrapBackend`** trait (`src/bootstrap/mod.rs`) - Interface for bootstrap tools
  - `MmdebstrapConfig` - mmdebstrap implementation
  - `DebootstrapConfig` - debootstrap implementation
  - Each backend builds command arguments and determines output type (directory vs archive)

- **`Bootstrap`** enum (`src/config.rs`) - Bootstrap backend wrapper
  - `resolve_privilege()` resolves privilege settings against profile defaults
  - `resolved_privilege_method()` returns the resolved `Option<PrivilegeMethod>`

- **`TaskDefinition`** enum (`src/task/mod.rs`) - Declarative task definition for pipeline steps
  - `Shell` variant (`src/task/shell.rs`) - Runs shell scripts within an isolation context
  - `Mitamae` variant (`src/task/mitamae.rs`) - Runs mitamae recipes within an isolation context
  - Each task has a `privilege: Privilege` field resolved during defaults application
  - Each task has an `isolation: TaskIsolation` field resolved via `resolve_isolation()`
  - `resolved_isolation_config()` returns `Option<&IsolationConfig>` after resolution
  - Enum-based dispatch with compile-time exhaustive matching
  - Shared utilities in `src/task/mod.rs`: `ScriptSource`, `TempFileGuard`, `validate_tmp_directory()`
  - Helper functions: `execute_in_context()`, `check_execution_result()`, `prepare_files_with_toctou_check()`

- **`MitamaeTask`** (`src/task/mitamae.rs`) - Mitamae recipe execution
  - `binary` field: `Option<Utf8PathBuf>` — can be omitted and resolved from `defaults.mitamae`
  - Copies binary to rootfs /tmp with 0o700 permissions, runs `mitamae local <recipe>`
  - RAII cleanup of both binary and recipe temp files via `TempFileGuard`

- **`Pipeline`** struct (`src/pipeline.rs`) - Orchestrates task execution in three phases
  - Creates per-task isolation contexts based on each task's `resolved_isolation_config()`
  - `run_task()` creates provider → setup → execute → teardown for each task independently
  - Executes pre-processors, provisioners, post-processors in order
  - Guarantees teardown even on task execution errors

- **`TaskIsolation`** enum (`src/isolation/mod.rs`) - Task-level isolation setting
  - `Inherit` (default): use profile defaults
  - `UseDefault`: explicitly use defaults (`isolation: true`)
  - `Disabled`: no isolation, direct execution (`isolation: false`)
  - `Config(IsolationConfig)`: explicit config (`isolation: { type: chroot }`)
  - `resolve()` / `resolve_in_place()` collapse against profile `IsolationConfig` defaults
  - `resolved_config()` returns `Option<&IsolationConfig>` — `Some` for isolation, `None` for disabled
  - Custom Serialize/Deserialize: `true` → UseDefault, `false` → Disabled, `{ type: chroot }` → Config, absent → Inherit
  - Note: `UseDefault` and `Inherit` produce identical behavior because `IsolationConfig` always has a default (`Chroot`). Both exist for API symmetry with `Privilege` enum.

- **`IsolationConfig`** enum (`src/config.rs`) - Isolation backend configuration
  - `Chroot { preset, mounts }` - chroot with optional filesystem mounts
  - `preset: Option<MountPreset>` — predefined mount set (e.g., `recommends`)
  - `mounts: Vec<MountEntry>` — custom mount entries
  - `resolved_mounts()` merges preset + custom mounts (custom overrides preset at original position)
  - `has_mounts()` returns true if preset or custom mounts are specified
  - `chroot()` convenience constructor returns default chroot (no preset, no mounts)

- **`MountEntry`** struct (`src/config.rs`) - Filesystem mount specification
  - Fields: `source` (device/path), `target` (absolute path in rootfs), `options` (mount -o flags)
  - `is_pseudo_fs()` — checks if source is a known pseudo-filesystem (proc, sysfs, etc.)
  - `is_bind_mount()` — checks if options contain "bind"
  - `build_mount_spec()` / `build_umount_spec()` — construct `CommandSpec` for mount/umount commands
  - `build_mount_spec_with_path()` — like `build_mount_spec()` but accepts a pre-validated absolute target path
  - `validate()` checks `..` components in targets, bind mount sources, and regular mount sources
  - Pseudo-fs uses `mount -t <type>`, bind mounts use `mount -o bind`

- **`MountPreset`** enum (`src/config.rs`) - Predefined mount sets
  - `Recommends` — common mounts: proc -> /proc, sysfs -> /sys, devtmpfs -> /dev, devpts -> /dev/pts, tmpfs -> /tmp, tmpfs -> /run

- **`RootfsMounts`** struct (`src/isolation/mount.rs`) - RAII mount lifecycle manager
  - Mounts entries in order, unmounts in reverse order
  - `mount()` uses `safe_create_mount_point()` to create directories with `openat`/`mkdirat` + `O_NOFOLLOW` (TOCTOU-safe)
  - Stores verified absolute paths in `mounted_paths: Vec<Option<Utf8PathBuf>>` and reuses them for `umount` (avoids re-traversal)
  - `unmount()` is idempotent, collects errors from all entries
  - `Drop` impl guarantees cleanup even on error paths
  - Used by `run_pipeline_phase()` to bracket the entire pipeline execution

- **`safe_create_mount_point()`** fn (`src/isolation/mount.rs`) - Symlink-safe directory creation
  - Opens rootfs with `O_NOFOLLOW` to verify it's not a symlink
  - Traverses each path component with `openat(O_NOFOLLOW)`, creates missing dirs with `mkdirat`
  - Returns `ELOOP`/`ENOTDIR` → `RsdebstrapError::Isolation` on symlink detection
  - Handles race conditions (`EEXIST` on `mkdirat` → re-open)
  - Uses `rustix` crate (direct dependency, `features = ["fs"]`) for memory-safe syscall wrappers

- **`IsolationProvider`** / **`IsolationContext`** traits (`src/isolation/mod.rs`) - Isolation backends
  - `ChrootProvider` / `ChrootContext` - chroot-based isolation
  - `DirectProvider` / `DirectContext` (`src/isolation/direct.rs`) - No isolation, direct execution on host
    - Translates absolute paths to rootfs-prefixed paths (e.g., `/bin/sh` → `<rootfs>/bin/sh`)
    - Guards against empty commands and post-teardown execution
  - `IsolationContext::execute()` takes `privilege: Option<PrivilegeMethod>` parameter

- **`CommandExecutor`** trait / **`CommandSpec`** struct (`src/executor/mod.rs`) - Command execution
  - `RealCommandExecutor` - Actual execution with dry-run support
  - `CommandSpec` fields: `command`, `args`, `cwd`, `env`, `privilege: Option<PrivilegeMethod>`
  - Builder methods: `with_privilege()`, `with_cwd()`, `with_env()`, `with_envs()`
  - `format_args_lossy()` utility for consistent argument formatting in errors and dry-run output
  - Tests use mock executors to verify command construction without running real commands

### Profile Structure (YAML)

```yaml
dir: /output/path           # Base output directory
defaults:                   # Optional default settings
  isolation:
    type: chroot            # Isolation backend: chroot (default)
    preset: recommends      # Optional: predefined mount set
    mounts:                 # Optional: custom mount entries
      - source: /dev
        target: /dev
        options: [bind]
  privilege:                # Optional default privilege escalation
    method: sudo            # Method: sudo | doas
  mitamae:                  # Optional mitamae defaults
    binary:
      x86_64: /path/to/mitamae-x86_64
      aarch64: /path/to/mitamae-aarch64
bootstrap:
  type: mmdebstrap          # Backend type: mmdebstrap | debootstrap
  suite: trixie             # Debian suite
  target: rootfs            # Output name (directory or archive)
  privilege: true           # Use default privilege method
  # Backend-specific options...
pre_processors:             # Optional pre-provisioning steps
  - type: shell
    content: "..."
    privilege: false         # Disable privilege escalation for this task
    isolation: false         # Disable isolation (direct execution on host)
provisioners:               # Optional main provisioning steps
  - type: shell
    content: "..."          # Inline script
    # OR
    script: ./script.sh     # External script path
  - type: mitamae
    script: ./recipe.rb     # Mitamae recipe file
    # OR
    content: "..."          # Inline recipe
    binary: /path/to/mitamae  # Optional: override defaults.mitamae
    privilege:               # Optional: override defaults.privilege
      method: doas
    isolation:               # Optional: override defaults.isolation
      type: chroot
post_processors:            # Optional post-provisioning steps
  - type: shell
    script: ./cleanup.sh
```

#### Privilege field values

- Absent (field not specified) → `Inherit`: use defaults if available, no escalation otherwise
- `privilege: true` → `UseDefault`: require `defaults.privilege.method` (error if not configured)
- `privilege: false` → `Disabled`: no privilege escalation
- `privilege: { method: sudo }` → `Method`: use the specified method explicitly

#### Isolation field values

- Absent (field not specified) → `Inherit`: use `defaults.isolation` (defaults to chroot)
- `isolation: true` → `UseDefault`: use `defaults.isolation` explicitly (same behavior as `Inherit`)
- `isolation: false` → `Disabled`: no isolation (direct execution on host via `DirectProvider`)
- `isolation: { type: chroot }` → `Config`: use the specified isolation backend explicitly

#### Mount configuration rules

- Mounts are configured at profile level (`defaults.isolation`), not at task level
- When `preset` or `mounts` are specified, `defaults.privilege` must be configured
- Mount targets must be absolute paths without `..` components
- Bind mount sources must exist on the host
- Mount order must satisfy parent-before-child ordering
- Custom mounts override preset entries with the same target at their original position (preserving mount order)
- `RootfsMounts` handles mount/unmount lifecycle around the entire pipeline phase

### Testing Pattern

Tests use a mock executor pattern defined in `tests/helpers/mod.rs`:
- `MockContext` - Shared mock isolation context (used by shell_task_test.rs and mitamae_task_test.rs) with configurable failure modes (`should_fail`, `should_error`, `return_no_status`)
- `MockContext` tracks `executed_commands` and `executed_privileges` for assertion
- `helpers::load_profile_from_yaml()` / `load_profile_from_yaml_typed()` - Load profiles from YAML strings in temp files
- Test builders: `MmdebstrapConfigBuilder`, `DebootstrapConfigBuilder` with fluent API
- Privilege-related tests verify resolution, inheritance, and error handling across tasks and bootstrap backends

#### Known test gaps

- `Pipeline::run_task()` teardown failure paths (patterns 3 and 4: `Ok/Err` and `Err/Err`) are not currently testable because the pipeline internally creates providers from `task.resolved_isolation_config()`, making failure injection impractical. Both `ChrootProvider` and `DirectProvider` have infallible teardown, so these paths are unreachable with current backends. Tests should be added when backends with fallible teardown (e.g., bwrap, systemd-nspawn) are introduced.
- `run_pipeline_phase()` 4-way error matrix (`Ok/Ok`, `Err/Ok`, `Ok/Err`, `Err/Err`) is not directly tested as an integration test because the function is private and requires real filesystem mounts. `RootfsMounts` unit tests cover mount/unmount error paths independently using `MockMountExecutor`.
