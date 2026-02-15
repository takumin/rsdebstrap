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

rsdebstrap is a declarative CLI tool for building Debian-based rootfs images using YAML manifest files. It wraps bootstrap tools (`mmdebstrap`, `debootstrap`) and provides post-bootstrap provisioning with privilege escalation support.

### Core Flow

1. **CLI** (`src/cli.rs`) - Parses arguments using clap, provides `apply`, `validate`, and `completions` subcommands
2. **Config** (`src/config.rs`) - Loads and validates YAML profiles, resolves relative paths, applies defaults
3. **Privilege** (`src/privilege.rs`) - Privilege escalation configuration and resolution (sudo/doas)
4. **Error** (`src/error.rs`) - Typed error handling with `RsdebstrapError`
5. **Bootstrap** (`src/bootstrap/`) - Executes bootstrap backends to create the rootfs
6. **Pipeline** (`src/pipeline.rs`) - Orchestrates `prepare`, `provision`, and `assemble` phases in order

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

- **`PhaseItem`** trait (`src/phase/mod.rs`) - Internal trait for generic phase processing
  - `pub(crate)` — used by Pipeline to process tasks uniformly across phases
  - Methods: `name()`, `validate()`, `execute()`, `resolved_isolation_config()`
  - Implemented by `PrepareTask`, `ProvisionTask`, `AssembleTask`

- **`PrepareTask`** enum (`src/phase/prepare/mod.rs`) - Preparation tasks before provisioning
  - `Mount` variant (`src/phase/prepare/mount.rs`) - Declares filesystem mounts for the rootfs
  - `ResolvConf` variant (`src/phase/prepare/resolv_conf.rs`) - Declares resolv.conf setup for DNS resolution
  - `mount_task()` returns `Option<&MountTask>` for accessing the inner mount task
  - `resolv_conf_task()` returns `Option<&ResolvConfTask>` for accessing the inner resolv_conf task
  - `PhaseItem::execute()` is a no-op for both — lifecycle managed at pipeline level

- **`MountTask`** struct (`src/phase/prepare/mount.rs`) - Mount declaration for prepare phase
  - `preset: Option<MountPreset>`, `mounts: Vec<MountEntry>`
  - `resolved_mounts()` merges preset + custom mounts (same logic as former `IsolationConfig::resolved_mounts()`)
  - `has_mounts()` returns true if preset or custom mounts are specified
  - `validate()` checks entries and mount order
  - `name()` returns "preset", "custom", "preset+custom", or "empty"
  - At most one mount task allowed in prepare phase (validated by `Profile::validate_mounts()`)

- **`ResolvConfTask`** struct (`src/phase/prepare/resolv_conf.rs`) - resolv.conf declaration for prepare phase
  - Fields: `copy: bool`, `name_servers: Vec<IpAddr>`, `search: Vec<String>` (flat, same as `ResolvConfConfig`)
  - `#[serde(deny_unknown_fields)]` for strict YAML parsing
  - `name()` returns `"copy"` or `"generate"`
  - `config()` converts to `ResolvConfConfig` for use with `RootfsResolvConf`
  - `validate()` delegates to `config().validate()`
  - At most one resolv_conf task allowed in prepare phase (validated by `Profile::validate_resolv_conf()`)
  - Mount tasks must come before resolv_conf tasks (validated by `Profile::validate_prepare_order()`)

- **`AssembleTask`** enum (`src/phase/assemble/mod.rs`) - Finalization tasks after provisioning
  - `ResolvConf` variant (`src/phase/assemble/resolv_conf.rs`) - Writes a permanent `/etc/resolv.conf`
  - `resolv_conf_task()` returns `Option<&AssembleResolvConfTask>` for accessing the inner task
  - `PhaseItem::execute()` delegates to inner task's `execute()`
  - `resolved_isolation_config()` returns `None` (operates directly on rootfs filesystem via `DirectProvider`)

- **`AssembleResolvConfTask`** struct (`src/phase/assemble/resolv_conf.rs`) - Permanent resolv.conf for assemble phase
  - Fields: `link: Option<String>`, `name_servers: Vec<IpAddr>`, `search: Vec<String>`
  - `#[serde(deny_unknown_fields)]` for strict YAML parsing
  - `link` and `name_servers`/`search` are mutually exclusive
  - `name()` returns `"link"` or `"generate"`
  - `validate()` checks mutual exclusivity, link validation (empty/newline/null), delegates to `ResolvConfConfig::validate()` for generate mode
  - `execute()` writes file via `generate_resolv_conf()` or creates symlink via `std::os::unix::fs::symlink()`
  - At most one `resolv_conf` task allowed in assemble phase (validated by `Profile::validate_assemble_resolv_conf()`)

- **`ProvisionTask`** enum (`src/phase/provision/mod.rs`) - Declarative task definition for provision pipeline steps
  - `Shell` variant (`src/phase/provision/shell.rs`) - Runs shell scripts within an isolation context
  - `Mitamae` variant (`src/phase/provision/mitamae.rs`) - Runs mitamae recipes within an isolation context
  - Each task has a `privilege: Privilege` field resolved during defaults application
  - Each task has an `isolation: TaskIsolation` field resolved via `resolve_isolation()`
  - `resolved_isolation_config()` returns `Option<&IsolationConfig>` after resolution
  - Enum-based dispatch with compile-time exhaustive matching
  - Shared utilities in `src/phase/mod.rs`: `ScriptSource`, `TempFileGuard`, `validate_tmp_directory()`
  - Helper functions: `execute_in_context()`, `check_execution_result()`, `prepare_files_with_toctou_check()`

- **`MitamaeTask`** (`src/phase/provision/mitamae.rs`) - Mitamae recipe execution
  - `binary` field: `Option<Utf8PathBuf>` — can be omitted and resolved from `defaults.mitamae`
  - Copies binary to rootfs /tmp with 0o700 permissions, runs `mitamae local <recipe>`
  - RAII cleanup of both binary and recipe temp files via `TempFileGuard`

- **`Pipeline`** struct (`src/pipeline.rs`) - Orchestrates task execution in three phases
  - Holds `&[PrepareTask]`, `&[ProvisionTask]`, `&[AssembleTask]` slices
  - Creates per-task isolation contexts based on each task's `resolved_isolation_config()`
  - Generic `run_phase_items<T: PhaseItem>()` and `validate_phase_items<T: PhaseItem>()` free functions
  - `run_task_item()` creates provider → setup → execute → teardown for each task independently
  - Executes prepare, provision, assemble phases in order
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
  - `Chroot` - chroot isolation (unit variant, no fields)
  - `chroot()` convenience constructor returns `Self::Chroot`
  - `as_provider()` returns the corresponding `IsolationProvider`
  - Note: `mount` and `resolv_conf` configuration have moved to the prepare phase

- **`ResolvConfConfig`** struct (`src/config.rs`) - resolv.conf configuration
  - `copy: bool` — copy host's /etc/resolv.conf into the chroot (following symlinks)
  - `name_servers: Vec<IpAddr>` — explicit nameserver IP addresses
  - `search: Vec<String>` — search domains
  - `copy: true` and `name_servers`/`search` are mutually exclusive
  - `validate()` enforces resolv.conf spec limits (max 3 nameservers, max 6 search domains, 256 char total)

- **`MountEntry`** struct (`src/config.rs`) - Filesystem mount specification
  - Fields: `source` (device/path), `target` (absolute path in rootfs), `options` (mount -o flags)
  - `is_pseudo_fs()` — checks if source is a known pseudo-filesystem (proc, sysfs, etc.)
  - `is_bind_mount()` — checks if options contain "bind"
  - `build_mount_spec_with_path()` / `build_umount_spec_with_path()` — construct `CommandSpec` for mount/umount using a pre-validated absolute target path
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

- **`RootfsResolvConf`** struct (`src/isolation/resolv_conf.rs`) - RAII resolv.conf lifecycle manager
  - `setup()` backs up existing resolv.conf, writes new content (copy from host or generate)
  - `teardown()` restores original resolv.conf from backup
  - Write failure triggers rename rollback to prevent data loss
  - Drop guard ensures cleanup even on error paths
  - `host_resolv_conf` parameter enables test-time host path injection
  - Validates `/etc` is not a symlink, checks for leftover backup files
  - Used by `run_pipeline_phase()` between mount and pipeline execution

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
prepare:                    # Optional preparation steps
  - type: mount             # Filesystem mounts for the rootfs
    preset: recommends      # Optional: predefined mount set
    mounts:                 # Optional: custom mount entries
      - source: /dev
        target: /dev
        options: [bind]
  - type: resolv_conf       # resolv.conf setup for DNS in chroot
    copy: true              # Copy host's /etc/resolv.conf
    # OR
    # name_servers: [8.8.8.8]  # Generate with explicit nameservers
    # search: [example.com]    # Optional search domains
provision:                  # Optional main provisioning steps
  - type: shell
    content: "..."          # Inline script
    # OR
    script: ./script.sh     # External script path
    privilege: false         # Disable privilege escalation for this task
    isolation: false         # Disable isolation (direct execution on host)
  - type: mitamae
    script: ./recipe.rb     # Mitamae recipe file
    # OR
    content: "..."          # Inline recipe
    binary: /path/to/mitamae  # Optional: override defaults.mitamae
    privilege:               # Optional: override defaults.privilege
      method: doas
    isolation:               # Optional: override defaults.isolation
      type: chroot
assemble:                   # Optional finalization steps
  - type: resolv_conf       # Permanent /etc/resolv.conf in final rootfs
    name_servers: [8.8.8.8, 8.8.4.4]  # Generate resolv.conf with nameservers
    search: [example.com]   # Optional search domains
    # OR
    # link: ../run/systemd/resolve/stub-resolv.conf  # Create symlink instead
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

#### `resolv_conf` task fields (prepare phase)

- `copy: true` → copy host's /etc/resolv.conf into the `chroot`
- `name_servers: [...]` → generate `resolv.conf` with specified nameservers
- `name_servers: [...], search: [...]` → generate with nameservers + search domains
- `copy` and `name_servers`/`search` are mutually exclusive

#### Mount configuration rules

- Mounts are configured in the `prepare` phase as a `type: mount` task
- At most one mount task is allowed in the prepare phase
- When mounts are specified, `defaults.isolation` must be `chroot` (validated by `validate_mounts()`)
- When mounts are specified, `defaults.privilege` must be configured
- Mount targets must be absolute paths without `..` components
- Bind mount sources must exist on the host
- Mount order must satisfy parent-before-child ordering
- Custom mounts override preset entries with the same target at their original position (preserving mount order)
- `RootfsMounts` handles mount/unmount lifecycle around the entire pipeline phase
- `RootfsResolvConf` handles resolv.conf setup/restore between mount and pipeline execution
- `resolv_conf` is configured in the `prepare` phase as a `type: resolv_conf` task
- At most one `resolv_conf` task is allowed in the prepare phase
- Mount tasks must come before `resolv_conf` tasks in the prepare phase (validated by `validate_prepare_order()`)
- Assemble `resolv_conf` writes a permanent `/etc/resolv.conf` (file or symlink) to the final rootfs
- At most one `resolv_conf` task is allowed in the assemble phase (validated by `validate_assemble_resolv_conf()`)
- `link` and `name_servers`/`search` are mutually exclusive in assemble `resolv_conf`
- Prepare and assemble can both have `resolv_conf` tasks (no constraint — different roles: temporary DNS vs permanent config)

### Testing Pattern

Tests use a mock executor pattern defined in `tests/helpers/mod.rs`:
- `MockContext` - Shared mock isolation context (used by shell_task_test.rs and mitamae_task_test.rs) with configurable failure modes (`should_fail`, `should_error`, `return_no_status`)
- `MockContext` tracks `executed_commands` and `executed_privileges` for assertion
- `helpers::load_profile_from_yaml()` / `load_profile_from_yaml_typed()` - Load profiles from YAML strings in temp files
- Test builders: `MmdebstrapConfigBuilder`, `DebootstrapConfigBuilder` with fluent API
- Privilege-related tests verify resolution, inheritance, and error handling across tasks and bootstrap backends

#### Known test gaps

- `run_task_item()` teardown failure paths (patterns 3 and 4: `Ok/Err` and `Err/Err`) are not currently testable because the pipeline internally creates providers from `task.resolved_isolation_config()`, making failure injection impractical. Both `ChrootProvider` and `DirectProvider` have infallible teardown, so these paths are unreachable with current backends. Tests should be added when backends with fallible teardown (e.g., bwrap, systemd-nspawn) are introduced.
- `run_pipeline_phase()` 4-way error matrix (`Ok/Ok`, `Err/Ok`, `Ok/Err`, `Err/Err`) is not directly tested as an integration test because the function is private and requires real filesystem mounts. `RootfsMounts` unit tests cover mount/unmount error paths independently using `MockMountExecutor`.
