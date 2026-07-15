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

rsdebstrap is a declarative CLI tool for building Debian-based rootfs images using YAML
manifest files. It wraps bootstrap tools (`mmdebstrap`, `debootstrap`) and provides
post-bootstrap provisioning with privilege escalation support.

Flow: **CLI** (`src/cli.rs`) → **Config** (`src/config.rs`) → **Bootstrap**
(`src/bootstrap/`) → **Pipeline** (`src/pipeline.rs`). The pipeline runs three phases in
order — `prepare`, `provision`, `assemble` — each task in its own isolation context
(chroot by default, or direct execution on the host) with optional privilege escalation
(sudo/doas).

**For internal design rationale, invariants (TOCTOU/RAII), and the testing approach,
see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).** Read it before changing the
resolution model, the phase pipeline, isolation/privilege plumbing, or the
filesystem-safety code — it captures decisions that are not obvious from the source.

## Profile Structure (YAML)

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
    privilege: true          # Optional: use default privilege method
    # OR
    # link: ../run/systemd/resolve/stub-resolv.conf  # Create symlink instead
```

### Privilege field values

- Absent (field not specified) → `Inherit`: use defaults if available, no escalation otherwise
- `privilege: true` → `UseDefault`: require `defaults.privilege.method` (error if not configured)
- `privilege: false` → `Disabled`: no privilege escalation
- `privilege: { method: sudo }` → `Method`: use the specified method explicitly

### Isolation field values

- Absent (field not specified) → `Inherit`: use `defaults.isolation` (defaults to chroot)
- `isolation: true` → `UseDefault`: use `defaults.isolation` explicitly (same behavior as `Inherit`)
- `isolation: false` → `Disabled`: no isolation (direct execution on host via `DirectProvider`)
- `isolation: { type: chroot }` → `Config`: use the specified isolation backend explicitly

### `resolv_conf` task fields (prepare phase)

- `copy: true` → copy host's /etc/resolv.conf into the `chroot`
- `name_servers: [...]` → generate `resolv.conf` with specified nameservers
- `name_servers: [...], search: [...]` → generate with nameservers + search domains
- `copy` and `name_servers`/`search` are mutually exclusive

### Mount configuration rules

- Mounts are configured in the `prepare` phase as a `type: mount` task
- At most one mount task is allowed in the prepare phase
- When mounts are specified, `defaults.isolation` must be `chroot` and `defaults.privilege` must be configured
- Mount targets must be absolute paths without `..` components
- Bind mount sources must exist on the host
- Mount order must satisfy parent-before-child ordering
- Custom mounts override preset entries with the same target at their original position (preserving mount order)

### resolv.conf task rules

- `resolv_conf` is configured in the `prepare` phase as a `type: resolv_conf` task; at most one per phase
- Mount tasks must come before `resolv_conf` tasks in the prepare phase
- Assemble `resolv_conf` writes a permanent `/etc/resolv.conf` (file or symlink) to the final rootfs; at most one per phase
- `link` and `name_servers`/`search` are mutually exclusive in assemble `resolv_conf`
- Prepare and assemble can both have `resolv_conf` tasks — different roles: temporary DNS vs permanent config
