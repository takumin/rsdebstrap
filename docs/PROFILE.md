# Profile Format (YAML)

A machine-readable JSON Schema for this format is committed at
[`schema/rsdebstrap.schema.json`](../schema/rsdebstrap.schema.json) (usable for editor
completion/validation). It is generated from the Rust config types — regenerate it with
`task schema` (or `cargo run -- schema > schema/rsdebstrap.schema.json`) after any
config-type change; the autofix.ci workflow also regenerates it and auto-commits drift
to pull requests (see [`ARCHITECTURE.md`](ARCHITECTURE.md#json-schema-generation)).

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
  # Backend-specific options (mirrors, variant, components, hooks, …) are not listed
  # here — see the generated schema or examples/debian_trixie_mmdebstrap.yml
prepare:                    # Optional preparation steps (named-field struct)
  mount:                    # Filesystem mounts for the rootfs (at most one)
    preset: recommends      # Optional: predefined mount set
    mounts:                 # Optional: custom mount entries
      - source: /dev
        target: /dev
        options: [bind]
  resolv_conf:              # resolv.conf setup for DNS in chroot (at most one)
    copy: true              # Copy host's /etc/resolv.conf
    # OR
    # name_servers: [8.8.8.8]  # Generate with explicit nameservers
    # search: [example.com]    # Optional search domains
provision:                  # Optional main provisioning steps (ordered list)
  - type: shell
    content: "..."          # Inline script
    # OR
    script: ./script.sh     # External script path
    shell: /bin/sh           # Optional: interpreter (default /bin/sh)
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
assemble:                   # Optional finalization steps (named-field struct)
  resolv_conf:              # Permanent /etc/resolv.conf in final rootfs (at most one)
    name_servers: [8.8.8.8, 8.8.4.4]  # Generate resolv.conf with nameservers
    search: [example.com]   # Optional search domains
    # OR
    # link: ../run/systemd/resolve/stub-resolv.conf  # Create symlink instead
```

## YAML scalar and null rules

- String-typed fields (paths, suite/target names, mount sources/options, search domains) accept
  only YAML strings. Numbers, booleans, and `null` are parse errors — quote values that look like
  scalars (`suite: "13"`). `dir` must additionally be non-empty.
- On defaulted section/list/map fields (`defaults`, `prepare`, `provision`, `assemble`, `mounts`,
  `options`, `name_servers`, `search`, `mitamae`, `mitamae.binary`), an explicit `null`, an empty
  value (e.g. a section whose entries are all commented out), and omitting the key are
  equivalent — all mean "use the default".
- That list is exhaustive: the list fields inside the internally tagged `bootstrap:` maps
  (`include`, `components`, `keyring`, hook lists, …) and the tagged `isolation:` config stay
  strict — an explicit `null` or an empty value (e.g. a list whose entries are all commented
  out) is a parse error there. Omit the key instead.

## Privilege field values

`privilege` appears on provision tasks and on the `bootstrap:` backend. It does *not* appear on
`assemble.resolv_conf`: that task modifies the rootfs through the privileged helper described
below, which is opened once per run from `defaults.privilege`, so a per-task override could not
be honored. Setting it is a parse error rather than a silent no-op.

- Absent (field not specified) → `Inherit`: use defaults if available, no escalation otherwise
- `privilege: true` → `UseDefault`: require `defaults.privilege.method` (error if not configured)
- `privilege: false` → `Disabled`: no privilege escalation
- `privilege: { method: sudo }` → `Method`: use the specified method explicitly

## Isolation field values

- Absent (field not specified) → `Inherit`: use `defaults.isolation` (defaults to chroot)
- `isolation: true` → `UseDefault`: use `defaults.isolation` explicitly (same behavior as `Inherit`)
- `isolation: false` → `Disabled`: no isolation (direct execution on host via `DirectProvider`)
- `isolation: { type: chroot }` → `Config`: use the specified isolation backend explicitly

## `resolv_conf` task fields (prepare phase)

- `copy: true` → copy host's /etc/resolv.conf into the `chroot`
- `name_servers: [...]` → generate `resolv.conf` with specified nameservers
- `name_servers: [...], search: [...]` → generate with nameservers + search domains
- `copy` and `name_servers`/`search` are mutually exclusive
- resolv.conf specification limits apply to both the prepare and assemble tasks: at most 3
  `name_servers`, at most 6 `search` domains totalling 256 characters, and no empty or
  whitespace-containing search domain

## Mount configuration rules

- Mounts are configured in the `prepare` phase under the `mount` key (a singleton `Option`, so
  at most one mount task is structural — a duplicate `mount` key is a parse error)
- When mounts are specified, `defaults.privilege` must be configured (`mount`/`umount` require
  privilege escalation), and both commands must be on `PATH`
- Mount targets must be absolute paths without `..` components
- Bind mount sources must exist on the host
- Mount order must satisfy parent-before-child ordering
- Custom mounts override preset entries with the same target at their original position (preserving mount order)
- Two custom `mounts` entries may not share a target (duplicates are a validation error)
- Mounts cover `prepare` and `provision` only: they are released after `provision` and before
  `assemble`, so assemble tasks see the rootfs as the image will have it. A failed unmount
  skips `assemble` for that reason

## resolv.conf task rules

- `resolv_conf` is configured in the `prepare` phase under the `resolv_conf` key (a singleton
  `Option`; a duplicate key is a parse error)
- The pipeline always applies `mount` before `resolv_conf`; key order in the YAML is irrelevant
- Assemble `resolv_conf` writes a permanent `/etc/resolv.conf` (file or symlink) to the final
  rootfs under the `assemble.resolv_conf` key (also a singleton `Option`)
- `link` and `name_servers`/`search` are mutually exclusive in assemble `resolv_conf`, and
  exactly one of the two forms must be given (a task with neither is a validation error)
- Prepare and assemble can both have `resolv_conf` tasks — different roles: temporary DNS vs permanent config
- The temporary prepare `resolv_conf` is removed (and the original restored) after `provision`
  and before `assemble`, so assemble `resolv_conf` output persists in the final rootfs; the
  assemble phase only runs if that restore succeeds. The original is held in memory for the
  duration, not copied to a backup path, so an interrupted build leaves nothing behind to clean
  up by hand — but it also means the original is only recoverable while the process lives
- Assemble `resolv_conf` replaces `/etc/resolv.conf` atomically, so a failed assemble leaves the
  previous entry intact and stages nothing a later run has to clear. A pre-existing
  `/etc/resolv.conf` is replaced whether it is a regular file or a symlink; a symlink is never
  followed, so the entry it pointed at is left untouched

## How rootfs modifications are performed

Both `resolv_conf` tasks change files inside the rootfs, which normally needs root. Rather than
running `sudo cp` / `sudo mv` per operation, rsdebstrap escalates **once** per run: it spawns a
helper process under `defaults.privilege.method` that holds a descriptor to the rootfs and
performs the changes as syscalls anchored to it.

Two consequences are visible from a profile:

- `defaults.privilege` decides whether rootfs modifications are privileged. There is no per-task
  override for them (see *Privilege field values*).
- Every path component is resolved with `O_NOFOLLOW`. A symlink anywhere on the way to
  `/etc/resolv.conf` — including `/etc` itself — is an error, not something to follow. Only the
  final component may be a symlink, and it is replaced rather than written through.

Process execution (`mount`, `umount`, `chroot`, the bootstrap backend, provision tasks) still
escalates per command, so those keep their own `privilege` settings.
