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
    privilege: true          # Optional: use default privilege method
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

## Mount configuration rules

- Mounts are configured in the `prepare` phase under the `mount` key (a singleton `Option`, so
  at most one mount task is structural — a duplicate `mount` key is a parse error)
- When mounts are specified, `defaults.privilege` must be configured (`mount`/`umount` require
  privilege escalation), and both commands must be on `PATH`
- Mount targets must be absolute paths without `..` components
- Bind mount sources must exist on the host
- Mount order must satisfy parent-before-child ordering
- Custom mounts override preset entries with the same target at their original position (preserving mount order)

## resolv.conf task rules

- `resolv_conf` is configured in the `prepare` phase under the `resolv_conf` key (a singleton
  `Option`; a duplicate key is a parse error)
- The pipeline always applies `mount` before `resolv_conf`; key order in the YAML is irrelevant
- Assemble `resolv_conf` writes a permanent `/etc/resolv.conf` (file or symlink) to the final
  rootfs under the `assemble.resolv_conf` key (also a singleton `Option`)
- `link` and `name_servers`/`search` are mutually exclusive in assemble `resolv_conf`
- Prepare and assemble can both have `resolv_conf` tasks — different roles: temporary DNS vs permanent config
- The temporary prepare `resolv_conf` is removed (and the original restored) after `provision`
  and before `assemble`, so assemble `resolv_conf` output persists in the final rootfs; the
  assemble phase only runs if that restore succeeds
- Assemble `resolv_conf` replaces `/etc/resolv.conf` atomically: the new file/symlink is
  staged at `/etc/resolv.conf.rsdebstrap-tmp` and renamed over the final path with a plain
  same-directory `mv` (busybox/musl-safe; no GNU-only `-T`), so a failed assemble leaves the
  previous resolv.conf intact. A stale staging entry may remain after a failed build; the next
  run clears it first (both modes) before staging, so it is always overwritten
