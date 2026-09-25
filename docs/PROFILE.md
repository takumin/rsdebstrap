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
  apt:                      # APT keyrings, repositories and preferences; they stay (at most one)
    keyrings:               # Optional: OpenPGP keyrings
      - name: docker        # -> /etc/apt/keyrings/docker.{asc,gpg}
        url: https://download.docker.com/linux/debian/gpg
        # OR
        # path: ./keys/docker.asc  # Host file, relative to the profile
        # content: |               # Inline, ASCII-armored
        #   -----BEGIN PGP PUBLIC KEY BLOCK-----
        sha256: <64 hex digits>  # Optional: pin the key's bytes
    repositories:           # Optional: deb822 repositories
      - name: docker        # -> /etc/apt/sources.list.d/docker.sources
        sources:            # One stanza per source
          - types: [deb]    # Optional: deb | deb-src (default [deb])
            uris: [https://download.docker.com/linux/debian]
            suites: [trixie]
            components: [stable]  # Required unless every suite ends in '/'
            architectures: [amd64]  # Optional
            signed_by: docker  # Optional: keyrings entry or absolute rootfs path -> Signed-By
    preferences:            # Optional: apt_preferences(5) pins
      - name: backports     # -> /etc/apt/preferences.d/backports.pref
        pins:               # One stanza per pin
          - packages: [linux-image-amd64]  # Package: names, globs, /regex/, src:name, *
            pin: release n=trixie-backports  # Pin: release … | origin … | version …
            priority: 990   # Pin-Priority: non-zero integer
            explanation: newer kernel  # Optional: one-line Explanation
    remove_sources_list: false  # Optional: delete /etc/apt/sources.list (default false)
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
  - type: apt
    update: true            # Optional: run apt-get update first (default false)
    install: [docker-ce]    # Optional: packages for apt-get install
    recommends: false       # Optional: install Recommends too (default false)
    privilege: true         # Optional: same meaning as on shell/mitamae
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
  apt:                      # apt configuration of the final rootfs (at most one)
    dist_clean: true        # Optional: empty apt's cache and package lists (default false)
    remove_sources_list: true  # Optional: delete /etc/apt/sources.list (default false)
    keyrings: []            # Optional: as prepare.apt.keyrings
    repositories:           # Optional: as prepare.apt.repositories
      - name: debian        # -> /etc/apt/sources.list.d/debian.sources (replaced)
        sources:
          - uris: [https://deb.debian.org/debian]
            suites: [trixie]
            components: [main]
    preferences: []         # Optional: as prepare.apt.preferences
  machine_id: uninitialized # Optional: reset /etc/machine-id (uninitialized | empty)
  resolv_conf:              # Permanent /etc/resolv.conf in final rootfs (at most one)
    name_servers: [8.8.8.8, 8.8.4.4]  # Generate resolv.conf with nameservers
    search: [example.com]   # Optional search domains
    # OR
    # link: ../run/systemd/resolve/stub-resolv.conf  # Create symlink instead
  output:                   # Optional build artifacts written into `dir`
    kernel:
      file: vmlinuz         # File name in `dir`
      source: /vmlinuz      # Optional: default /vmlinuz, then /boot/vmlinuz
    initramfs:
      file: initrd.img      # File name in `dir`
      source: /initrd.img   # Optional: default /initrd.img, then /boot/initrd.img
    assets:                 # Optional files to place in `dir` (list, in order)
      - file: boot/start4.elf  # Path relative to `dir`; directories are created
        url: https://github.com/raspberrypi/firmware/raw/<commit>/boot/start4.elf
        sha256: <64 hex digits>  # Required with url, optional otherwise
        # OR
        # path: ./boot/config.txt  # Host file, relative to the profile
        # content: "console=serial0,115200 root=/dev/mmcblk0p2 rootwait\n"
        # source: /usr/lib/linux-image-<version>/broadcom/bcm2711-rpi-4-b.dtb  # In the rootfs
    rootfs:
      file: rootfs.squashfs # File name in `dir`
      compression: zstd     # Optional: gzip | lzo | lz4 | xz | zstd (mksquashfs default: gzip)
```

## YAML scalar and null rules

- String-typed fields (paths, suite/target names, mount sources/options, search domains) accept
  only YAML strings. Numbers, booleans, and `null` are parse errors — quote values that look like
  scalars (`suite: "13"`). `dir` must additionally be non-empty.
- On defaulted section/list/map fields (`defaults`, `prepare`, `provision`, `assemble`,
  `assemble.output`, `assemble.output.assets`, `mounts`, `options`, `name_servers`, `search`, the
  apt `keyrings`, `repositories`, `preferences`, `components` and `architectures`, the apt
  provision task's `install`, `mitamae`, `mitamae.binary`), an explicit `null`, an empty value
  (e.g. a section whose entries are all commented out), and omitting the key are equivalent — all
  mean "use the default".
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

A task that resolves to some method *and* `isolation: false` is rejected when the profile is
loaded — see the note under [Isolation field values](#isolation-field-values).

## Isolation field values

- Absent (field not specified) → `Inherit`: use `defaults.isolation` (defaults to chroot)
- `isolation: true` → `UseDefault`: use `defaults.isolation` explicitly (same behavior as `Inherit`)
- `isolation: false` → `Disabled`: no isolation (direct execution on host via `DirectProvider`)
- `isolation: { type: chroot }` → `Config`: use the specified isolation backend explicitly

`isolation: false` runs the program the task names — a path *inside* the rootfs — directly
on the host. Two consequences follow, and both are enforced rather than documented:

- It cannot be combined with a resolved privilege. A task that inherits
  `defaults.privilege` and sets `isolation: false` is rejected at load time, because
  escalating it would run rootfs-supplied code as root on the host. Say `privilege: false`
  on the task if that is what you mean.
- The program's path is resolved inside the rootfs, not by the host. Symlinks are followed
  — `/bin/sh` is one on any merged-`/usr` Debian rootfs — but they are resolved as if the
  rootfs were `/`, so a link whose target is absolute or climbs above the rootfs lands
  inside it rather than on the host. A path that ends up naming nothing, or naming
  something that is not a regular file, fails instead of running. Resolution ends on a
  descriptor and the task runs *that*, so the name cannot be repointed between the check
  and the exec. It needs Linux 5.6 or newer; on an older kernel the task is refused rather
  than run with a path the host would resolve.

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
- Mount targets must be absolute paths without `.` or `..` components, and may not be `/`.
  These are rejected while the profile is read, not by a later validation pass: the field is a
  `RelPath`, which cannot express any of them
- Bind mount sources must exist on the host
- Mount order must satisfy parent-before-child ordering
- Custom mounts override preset entries with the same target at their original position (preserving mount order)
- Two custom `mounts` entries may not share a target (duplicates are a validation error)
- Mounts cover `prepare` and `provision` only: they are released after `provision` and before
  `assemble`, so assemble tasks see the rootfs as the image will have it. A failed unmount
  skips `assemble` for that reason

## apt task rules

- `apt` is configured in the `prepare` phase under the `apt` key (a singleton `Option`). The
  pipeline applies `mount`, then `apt`, then `resolv_conf`, whatever the key order
- `keyrings`, `repositories` and `preferences` are separate lists, and at least one of them
  must be non-empty unless `remove_sources_list` is set.
  A source uses a keyring by naming it in `signed_by`, which is written as the stanza's
  `Signed-By`, so the keyring is trusted for the sources that name it only. Several
  sources may name one keyring; `signed_by` naming no `keyrings` entry is an error
- `signed_by` may instead be an absolute path to a keyring file in the rootfs, such as
  `/usr/share/keyrings/debian-archive-keyring.gpg`, written as `Signed-By` verbatim. A value
  starting with `/` is a path; anything else is a `keyrings` name (names cannot contain `/`).
  The path may not contain `.` or `..` components, commas, whitespace or control characters
  (apt would read those as more than one value). Whether the file exists is not checked: apt
  reports a missing keyring at `apt-get update`, and in `assemble.apt` the file may come from a
  package installed in `provision`
- Each repository is written to `/etc/apt/sources.list.d/<name>.sources` in deb822 format, one
  stanza per entry of `sources`, in order, separated by blank lines; `sources` must not be
  empty. Sources that belong together — Debian's archive and its security archive, which lives
  under another URI — go in one file this way. The file only declares the repository: run `apt-get update` in a `provision` task (an apt task with
  `update: true`, see [apt provision task rules](#apt-provision-task-rules)) before installing
  from it
- `name` may hold only letters, digits, `_`, `-` and `.` and may not start with `.` — apt
  skips a file named otherwise. Names are unique within `keyrings`, within `repositories` and
  within `preferences`; entries in different lists may share one
- `uris`, `suites` and `components` values may not contain whitespace (deb822 separates values
  with it). `uris` must parse as URIs. A suite ending in `/` is an exact path and takes no
  `components`; otherwise `components` is required, and exact and distribution suites may not
  be mixed
- A keyring takes exactly one of `path`, `content` or `url`. It is written to
  `/etc/apt/keyrings/<name>.asc` if ASCII-armored or `<name>.gpg` if binary, mode `0644`.
  Inline `content` must be ASCII-armored. Anything that is not an OpenPGP public key —
  including a secret key or an HTML error page — is refused
- If the rootfs has no `/etc/apt/keyrings` (apt before 2.4, e.g. Debian bullseye), it is
  created with mode `0755`, owned by whoever performs rootfs modifications (root, with
  `defaults.privilege`). `/etc/apt` is resolved without following symlinks, and a symlink or a
  non-directory at `/etc/apt/keyrings` is an error rather than something to write through. The
  directory is built under a temporary name and moved into place without replacing anything,
  so it never exists at its own name with another mode. `/etc/apt` itself must exist
- `url` must be `https`, redirects included, and is verified against the host's trust store.
  The key is downloaded when the prepare phase runs (not in a dry run, and not by `validate`),
  and at most 1 MiB is accepted. `sha256`, if given, is checked against the bytes from any
  source; for inline `content` that happens when the profile is validated
- Every keyring is read, downloaded and checked before the first change, so a bad key fails
  the run with the rootfs untouched. A change that fails after that is not rolled back: it
  fails the build
- What `prepare.apt` writes stays in the final rootfs, replacing whatever was at those paths:
  the image is configured the way the build was. Where it should differ — a build mirror the
  image must not point at, say — `assemble.apt` writes over it (see
  [assemble apt rules](#assemble-apt-rules))
- Each preference is written to `/etc/apt/preferences.d/<name>.pref` (the `.pref` extension
  keeps a name containing `.` from being skipped by apt), mode `0644`, one apt_preferences(5)
  stanza per entry of `pins`, in order. `/etc/apt/preferences.d` must exist (apt ships it)
- A repository declared here next to the same repository in the bootstrap's
  `/etc/apt/sources.list` is configured twice, and if only one of them has `Signed-By`,
  `apt-get update` fails with `Conflicting values set for option Signed-By`.
  `remove_sources_list: true` deletes `/etc/apt/sources.list` after everything else is
  written, so the repositories declared here replace the bootstrap's instead; a failed write
  leaves it in place. An absent `/etc/apt/sources.list` is not an error; a directory there
  is. A deb822 file the bootstrap wrote in `/etc/apt/sources.list.d` (such as Ubuntu's
  `ubuntu.sources`) needs no such key: a repository of the same name replaces it
- A pin needs non-empty `packages` (written as `Package`, so `*`, globs, `/regex/` and
  `src:` names work; no whitespace inside a value), `pin` starting with `release`, `origin`
  or `version` followed by its argument, and a non-zero `priority` (apt ignores a pin with
  priority 0). `pin` and `explanation` may not contain a newline or other control character.
  The value after `release`/`origin`/`version` is passed through as written; apt, not the
  profile loader, decides what it matches

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

## apt provision task rules

- `type: apt` runs `apt-get update` when `update: true`, then `apt-get install -y` for the
  `install` list, inside the task's isolation. A task with neither is a validation error
- `update` defaults to `false`, so that installs split over several apt tasks do not refresh
  the package lists each time. A freshly bootstrapped rootfs has no up-to-date lists for the
  sources a profile adds: mmdebstrap removes the lists unless told `--skip=cleanup/apt/lists`,
  and debootstrap keeps only the indices it downloaded from its bootstrap mirror. So set
  `update: true` on the first apt task (and on the first one after a task that changes the
  apt sources). An install that fails in a task without it says so in the error
- `recommends` defaults to `false`, which passes `--no-install-recommends`. Packages the
  bootstrap should include from the base repositories belong in `bootstrap.include` instead;
  this task is for what `prepare.apt` or an earlier task made available
- `apt-get` runs with `DEBIAN_FRONTEND=noninteractive` and
  `-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold`, so it never waits for
  an answer; a conffile an earlier task changed is kept
- While `apt-get install` runs, `/usr/sbin/policy-rc.d` is a script exiting 101, so maintainer
  scripts do not start the services they install: a service started in the chroot would run
  on the host, keep the rootfs busy and fail the unmount. Whatever was there before is put
  back afterwards, including when the install fails; if the install itself replaced the file
  (a package shipping its own policy), the new one is left in place. `apt-get update` runs
  without it. Services still start on the booted system; the policy is not in the final
  rootfs
- Each `install` entry is `name[:arch][=version|/release]`: a Debian package name (lowercase
  letters, digits, `+`, `-`, `.`; at least two characters, starting with a letter or digit, not
  ending in `-`), then optionally an architecture, then a version or a target release. Anything
  else — an option, a glob, whitespace — is a validation error, so no entry can reach
  `apt-get` as an option
- `privilege` works as on the other provision tasks. `isolation: false` is refused: it would
  run the host's `apt-get` against the host

## Assemble apt rules

- `assemble.apt` writes apt's configuration into the final rootfs where it should differ from
  what the build used. `keyrings`, `repositories` and `preferences` take the entries
  `prepare.apt` does, with the same rules and files, and replace a file of the same name —
  one `prepare.apt` wrote included. A source's `signed_by` names an entry in
  `assemble.apt.keyrings` or is an absolute path to a keyring file in the rootfs
- Building from one mirror and shipping another:

  ```yaml
  prepare:
    apt:
      remove_sources_list: true
      repositories:
        - name: debian              # provisioning installs from the build mirror
          sources:
            - uris: [https://mirror.internal/debian]
              suites: [trixie]
              components: [main]
  assemble:
    apt:
      repositories:
        - name: debian              # the image points at the public mirror
          sources:
            - uris: [https://deb.debian.org/debian]
              suites: [trixie]
              components: [main]
  ```

- `remove_sources_list: true` deletes `/etc/apt/sources.list`, as in `prepare.apt`
- As in `prepare.apt`, every keyring is read, downloaded and checked before the first change,
  and a later failure is not rolled back
- At least one entry, `dist_clean` or `remove_sources_list` is required
- The files are written first, then `/etc/apt/sources.list` is removed, then `dist_clean`
  runs. `assemble.apt` runs before `assemble.machine_id`, the assemble `resolv_conf` and
  `assemble.output`

### dist_clean

- `assemble.apt.dist_clean: true` does the work of `apt-get distclean` without running it (the
  assemble phase cannot run a program): it empties `/var/cache/apt` — the downloaded `.deb`
  files, `pkgcache.bin` and `srcpkgcache.bin` — and the package lists in `/var/lib/apt/lists`.
  The image then needs `apt-get update` before it can install anything
- Files and subdirectories alike are removed. What the `apt` package ships is kept: the
  `archives` and `partial` directories (emptied) and the `lock` files
- The paths are apt's defaults; a `Dir::Cache` or `Dir::State` setting inside the rootfs is not
  consulted. A rootfs without these directories is not an error
- The squashfs image of `assemble.output` does not carry the removed files. Symlinks are
  removed as links and never followed, and a symlink in place of one of the directories
  themselves is an error

## Assemble machine_id rules

- `assemble.machine_id` rewrites `/etc/machine-id` so that machines booted from the image do
  not share the ID the build generated (installing systemd or dbus creates one). The value
  picks what machine-id(5) makes of the file at boot:
  - `uninitialized` writes the string `uninitialized`: the first boot is treated as one
    (`ConditionFirstBoot=` holds and unit presets are applied), and the ID generated then is
    written to disk. This is what `mmdebstrap` leaves
  - `empty` writes an empty file: an ID is generated at every boot and written to disk only if
    `/etc` is writable, and no boot is treated as the first one. Suits a read-only root
- The file is written as a regular file, mode `0444`, replacing whatever was there (a symlink is
  replaced, never followed). It is not removed instead: with a read-only root, systemd can only
  mount the generated ID over an existing file
- `/var/lib/dbus/machine-id` is not touched. Debian ships it as a symlink to `/etc/machine-id`,
  so it follows the reset; a rootfs where it is a regular file keeps the build's ID there
- It runs after `assemble.apt` and before the assemble `resolv_conf` and
  `assemble.output`

## Assemble output rules

- `assemble.output` writes build artifacts into `dir`, next to the bootstrap target. The `file`
  of `kernel`, `initramfs` and `rootfs` is a plain file name (no `/`, not `.` or `..`); an asset's
  `file` may be a relative path such as `boot/overlays/foo.dtbo`, without empty, `.` or `..`
  components. Two outputs may not share a `file`, no output may be written where another needs a
  directory (`boot` next to `boot/start4.elf`), and none may be the bootstrap `target` or lead into
  it
- Outputs are written after every other assemble task, in the order `kernel`, `initramfs`, each
  of `assets` in list order, then `rootfs`, so they reflect the rootfs in its final state (the
  assemble `resolv_conf` included). Assets come before the squashfs image so that a failed
  download fails the build before its slowest step
- Each output is staged under a temporary name in `dir` and renamed over `file`, so an existing
  file is replaced atomically and a failed build leaves no partial file behind. `dir` must be
  writable by the user running `rsdebstrap`
- `kernel` / `initramfs` copy one file out of the rootfs. `source` is an absolute path inside the
  rootfs; without it, `/vmlinuz` then `/boot/vmlinuz` (`/initrd.img` then `/boot/initrd.img`) are
  tried, which are the links Debian's kernel packages keep pointing at the newest installed
  version. Symlinks are followed, but resolved as if the rootfs were `/`, so no link can lead the
  read outside it; this needs Linux 5.6 or newer. Finding none of the candidates is an error
- The copy keeps the source's permission bits (Debian installs the initramfs readable by root
  only) and is owned by the user running `rsdebstrap`. With `defaults.privilege` set, the file is
  read through the privileged helper described below, so a root-only source can be copied
- `rootfs` runs `mksquashfs <rootfs> <file> -noappend -one-file-system [-comp <compression>]`.
  `mksquashfs` must be on `PATH` (checked when the profile is validated) and is escalated with
  `defaults.privilege`, like `mount`; there is no per-output `privilege` key. The image is owned by
  the user running `rsdebstrap` with mode `0600`, because it holds every file of the rootfs.
  `-one-file-system` keeps anything still mounted under the rootfs out of the image
- Each asset names exactly one source: `url` (https only, redirects included, and requires
  `sha256`), `path` (a regular file on the host, not a symlink; relative paths are resolved
  against the profile's directory), `content` (inline text), or `source` (an absolute path in
  the rootfs, read like `kernel.source`). `sha256` is optional on the other three. The digest is
  computed while the file is written and checked before it is renamed into place, so a mismatch
  leaves an existing file untouched. A download over 1 GiB is refused, and a host file over
  64 MiB
- Directories on the way to an asset are created with mode `0755` (less the umask) and left in
  place if the build fails. An existing entry on the way must be a directory: a symlink is
  refused rather than followed, since it could lead into the bootstrap target
- An asset is written with mode `0644`, except one copied from the rootfs, which keeps the
  source's permission bits without its setuid, setgid or sticky bits

## How rootfs modifications are performed

Several items change files inside the rootfs, which normally needs root: both `resolv_conf`
tasks, `prepare.apt` and `assemble.apt` (keyrings, sources, preferences and caches),
`assemble.machine_id`, the `policy-rc.d` an apt provision task installs around its install,
and the scripts and binaries staged for provision tasks. Rather than running `sudo cp` /
`sudo mv` per operation, rsdebstrap escalates **once** per run: it spawns a helper process
under `defaults.privilege.method` that holds a descriptor to the rootfs and performs the
changes as syscalls anchored to it.

Two consequences are visible from a profile:

- `defaults.privilege` decides whether rootfs modifications are privileged. There is no per-task
  override for them (see *Privilege field values*).
- Every path component is resolved with `O_NOFOLLOW`. A symlink anywhere on the way to
  `/etc/resolv.conf` — including `/etc` itself — is an error, not something to follow. Only the
  final component may be a symlink, and it is replaced rather than written through.

Process execution (`mount`, `umount`, `chroot`, the bootstrap backend, `mksquashfs`, provision
tasks) still escalates per command. `mount`, `umount` and `mksquashfs` use `defaults.privilege`;
the bootstrap backend and provision tasks keep their own `privilege` settings.
