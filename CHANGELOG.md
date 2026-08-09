# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Rootfs modifications (both `resolv_conf` tasks) are performed by a single
  privileged helper process spawned once per run, instead of a `sudo cp` /
  `sudo mv` / `sudo chmod` per operation. Paths are resolved one component at a
  time with `O_NOFOLLOW` against a directory descriptor, so a symlink planted
  anywhere along a path is an error rather than a redirect for a privileged
  write.
- The prepare-phase `resolv_conf` guard holds the rootfs's original
  `/etc/resolv.conf` in memory instead of moving it to
  `/etc/resolv.conf.rsdebstrap-orig`, and restores it with the mode and owner it
  carried. An interrupted build no longer leaves a backup file for the operator
  to move back by hand, and a rootfs bootstrapped unprivileged keeps its own
  ownership of the file rather than having it reowned by the privileged helper
  that restores it. A restore that cannot put the recorded owner back fails
  rather than reporting success for a file it reowned.
- JSON Schema generation is no longer behind the `schema` cargo feature;
  `schemars` and `serde_json` are ordinary dependencies. Adds ~460 KB to the
  release binary. `--no-default-features` no longer produces a schema-less
  build.
- A provision task's script, recipe, or mitamae binary is staged into the rootfs
  through the same descriptor-anchored path, which buffers the file to cross the
  privilege boundary in one request. Files over 64 MiB are refused rather than
  read into memory in both processes.
- Profile parse errors name the field path that failed — `provision[0]`,
  `bootstrap` — after the line and column. The untagged `privilege` and
  `isolation` enums report only "data did not match any variant", which on its
  own does not say which entry is malformed.

### Added

- `tests/privileged_helper_test.rs`, which exercises real `sudo` escalation
  against a root-owned rootfs. `#[ignore]`d and self-skipping when passwordless
  sudo is unavailable.

### Fixed

- A dangling `/etc/resolv.conf` symlink — the normal state of a systemd rootfs
  before `systemd-resolved` runs — is now restored intact after provisioning.
  The backup was previously probed with a call that follows symlinks, so a
  dangling backup was read as absent, the restore was skipped, and the original
  was lost.

### Removed

- **Breaking:** `assemble.resolv_conf.privilege`. Privilege for rootfs
  modifications is now a property of the run, decided once by
  `defaults.privilege`, so a per-task override cannot be honored. The key is
  rejected at parse time rather than silently ignored.

## [0.1.0] - Unreleased

Initial development release of rsdebstrap — a declarative CLI tool to build
Debian-based rootfs images using `mmdebstrap`/`debootstrap` and YAML manifests.

### Added

- `apply` command to build a rootfs from a YAML profile, with `--dry-run`.
- `validate` command to check a profile without building.
- `schema` command to emit the profile JSON Schema (committed at
  `schema/rsdebstrap.schema.json`).
- Bootstrap backends: `mmdebstrap` and `debootstrap`.
- Three-phase provisioning pipeline: `prepare`, `provision`, `assemble`.
- Per-task isolation (chroot or direct host execution) and privilege escalation
  (`sudo`/`doas`).
- `prepare`-phase mounts and temporary `resolv.conf` handling; `assemble`-phase
  permanent `resolv.conf` writing.
- `shell` and `mitamae` provisioning tasks.
- `completions` command generating shell completions for bash, zsh, fish,
  powershell, and elvish.

[Unreleased]: https://github.com/takumin/rsdebstrap/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/takumin/rsdebstrap/releases/tag/v0.1.0
