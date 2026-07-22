# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
