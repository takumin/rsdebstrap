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
- The rootfs path is resolved before privilege is acquired, and the privileged
  helper then opens it one component at a time without following symlinks. A
  directory on the way to the rootfs that is replaced by a symlink after the
  bootstrap no longer redirects root's writes into the live system; a rootfs
  reached through a symlinked parent still works, because the parent process
  resolved it.
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
  through the same descriptor-anchored path, which buffers the content to cross
  the privilege boundary in one request. Anything over 64 MiB is refused rather
  than read into memory in both processes — a file named by `script:` when it is
  opened, and a task's inline `content:` when the profile is validated.
- A task with `isolation: false` runs the inode its program path resolves to
  inside the rootfs, not whatever the host resolves that path to at exec time.
  The path is resolved against a descriptor for the rootfs with
  `openat2(RESOLVE_IN_ROOT)`, so symlinks are followed — `/bin/sh` on a
  merged-`/usr` Debian rootfs is two of them — but an absolute target or a `..`
  above the rootfs is reinterpreted against it instead of reaching the host.
  Requires Linux 5.6 or newer; without it, direct execution is refused rather
  than run unconfined.
- Profile parse errors name the field path that failed — `provision[0]`,
  `bootstrap` — after the line and column. The untagged `privilege` and
  `isolation` enums report only "data did not match any variant", which on its
  own does not say which entry is malformed.
- **Breaking (library):** the prepare-phase guards (`RootfsMounts`,
  `RootfsResolvConf`) and the staged pipeline entry points
  (`run_prepare_and_provision`, `run_assemble`) are no longer public. Their
  ordering is carried by tokens — mounts established, prepare guards armed,
  provisioned, restored, unmounted — and a token is a value: across a public
  boundary one can be presented for a different guard, rootfs or pipeline than
  the one it was produced for, which is the ordering it exists to enforce. The
  public surface is `run_apply` and `Pipeline::run`, which refuses a pipeline
  that declares prepare tasks.
- `Pipeline::run` refuses a pipeline that declares prepare tasks instead of
  provisioning without them. The mount and the temporary resolv.conf a prepare
  task declares are held by guards that bracket provisioning, and that path is
  the one with nothing in between to hold them, so a profile asking for either
  would have had its provision tasks run without it and still be reported as
  successful. Callers with a prepare phase use `run_prepare_and_provision` and
  `run_assemble` and hold the guards across the two.
- A profile that declares `isolation: false` on a provision task while that task
  resolves to a privilege is refused when it is loaded, rather than run. Direct
  execution runs a program from *inside* the rootfs on the host, so escalating it
  hands root to whatever the half-built rootfs contains. A task that wants direct
  execution under `defaults.privilege` writes `privilege: false` on the same task.
- A profile whose `bootstrap` escalates while `defaults.privilege` is unset is
  refused when it is loaded. The two answer different questions — who builds the
  rootfs, and who modifies it afterwards — and nothing made them agree: the
  bootstrap ran under `sudo` and left a root-owned tree, then the rootfs helper
  opened it unprivileged and the run failed at the first staged file with a bare
  `EACCES`, after the expensive part. The other direction is untouched; a run may
  deliberately escalate only its rootfs writes.

### Added

- `tests/privileged_helper_test.rs`, which exercises real `sudo` escalation
  against a root-owned rootfs. `#[ignore]`d and self-skipping when passwordless
  sudo is unavailable.

### Fixed

- `RootfsResolvConf::setup` refuses to run a second time on the same guard
  instead of losing the rootfs's original `/etc/resolv.conf`. The original is
  held in memory by the first call; a second one detached the temporary that
  call had installed, replaced the original with it, and left teardown restoring
  the temporary under the original's name.
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
