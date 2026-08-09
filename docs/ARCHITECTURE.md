# Architecture

Design rationale for rsdebstrap internals. This documents the *why* — decisions
and invariants that are not obvious from reading the code. Exhaustive field and
method lists are intentionally omitted; the source is authoritative for those.

For the high-level map and build commands, see [`AGENTS.md`](../AGENTS.md); for the
YAML profile contract, see [`PROFILE.md`](PROFILE.md).

## Core flow

```
CLI (src/cli.rs) → Config (src/config.rs) → Bootstrap (src/bootstrap/) → Pipeline (src/pipeline.rs)
```

1. **CLI** parses arguments (clap): `apply`, `validate`, `completions`, `schema`.
2. **Config** loads/validates the YAML profile, resolves relative paths, applies defaults.
3. **Bootstrap** runs a backend (`mmdebstrap`/`debootstrap`) to create the rootfs.
4. **Pipeline** runs the `prepare` → `provision` → `assemble` phases in order.

## Configuration & resolution model

`Privilege` (`src/privilege.rs`) and `TaskIsolation` (`src/isolation/mod.rs`) share
one deliberate 4-state pattern, resolved against profile `defaults`:

| YAML         | State        | Meaning                                   |
| ------------ | ------------ | ----------------------------------------- |
| absent       | `Inherit`    | use defaults if available                 |
| `true`       | `UseDefault` | require defaults (error if unconfigured)  |
| `false`      | `Disabled`   | no escalation / no isolation              |
| `{ ... }`    | explicit     | `Method(...)` / `Config(...)`             |

- The custom `Serialize`/`Deserialize` impls encode this mapping (`true` → `UseDefault`,
  `false` → `Disabled`, mapping → explicit, absent → `Inherit`). Keeping the scalar
  `true`/`false` shorthand in YAML is the reason these are hand-written rather than derived.
- **Both types describe only what the profile *declared*.** `resolve()` collapses a state
  against the profile default into a concrete `Option<...>` (`None` == disabled/no-op) and
  returns it; neither type has a resolved variant to be in, and neither is mutated in place.
- **Non-obvious:** for `TaskIsolation`, `UseDefault` and `Inherit` behave identically
  because `IsolationConfig` always has a default (chroot). Both variants exist only for
  API symmetry with `Privilege`, where the distinction is real.

The declared/resolved split is the point. These enums used to span both: `resolve_in_place()`
rewrote `Inherit`/`UseDefault` into `Method`/`Config`, and the readers took the unresolved
states as a case to defend against — a `debug_assert!`, a `tracing::warn!`, and a fallback
each. The two fallbacks pointed opposite ways (privilege fell back to *no* escalation,
isolation to chroot), so which direction counted as safe lived only in a comment. Resolution
now produces a separate value, `ResolvedProvisionTask` (`src/phase/provision/mod.rs`), which
pairs a task with the settings it resolves to and is what implements `ProvisionItem`. An
unresolved setting has no path to a reader at all, and all of that runtime defence is gone.

`ProvisionTask::resolve` also rejects one combination outright: a task that resolves to *no
isolation* and *some privilege method*. `isolation: false` runs the program the task names —
a path inside the rootfs — directly on the host, so escalating it hands root to whatever the
half-built rootfs contains. Each setting is reasonable alone, so neither one can reject it;
the check belongs where both are known. It fires during `load_profile`, not mid-run.

`Profile::validate` returns a `ValidatedProfile`, and that is the only thing that can build
a pipeline. The semantic checks — a mount target that must be a reachable directory, a
declared script that must be a regular file, a backend output that must be a directory when
there are pipeline tasks — cannot be stated in the config types, so "this profile was
validated" is carried as a value rather than as a convention `run_apply` happens to follow.
(`Pipeline::new` remains public as the unvalidated low-level constructor, and says so.)

It borrows the profile it was produced from rather than standing for it. A bare token says
only that *some* profile passed, and can be presented for a second one whose mount targets,
script paths and backend output were never checked — of those, only the backend output is
checked again downstream. The borrow also means no `&mut` can be taken while the evidence is
alive, so the profile cannot be edited after the checks ran.

`mount` and `resolv_conf` used to live under `IsolationConfig`; they were moved out to
the `prepare` phase. `IsolationConfig` is now just the backend selector: an internally
tagged enum in the same shape as `Bootstrap` — currently the single variant
`Chroot(ChrootIsolation)`, where `ChrootIsolation` is the (empty, for now) payload struct
for backend-specific options. Each payload struct carries `#[serde(deny_unknown_fields)]`;
putting that attribute on the enum itself would be a silent serde no-op, but on the
payload it is enforced because serde consumes the `type` tag before handing the remaining
keys to the payload (see [JSON Schema generation](#json-schema-generation)). Adding a
backend (bwrap, nspawn, …) means adding a variant with its own payload struct.

## Phases & the pipeline

`Pipeline` (`src/pipeline.rs`) borrows `prepare: &PrepareConfig`, `provision: &[ProvisionTask]`,
and `assemble: &AssembleConfig`. `PhaseItem` (`src/phase/mod.rs`, `pub(crate)`) carries only
what all three share — `name` and `validate`. What an item can *do* differs per phase, and
three sub-traits say so:

| trait           | adds                                            |
| --------------- | ----------------------------------------------- |
| `PrepareItem`   | nothing                                         |
| `ProvisionItem` | `resolved_isolation_config`, `execute(&dyn IsolationContext)` |
| `AssembleItem`  | `execute(&dyn RootfsContext)`                   |

`ProvisionItem` is implemented by `ResolvedProvisionTask`, not by `ProvisionTask`: a task
cannot be run until its settings have been resolved, because the type the pipeline runs is
the one resolution produces.

Each phase is flattened to a `&[&dyn <phase>Item]` before running: `PrepareConfig::items()` and
`AssembleConfig::items()` emit their present `Option` fields in a **fixed execution order**
(`mount → resolv_conf`), and provision maps its `Vec` to trait objects. `run_phase_items` and
`validate_phase_items` are generic over `T: PhaseItem + ?Sized`, so the shared logging and
error-context wrapping are written once; only the per-item action differs.

Key invariants:

- **Per-task isolation lifecycle.** Each *provision* task independently runs
  provider → setup → execute → teardown. Teardown is guaranteed even when execute
  errors. Failure-injection for teardown paths is currently impractical (see
  [Known test gaps](#known-test-gaps)). Provision is the only phase that does this;
  the other two have no isolation to set up.
- **Prepare tasks are declarative.** `MountTask` and (prepare) `ResolvConfTask` implement
  `PrepareItem`, which has no `execute` at all — there is nothing to run, rather than
  something that runs and does nothing. Their real effect comes from the RAII managers below,
  set up in `run_pipeline_phase()`. Both brackets close before assemble: the temporary
  resolv.conf is torn down (the original restored) so an assemble `resolv_conf` task's
  permanent file/symlink survives, and the mounts are released so assemble sees the rootfs
  the way the image will — without `/proc`, `/sys` and `/dev` bound over it. Assemble writes
  the rootfs's *final* state, so anything still bound over it is not part of that state.

  That ordering is carried by three token types rather than by comment and convention.
  `Pipeline::run_prepare_and_provision` yields a `Provisioned`; `RootfsResolvConf::restore`
  consumes one and yields a `Restored`; `RootfsMounts::unmount_before_assembly` consumes that
  and yields an `Unmounted`; `Pipeline::run_assemble` requires an `Unmounted`. Assembling
  before either teardown is therefore a compile error, not a review finding. Each token is
  declared in the module of the guard that produces it, so its constructor is private *there*
  — declared in `pipeline` they would be `pub(crate)` and the orchestration could mint one,
  which is exactly the mistake being prevented. `Pipeline::run` (no guards, so nothing was
  detached and nothing was mounted) is the one exemption, via named functions that still
  demand the preceding token.

  A failed unmount consequently skips assemble, the same way a failed restore does: the
  rootfs is not in the state assemble is defined against. Unmounting itself is still
  attempted on every path, including after a provision failure.
- **Assemble operates on the final rootfs directly, and cannot run a program.** An
  `AssembleItem` receives a `RootfsContext` — `rootfs()`, `dry_run()`, `rootfs_ops()` — so
  every write goes through the descriptor-anchored operations and there is no `execute` to
  reach for. The phase takes no isolation provider either: it used to go through one, which
  always resolved to `DirectProvider` and whose only used capability was `rootfs_ops`, so
  `PlainRootfsContext` (built from the `rootfs`/`ops`/`dry_run` the pipeline already holds)
  replaced that setup/teardown round trip.

`prepare`/`assemble` are **named-field structs** (`PrepareConfig { mount, resolv_conf }`,
`AssembleConfig { resolv_conf }`), not lists. This makes the singleton invariants structural:
"at most one mount" / "at most one resolv_conf" hold because each is an `Option` (a duplicate
YAML key is a `yaml_serde` parse error, an unknown key a `deny_unknown_fields` error), and the
`mount → resolv_conf` order is fixed by `items()` rather than by key order. The former
count/order validators (`validate_prepare_order`, and the count checks in
`validate_mounts`/`validate_resolv_conf`/`validate_assemble_resolv_conf`) were therefore
removed; only cross-field checks remain in `Profile::validate_*` (mounts → privilege;
`mount`/`umount` in `PATH`; prepare `resolv_conf` → `ResolvConfConfig::validate`). The former
"mounts/`resolv_conf` require chroot isolation" guards were removed as well: `IsolationConfig`
has a single `Chroot` variant, so `defaults.isolation` is always chroot and those guards were
unreachable dead code — reintroduce one next to a second isolation backend if ever added, where
it would be reachable and testable. Prepare and assemble may each carry a `resolv_conf` task —
they play different roles (temporary DNS during provisioning vs. the permanent installed file).

## Filesystem safety: TOCTOU & RAII

The rootfs is an untrusted directory tree we mutate with elevated privileges, so two
patterns run throughout `src/isolation/`:

- **TOCTOU-safe path traversal.** `safe_create_mount_point()` never trusts a resolved
  path string: it opens the rootfs with `O_NOFOLLOW`, then walks each component with
  `openat(O_NOFOLLOW)` / `mkdirat`, treating `ELOOP`/`ENOTDIR` as a symlink attack
  (`RsdebstrapError::Isolation`). Verified absolute paths are cached and reused for the
  matching `umount` to avoid re-traversal. Implemented with the `rustix` crate for
  memory-safe syscall wrappers.

  The target it walks is a `RelPath`, not a `Utf8PathBuf`. That matters: camino yields `..`
  as a component, so a target of `/sub/../../x` used to walk *out* of the rootfs, create the
  directory there, and return that path to a privileged `mount` as "verified". Only
  `MountEntry::validate` stood in the way, and nothing in the types required it to have run.
  `RelPath` cannot express `..`, `.`, or an empty path, so the walk is now safe by
  construction; deserialization additionally requires the leading `/`, keeping the profile
  contract that a target is spelled absolutely.
- **All rootfs mutation goes through `RootfsOps`** (`src/rootfs/`), which applies the same
  traversal to every write. Paths are `RelPath` values — absolute forms are accepted and
  normalized, `..` is rejected at construction — so no combination of them names anything
  outside the rootfs. Only the *final* component may be a symlink, and it is replaced rather
  than followed, which is what Debian's symlinked `/etc/resolv.conf` requires.

  This replaced `sudo mv` / `sudo cp` / `sudo chmod` per operation. Those took path *strings*,
  so an `openat(O_NOFOLLOW)` check could only prove a path was safe at one instant and the
  command then resolved the name again — the window was real and previously documented here as
  unavoidable. It is not: see *Privilege boundary* below.
  `RelPath` has exactly one constructor, `parse`, which splits on `/`. That is what keeps
  every component separator-free, which the walk depends on: `openat`/`unlinkat` read a
  separator as another level of path and apply `O_NOFOLLOW` only to the last one. A
  `with_suffix` helper that appended to the final component could put `/..` inside a single
  component and so escape; it was unused and has been removed.
- **Provision staging is inside the boundary too.** A task's script, and the mitamae binary
  and recipe, are written with `RootfsOps::write_file` and removed with `RootfsOps::remove`.
  They used to be host-path `fs::write`/`fs::copy`/`chmod`/`remove_file` guarded by a
  `symlink_metadata` on `<rootfs>/tmp` that ran once at validation and once more just before
  the write — check-then-use, twice over, in the one place the rest of the crate had stopped
  doing it. The anchored write also lands its mode exactly — `openat`'s mode argument is
  masked by the process umask, so `write_file` stages the entry owner-only and `fchmod`s the
  descriptor once the content is final — and it is the final `renameat` that publishes the
  name, so a staged binary never exists in the rootfs with permissions other than the ones
  asked for. The mode travels as a `FileMode` rather than a `u32`, which masks the file-type
  bits off at construction: `take` reads a full `st_mode`, and the value it records is fed
  straight back to `write_file` by `put_back`.

  **Direct execution names an inode too.** With `isolation: false` the program a task
  declares is resolved by the kernel on the host, so the walk that refuses a symlinked
  component now ends by returning the descriptor it landed on, and `CommandSpec` carries it.
  The executor execs `/proc/self/fd/N` and sets argv[0] back to the path, which is the only
  way here to exec an inode rather than a name. Two things fall out of that and are pinned
  by tests: the descriptor must not be close-on-exec, because a `#!` program's interpreter
  opens that same name after the exec; and a `#!` program's `$0` is the descriptor's name,
  because the kernel builds the interpreter's argv itself. There is no privileged form —
  `sudo` and `doas` close the descriptors they inherit — which costs nothing, since a task
  that escalates without isolation is rejected when it is resolved.

  The host side of that copy stays in the parent and goes through `read_host_file`, which
  opens with `O_NOFOLLOW`, `fstat`s the *opened* descriptor, and reads from it. The earlier
  `validate_host_file_exists` resolves a path string, so it can only report what was true
  then; repointing the name in between used to make execution stage whatever it pointed at
  under a path validation had approved. It remains as the pre-flight check that gives a
  readable error, and its doc says it is not the control.
- **RAII lifecycle managers.** `RootfsMounts` and `RootfsResolvConf` (plus
  `StagedFileGuard` in `src/phase/mod.rs`, which removes scripts and binaries staged
  into the rootfs) all guarantee cleanup via `Drop`, including on error paths. Mounts
  unmount in reverse order and `unmount()` is idempotent, collecting errors across entries.
  `RootfsResolvConf` detaches the rootfs's own resolv.conf with `RootfsOps::take`, which
  returns it as a value (file content, mode and owner, or symlink target and owner) rather
  than moving it to a backup path, and puts it back on teardown or `Drop`.

  Holding it in memory removes two failure modes a backup file had. A crash left the backup
  as an orphan the operator had to move back by hand, and an attacker who could pre-create the
  backup path as a *dangling* symlink defeated both the leftover check and the restore —
  `exists()` and `try_exists()` both follow links, so a dangling backup read as absent and the
  original was silently lost. The trade is that the original only survives as long as the
  process does — which is why `setup` arms the guard *before* installing the replacement. If
  the install fails and the rollback fails with it, the restore is still owed and `Drop` is the
  one thing left holding the entry; the returned error names the detached original rather than
  only the write that failed.

  `take` reads before it detaches, on a descriptor. One `openat` of the caller's own name
  decides the type, the size, the mode and the owner by `fstat`, and a symlink (which cannot
  be opened for reading) is held by `O_PATH | O_NOFOLLOW` and read back with an empty path to
  `readlinkat`. The open is non-blocking, because a FIFO left in the way would otherwise wait
  for a writer that is never coming — for the privileged helper, that is the build hanging
  with no output. Only then is the entry renamed to a sibling whose name carries a fresh
  UUID, which takes the caller's name out of play in one syscall.

  Reading first is what makes that rename checkable. A rename does not make the new name
  *secret* — a watcher on the directory is told where one lands — so the detached name has to
  be compared against something the watcher cannot have chosen, and that is the identity of
  the descriptor opened while the entry was still the caller's. Sampling the identity from
  the detached name afterwards instead would describe whatever is there by then, and agree
  with itself no matter who put it there.

  It also puts every refusal (wrong type, over `MAX_TAKE_SIZE`) before anything has moved, so
  a refused `take` leaves the caller's name exactly as it was and there is no rollback rename
  to aim at the wrong inode. The read stays bounded even though the size came off the same
  descriptor, because the entry is still linked at its own name and a writer can be appending
  to it. `read_host_file` bounds the host side the same way and for a second reason: staging
  crosses the privilege boundary as one base64-in-JSON request, so the bytes exist several
  times over at the peak.

  Staging a *symlink* cannot bind at all: no syscall creates one and hands back a descriptor,
  and the staging name is announced to anyone watching the directory. Checking is enough
  there for a reason that does not generalize — a symlink has nothing to it but its target,
  which is fixed at creation, so a link that is a symlink, points where the call asked, and
  carries the owner it restored is not merely *like* the staged one, it is indistinguishable
  from it. All three come off one `O_PATH | O_NOFOLLOW` descriptor, and its identity is what
  the promoting rename rechecks.

  The steps that name an entry rather than holding one are where binding stops being
  achievable, and there are three: the `renameat` that detaches, the `unlinkat` that removes
  what was taken, and the `renameat` that promotes a staged write over the caller's name.
  Linux has neither unlink- nor rename-by-descriptor, so each compares `st_dev`/`st_ino`
  against the inode a descriptor already established and errors out rather than acting on
  another — a UUID in a staging name is not a secret from anyone watching the directory.
  Those checks narrow the window to two syscalls rather than closing it, and each says so
  where it stands. When one fails, nothing is published and nothing is removed: the name
  means someone else's entry at that point, and neither is ours to do.

  What the value carries is what a faithful restore needs: content, mode and owner.
  `put_back` installs a *new* inode — that is what makes it atomic — so an owner it did not
  record would be replaced by the writer's, which is root for the whole of a privileged run.
  Timestamps, xattrs and ACLs are not carried, and hard-link identity no in-memory
  representation could carry.

## Isolation & command execution

- `IsolationProvider`/`IsolationContext` (`src/isolation/mod.rs`) abstract the backend.
  `ChrootProvider` runs inside a chroot; `DirectProvider` (`src/isolation/direct.rs`)
  executes on the host, translating absolute paths to rootfs-prefixed paths
  (`/bin/sh` → `<rootfs>/bin/sh`) and guarding against empty or post-teardown commands.

  That translation is a string join, and the kernel resolves the result when it execs — so a
  rootfs whose `/bin/sh` is a symlink pointing outward used to run a host binary. The program
  (only the program: it is the one argument the kernel resolves on our behalf) is now walked
  component by component with `O_NOFOLLOW` first, with the final component checked by
  `statat` rather than an open, because `O_NOFOLLOW | O_PATH` opens the *link itself* and
  succeeds. See also the escalation ban in
  [Configuration & resolution model](#configuration--resolution-model).
- `IsolationContext` is split so that the two capabilities can be handed out separately.
  `RootfsContext` is the rootfs view — `rootfs()`, `dry_run()`, `rootfs_ops()` — and
  `IsolationContext: RootfsContext` adds `name()`, `execute()` and `teardown()`. Only
  provision tasks are given the latter.
- **One answer to "is this a dry run".** `CommandExecutor::dry_run()` is it; contexts,
  `RootfsMounts` and `rootfs::open` all derive from there, and `IsolationProvider::setup`
  takes no such flag. The value existed four times over before, passed independently, so a
  dry-run executor paired with a live context was constructible and wrote for real. `main`
  builds the executor from `--dry-run` and nothing downstream re-reads the CLI flag.

  Two things keep it that way rather than leaving it to review. `dry_run()` has no default
  implementation: a default would have to be `false`, so an executor that forgot to answer
  would claim to be a live run, and the omission is a compile error instead. And `run_apply`
  takes `CommonArgs`, not `ApplyArgs`, so `--dry-run` is not in scope where the run happens —
  a caller cannot pass a flag that disagrees with the executor, because it cannot pass one at
  all. Both holes were real: a test executor inheriting the default drove a "dry run" that
  created directories and escalated to a `sudo` rootfs helper.
- Privilege is threaded through *command* execution as `Option<PrivilegeMethod>`, so
  escalation is uniform across the commands that genuinely are external programs
  (`mount`, `umount`, `chroot`, the bootstrap backend, provision scripts).

### Privilege boundary

Rootfs *mutation* does not use that path. `rootfs::open()` is called once for the run in
`run_pipeline_phase`, and when `defaults.privilege` is set it spawns one helper —
`sudo <self> __rootfs-helper --rootfs <path>`, a hidden subcommand of this same binary — which
opens the rootfs descriptor and serves typed `Request`s over a pipe (`src/rootfs/helper.rs`).
Every path in a `Request` is a `RelPath`, and no variant carries a host path — host files are
read by the parent, so only bytes cross the boundary. Those bytes are base64: the protocol is
one JSON object per line, and `serde_json` renders a `Vec<u8>` as a decimal array, which costs
about 4.6 bytes of text per byte of file — enough to turn a mitamae binary into a
hundreds-of-megabytes line parsed one integer at a time. A raw length-prefixed frame would
avoid the remaining 33%, at the cost of making the payload the one part of the protocol that
is not self-delimiting, in a reader running as root. The anchor itself is the exception that
cannot be typed away: it is a path argument from the unprivileged parent, so a `sudo` rule
permitting the helper permits root writes under any directory the invoking user can name.
`CheckedAnchor` refuses the live system's own hierarchy; grant the rule accordingly.

It refuses it by inode, and only after opening: the descriptor is taken first and the check
runs against *that*, because resolving the path once to check it and again to open it is the
check-then-use shape the rest of this module exists to avoid. Comparing inodes rather than
strings also catches names canonicalization does not resolve, such as a bind mount of `/etc`.
Being the only way to construct the value `dispatch` takes is what keeps the check from being
skipped.

Opening the anchor is itself a walk, one component at a time under `O_NOFOLLOW`, because a
single `openat` of the whole path applies `O_NOFOLLOW` to the last component only. Root
following an intermediate symlink would anchor it wherever that points, and the refusal list
names the *top* of each live hierarchy — `/etc` is on it, `/etc/ssh` is not, so a redirected
anchor would land under a floor that never fires. Refusing symlinks there does not refuse a
legitimate layout: `rootfs::open()` resolves the path's prefix first, in the unprivileged
parent, so a rootfs reached through a symlinked `/home` still works and the resolution that
made it work never held privilege. The final component is deliberately left out of that —
a rootfs that is itself a symlink stays refused, because resolving it would turn the refusal
into a redirection.

The one other `rootfs::open()` in a run escalates nothing, and has to not. A provision task
that resolved to no isolation cannot also have resolved to a privilege — `ProvisionTask::resolve`
refuses that pair — so its script is exec'd as the calling user, and a script staged through the
helper would arrive `root:root` at the owner-only mode staging asks for, denying the exec it was
staged for. `run_provision_item` therefore opens local ops for the direct branch, passing
`privilege: None`, which is where the staging identity sat before the helper existed. Pinned by
`direct_execution_does_not_stage_through_the_runs_shared_ops` in `src/pipeline.rs`.

Privilege cannot be attached to an arbitrary command any more. `CommandSpec`'s fields are
private, and the only constructor that sets `privilege` for a fixed program takes the closed
`PrivilegedProgram` enum (`mount`, `umount`, `chroot`, the bootstrap backends — programs with
no syscall equivalent in this crate). `CommandSpec::for_task_command` is the exception, since
a provision task names its own program. It is `pub(crate)` and takes a `TaskCommandToken`
whose field is private to `isolation`, so only `isolation::direct` can build one and every
other caller fails to compile. The token cannot bound *which argv* is handed to it, which is
what `tests/privilege_boundary_test.rs` scans for.

`IsolationContext` no longer exposes the executor either — that accessor existed so the
assemble task could issue `cp`/`ln`/`mv`, and nothing needed it once `RootfsOps` replaced
them. A `CommandSpec` built inside a phase is therefore inert; what a task can do is bounded
by the context trait it is handed.

Which context that is now depends on the phase. An `AssembleItem` gets a `RootfsContext`,
which has no `execute`, so `ctx.execute(["cp", "/etc/shadow", …], Some(Sudo))` from an
assemble task is a compile error rather than a reviewer's job to catch. Only `ProvisionItem`
gets the full `IsolationContext`, where running a declared program is the point.

This makes "assemble cannot run a program" a permanent property, deliberately: assemble
writes the rootfs's final state, and anything that wants to run a program is provision's
work. A future assemble task that genuinely needed one would also have to answer *under what
isolation* — `AssembleConfig` has no `isolation` key — so it would be a profile-format change,
not just a widening of this trait.

Two things follow that per-command escalation could not give:

- **Root's authority is bounded by an enum, not by what a command can be argued into.** Every
  request carries a `RelPath`, which cannot express a path outside the rootfs, so the escape is
  refused while *decoding* — before any operation runs, and regardless of what root could
  otherwise reach.
- **No coreutils binary runs as root.** `which`-resolved `cp`/`mv` no longer execute with
  elevated privilege at all.

Because the boundary is crossed once for the whole run, privilege for rootfs mutation is a
property of the run rather than of a task. `assemble.resolv_conf` therefore has no `privilege`
key; it was removed rather than left as a silent no-op (`deny_unknown_fields` makes setting it
a parse error).

`tests/privileged_helper_test.rs` exercises this against a root-owned rootfs under real `sudo`,
including that the helper exits when its parent drops the channel — otherwise a root process
would outlive the build holding a descriptor into the rootfs. It is `#[ignore]`d and skips
itself when passwordless sudo is unavailable.
- `CommandSpec` (`src/executor/mod.rs`) is the command value object (command/args/cwd/
  env/privilege) with a builder API. `RealCommandExecutor` implements dry-run and is what
  `dry_run()` answers for; tests use mock executors to assert on constructed commands without
  running anything.

## Bootstrap backends

`BootstrapBackend` (`src/bootstrap/mod.rs`) is the interface; `MmdebstrapConfig` and
`DebootstrapConfig` implement it. Each builds its own argument vector and decides
whether the output is a directory or an archive. Bootstrap privilege resolves against
profile defaults like any other task.

## JSON Schema generation

`rsdebstrap schema` prints a JSON Schema for the YAML profile, generated **directly from the
Rust config types** via `schemars` (`profile_json_schema()` / `profile_json_schema_pretty()` in
`src/lib.rs`). There is no hand-written schema JSON: the Rust types are the single source of
truth, so the schema cannot describe a shape that `apply`/`validate` would not accept. Schema
generation is unconditional: `schemars`/`serde_json` are ordinary dependencies and every
`JsonSchema` derive is a plain derive.

This was once behind a default-on `schema` cargo feature, so `apply`/`validate`-only builds
could drop schemars. The feature cost 82 `cfg`/`cfg_attr` sites, a second feature graph CI had
to compile, and a crate-level gate on the schema test suites that took the drift guards with
it — all to save 460 KB of binary (measured: 3.42 MB vs 3.89 MB, release).
Removing it made the whole `Deserialize`/`JsonSchema` alignment problem smaller: with one
feature graph, a type either carries both derives or neither, and there is no build in which
the drift guards silently do not run.

The non-obvious parts are all about keeping the schema faithful to the *deserializer*:

- **The YAML text layer is aligned with the JSON data model** (`src/de.rs`). `yaml_serde`'s text
  deserializer hands the raw scalar text to any field that asks for a string — `dir: null` would
  otherwise parse as the literal path `"null"` (and only outside internally tagged enums, whose
  content buffering resolves scalars first, so acceptance was context-dependent) — and it accepts
  an *empty* value as the default for container fields while rejecting an explicit `null`.
  String-typed fields therefore deserialize through the `deserialize_any`-based helpers in
  `src/de.rs`, which reject non-string scalars uniformly, and defaulted section/list/map fields
  (including `defaults.mitamae`, whose empty form yaml_serde already accepted) map an explicit
  `null` to the default. The net rule: an explicit `null` and an empty value are equivalent
  everywhere, and on defaulted section/list/map fields they additionally mean "key omitted" (what
  a fully commented-out section leaves behind). Fields that reject the empty form — scalars, the
  tagged `isolation` config, everything inside the internally tagged `bootstrap:` maps — keep
  rejecting `null` too. The schema models the lenient fields as nullable to match, and string
  fields as plain strings.
- **camino paths.** `Utf8PathBuf` has no `schemars` support and the orphan rule forbids a direct
  impl, so path fields point at the `Utf8PathSchema` proxy (`src/schema.rs`) via
  `#[schemars(with = "...")]`. Forgetting it on a new path field is a **compile error** (the
  derive requires `Utf8PathBuf: JsonSchema`, which does not hold), so this cannot drift silently.
- **Custom-`Deserialize` types deserialize *through* their wire shape.** `Privilege` /
  `TaskIsolation` accept a `true`/`false`/map/null shorthand via a `#[serde(untagged)]` wire enum
  (`PrivilegeWire` / `TaskIsolationWire`) that drives both `Deserialize` and `JsonSchema`, so the
  schema's `anyOf[bool, map, null]` cannot describe a different acceptance set from the parser.

  These once had a hand-written visitor for production and the wire enum for schemars only. The
  outer acceptance set then existed twice with no compile-time tie, held together by
  `wire_parity` tests. Collapsing them cost the visitor's `expecting` message ("a boolean or a
  map with a 'method' field") in favor of untagged's "did not match any variant"; `load_profile`
  wraps deserialization in `serde_path_to_error`, so errors carry the field path
  (`provision[2].privilege`) instead. `ShellTask` / `MitamaeTask` never had the split: they
  forward to their hoisted `Raw*` DTOs, which *are* the deserialize path.
- **`script` xor `content`** is enforced at runtime by `resolve_script_source`; the schema mirrors
  it as a `oneOf` on the `Raw*` DTO, shared by both provisioners via
  `schema::script_or_content()`. Each branch constrains the source to a *string*, not mere key
  presence, because `serde` treats an explicit `null` on an `Option` field as absent — so
  `{ script: null, content: hi }` is accepted and `{ script: null }` rejected, matching serde.
  This is the *only* mutual exclusion mirrored in the schema, because it is the only one enforced
  at deserialize time. The `resolv_conf` exclusions (`copy` vs `name_servers`/`search` in prepare,
  `link` vs `name_servers`/`search` in assemble) are *semantic* — checked in `validate()`, not
  `Deserialize` — so encoding them as a schema `oneOf`/`not` would reject documents the
  deserializer accepts, violating the never-false-reject invariant. They stay out of the schema
  deliberately.
- **`deny_unknown_fields` ⇒ `additionalProperties: false`.** Applied to `Profile`, `Defaults`,
  `MitamaeDefaults`, `MountEntry`, `PrivilegeDefaults`, both bootstrap configs, and
  `ChrootIsolation` so typo'd keys are rejected. It is honored even on the internally tagged
  `Bootstrap` / `IsolationConfig` variants because serde's internally-tagged newtype-variant
  deserialization consumes the `type` tag when selecting the variant and hands only the remaining
  fields to the variant struct (so the tag is not seen as an unknown field) — serde-core behavior
  that holds under `serde_json` and `yaml_serde` alike, not a parser quirk. The well-known serde
  limitation is narrower: `deny_unknown_fields` is a no-op when placed on the internally-tagged
  *enum* itself, which is why both `Bootstrap` and `IsolationConfig` put it on their variant
  payload structs instead. On the schema side, `schemars` inlines the `type` const into each
  `oneOf` branch's `properties`, so `additionalProperties: false` does not falsely reject the
  discriminator.
- **IP address fields use `format`, not a hard `pattern`.** `name_servers` renders via the
  `IpAddrSchema` proxy as `{ type: string, anyOf: [ { format: ipv4 }, { format: ipv6 } ] }`.
  `format` is annotational (non-asserting by default), so the schema never *rejects* a string the
  `IpAddr` deserializer accepts. A regex `pattern` strict enough to reject non-IPs would have to
  accept the entire `IpAddr::from_str` grammar (compressed and embedded-IPv4 forms, …) exactly;
  getting it slightly wrong would reintroduce false-rejects, so it is avoided on purpose. Editors
  and format-asserting validators still surface non-IP values through `format`.
- **Enum variants must not carry serde aliases `schemars` won't emit.** `#[serde(alias = "…")]`
  makes the deserializer accept a spelling that never appears in the generated `oneOf`, producing a
  schema false-reject. The `Variant` / `Mode` / `Format` defaults previously aliased `""`; the
  aliases were removed so `""` is a hard parse error on both sides, and `schema_proptest`'s
  bootstrap axis now includes `""` to lock it.

Drift guards (all in `cargo test`, so CI fails on drift):

- **`schema/rsdebstrap.schema.json` is committed** and byte-compared against generator output by
  `committed_schema_is_up_to_date`. It is rendered with tab indentation (via
  `profile_json_schema_pretty()`) to satisfy `.editorconfig`. Regenerate after any config-type
  change with `task schema` (wraps `cargo run -- schema > schema/rsdebstrap.schema.json`). The
  autofix.ci workflow runs `task schema` on every pull request and auto-commits the regenerated
  file, so drift normally fixes itself; this byte-compare test remains the enforcement backstop.
- **Differential + property tests** (`tests/schema_test.rs`, `tests/schema_proptest.rs`) assert the
  critical safety invariant: whenever the structural deserializer accepts a document, the schema
  must accept it too (no false rejections that would make editor tooling flag valid configs). The
  property test asserts this twice per generated document — once on the `serde_json::Value` and
  once through a YAML text round-trip, because production parses YAML and `yaml_serde`'s
  acceptance surface is not identical to the JSON value model. The known divergences in the
  other direction (annotational `ipv4`/`ipv6` formats; mount targets, whose `RelPath` shape
  JSON Schema can only approximate with a regex; duplicate mapping keys, which serde rejects
  but the YAML→JSON conversion resolves last-wins before the schema can see them; and
  non-finite floats like `.nan`, which that conversion collapses to `null`, so nullable fields
  schema-accept them) are pinned with per-side expectations in `schema_divergences_are_pinned`.

  That direction is checked, not merely documented: the property test asserts the converse too,
  allowing only those classes. A schema that accepts what the parser rejects is not a safety
  violation, but an unlisted one means the schema drifted looser than the parser with nothing
  saying so. Typing `mount.target` as a `RelPath` produced exactly such a divergence, and this
  assertion is what surfaced it. Semantic checks that JSON Schema cannot express (mount
  `name_servers` exclusivity, mitamae binary resolution) stay in `Profile::validate_*` and are out
  of scope here.

## MSRV policy

The Minimum Supported Rust Version is **declared** as `rust-version` in `Cargo.toml` (the
machine-readable floor `cargo` and packagers read) and **pinned** to an exact patch release in
`rust-toolchain.toml` (`channel`) for reproducible builds. The policy uses a single pinned stable
toolchain; `rust-version` declares the MSRV floor, while `tests/msrv_test.rs` enforces
`major.minor` agreement (patch versions may differ) rather than a matrix-verified range. Bumping
the pin to a new minor therefore requires a deliberate `rust-version` bump in the same change.

## Testing pattern

Mock-executor pattern (`tests/helpers/mod.rs`):

- `MockContext` — shared mock isolation context with injectable failure modes
  (`should_fail`, `should_error`, `return_no_status`); records `executed_commands` and
  `executed_privileges` for assertions.
- `load_profile_from_yaml()` / `load_profile_from_yaml_typed()` load profiles from YAML
  strings in temp files.
- Builders `MmdebstrapConfigBuilder` / `DebootstrapConfigBuilder` (fluent API).
- Privilege tests exercise resolution, inheritance, and error handling across tasks and
  bootstrap backends.

### Known test gaps

- **`run_provision_item()` teardown failure paths** (execute `Ok`/teardown `Err`, and
  `Err`/`Err`) are untestable today: the pipeline builds providers from
  `task.resolved_isolation_config()`, so failure injection is impractical, and both
  `ChrootProvider` and `DirectProvider` have infallible teardown — these paths are
  unreachable with current backends. Add tests when a backend with fallible teardown
  (bwrap, systemd-nspawn) lands.
- **Escalation is only exercised for filesystem operations.** `tests/privileged_helper_test.rs`
  runs the helper under real `sudo`, but the per-command escalation path
  (`mount`/`umount`/`chroot`/bootstrap) is still only asserted at the argv level. A full
  privileged `apply` has been run by hand; nothing runs it automatically.
- **`run_pipeline_phase()` sequencing and gating** are covered by in-crate tests in
  `src/lib.rs`, using a recording executor that really runs the provision command and
  `RootfsOps` failure injection against a temp rootfs: the temporary resolv.conf is
  restored after provision (a real provision command sits between setup and restore)
  and before assemble; assemble is gated on both the prepare/provision result and the
  restore result; assemble runs only after the mounts are released (an executor and an
  ops wrapper sharing one timeline pin `mount` → `umount` → the assemble write); an
  assemble failure propagates while the atomically-staged replace leaves the restored
  original in place; and both link- and generate-mode assemble tasks are exercised
  end-to-end. The remaining gap is the interplay with real mount/unmount failures —
  `RootfsMounts` unit tests cover those error paths independently via
  `MockMountExecutor`.
