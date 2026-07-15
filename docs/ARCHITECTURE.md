# Architecture

Design rationale for rsdebstrap internals. This documents the *why* — decisions
and invariants that are not obvious from reading the code. Exhaustive field and
method lists are intentionally omitted; the source is authoritative for those.

For the high-level map, build commands, and the YAML profile contract, see
[`AGENTS.md`](../AGENTS.md).

## Core flow

```
CLI (src/cli.rs) → Config (src/config.rs) → Bootstrap (src/bootstrap/) → Pipeline (src/pipeline.rs)
```

1. **CLI** parses arguments (clap): `apply`, `validate`, `completions`.
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
- `resolve()` collapses a state against the profile default into a concrete
  `Option<...>` (`None` == disabled/no-op). `resolve_in_place()` mutates ahead of execution.
- **Non-obvious:** for `TaskIsolation`, `UseDefault` and `Inherit` behave identically
  because `IsolationConfig` always has a default (`Chroot`). Both variants exist only
  for API symmetry with `Privilege`, where the distinction is real.

`mount` and `resolv_conf` used to live under `IsolationConfig`; they were moved out to
the `prepare` phase. `IsolationConfig` is now just the backend selector (`Chroot`).

## Phases & the pipeline

`Pipeline` (`src/pipeline.rs`) holds the three task slices and drives them uniformly
through the `PhaseItem` trait (`src/phase/mod.rs`, `pub(crate)`) — `name`/`validate`/
`execute`/`resolved_isolation_config`. Generic `run_phase_items`/`validate_phase_items`
avoid per-phase duplication.

Key invariants:

- **Per-task isolation lifecycle.** Each task independently runs
  provider → setup → execute → teardown. Teardown is guaranteed even when execute
  errors. Failure-injection for teardown paths is currently impractical (see
  [Known test gaps](#known-test-gaps)).
- **Prepare tasks are declarative.** `PrepareTask::execute()` is a no-op for both
  `Mount` and `ResolvConf`; their real effect is bracketed around the *whole* phase by
  the RAII managers below, set up in `run_pipeline_phase()` between mount and execution.
- **Assemble operates on the final rootfs directly.** `AssembleTask::resolved_isolation_config()`
  returns `None`, so it runs via `DirectProvider` on the rootfs filesystem rather than
  inside an isolation context.

Ordering rules enforced at validation time (`Profile::validate_*`): at most one mount
task and one `resolv_conf` task per phase; mount tasks precede `resolv_conf` tasks in
`prepare`. Prepare and assemble may each carry a `resolv_conf` task — they play
different roles (temporary DNS during provisioning vs. the permanent installed file).

## Filesystem safety: TOCTOU & RAII

The rootfs is an untrusted directory tree we mutate with elevated privileges, so two
patterns run throughout `src/isolation/`:

- **TOCTOU-safe path traversal.** `safe_create_mount_point()` and the assemble
  `resolv_conf` `/etc` handling never trust a resolved path string. They open the
  rootfs with `O_NOFOLLOW`, then walk each component with `openat(O_NOFOLLOW)` /
  `mkdirat`, treating `ELOOP`/`ENOTDIR` as a symlink attack (`RsdebstrapError::Isolation`).
  Verified absolute paths are cached and reused for the matching `umount` to avoid
  re-traversal. Implemented with the `rustix` crate for memory-safe syscall wrappers.
- **RAII lifecycle managers.** `RootfsMounts`, `RootfsResolvConf`, and `TempFileGuard`
  all guarantee cleanup via `Drop`, including on error paths. Mounts unmount in reverse
  order and `unmount()` is idempotent, collecting errors across entries.
  `RootfsResolvConf` backs up the existing file and rolls back via rename on write
  failure to avoid destroying the host/rootfs resolv.conf. Atomic writes go through a
  temp file + `cp`.

## Isolation & command execution

- `IsolationProvider`/`IsolationContext` (`src/isolation/mod.rs`) abstract the backend.
  `ChrootProvider` runs inside a chroot; `DirectProvider` (`src/isolation/direct.rs`)
  executes on the host, translating absolute paths to rootfs-prefixed paths
  (`/bin/sh` → `<rootfs>/bin/sh`) and guarding against empty or post-teardown commands.
- Privilege is threaded through execution as `Option<PrivilegeMethod>` — both
  `IsolationContext::execute()` and the `CommandExecutor` obtained via `ctx.executor()`
  take it, so escalation is uniform whether a task runs a script or issues raw
  `cp`/`chmod`/`ln` commands (as assemble `resolv_conf` does).
- `CommandSpec` (`src/executor/mod.rs`) is the command value object (command/args/cwd/
  env/privilege) with a builder API. `RealCommandExecutor` supports dry-run; tests use
  mock executors to assert on constructed commands without running anything.

## Bootstrap backends

`BootstrapBackend` (`src/bootstrap/mod.rs`) is the interface; `MmdebstrapConfig` and
`DebootstrapConfig` implement it. Each builds its own argument vector and decides
whether the output is a directory or an archive. Bootstrap privilege resolves against
profile defaults like any other task.

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

- **`run_task_item()` teardown failure paths** (execute `Ok`/teardown `Err`, and
  `Err`/`Err`) are untestable today: the pipeline builds providers from
  `task.resolved_isolation_config()`, so failure injection is impractical, and both
  `ChrootProvider` and `DirectProvider` have infallible teardown — these paths are
  unreachable with current backends. Add tests when a backend with fallible teardown
  (bwrap, systemd-nspawn) lands.
- **`run_pipeline_phase()` 4-way error matrix** (`Ok/Ok`, `Err/Ok`, `Ok/Err`, `Err/Err`)
  is not tested as an integration test — the function is private and needs real mounts.
  `RootfsMounts` unit tests cover the mount/unmount error paths independently via
  `MockMountExecutor`.
