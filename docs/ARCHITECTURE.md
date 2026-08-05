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
- `resolve()` collapses a state against the profile default into a concrete
  `Option<...>` (`None` == disabled/no-op). `resolve_in_place()` mutates ahead of execution.
- **Non-obvious:** for `TaskIsolation`, `UseDefault` and `Inherit` behave identically
  because `IsolationConfig` always has a default (chroot). Both variants exist only for
  API symmetry with `Privilege`, where the distinction is real.

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
and `assemble: &AssembleConfig`, and drives them uniformly through the `PhaseItem` trait
(`src/phase/mod.rs`, `pub(crate)`) — `name`/`validate`/`execute`/`resolved_isolation_config`.
Each phase is flattened to a `&[&dyn PhaseItem]` before running: `PrepareConfig::items()` and
`AssembleConfig::items()` emit their present `Option` fields in a **fixed execution order**
(`mount → resolv_conf`), and provision maps its `Vec` to trait objects. Generic
`run_phase_items`/`validate_phase_items` avoid per-phase duplication.

Key invariants:

- **Per-task isolation lifecycle.** Each task independently runs
  provider → setup → execute → teardown. Teardown is guaranteed even when execute
  errors. Failure-injection for teardown paths is currently impractical (see
  [Known test gaps](#known-test-gaps)).
- **Prepare tasks are declarative.** `MountTask` and (prepare) `ResolvConfTask` implement
  `PhaseItem` with a no-op `execute()`; their real effect comes from the RAII managers below,
  set up in `run_pipeline_phase()`. The brackets differ: mounts wrap all three phases, but the
  temporary resolv.conf wraps only prepare + provision — it is torn down (the original
  restored) before assemble, so an assemble `resolv_conf` task's permanent file/symlink
  survives.

  That ordering is carried by two token types rather than by comment and convention.
  `Pipeline::run_prepare_and_provision` yields a `Provisioned`; `RootfsResolvConf::restore`
  consumes one and yields a `Restored`; `Pipeline::run_assemble` requires a `Restored`.
  Assembling before the restore is therefore a compile error, not a review finding. `Restored`
  is declared in the guard's own module so its constructor is private *there* — declared in
  `pipeline` it would be `pub(crate)` and the orchestration could mint one, which is exactly the
  mistake being prevented. `Pipeline::run` (no guard, so nothing was detached) is the one
  exemption, via a named function that still demands a `Provisioned`.
- **Assemble operates on the final rootfs directly.** `AssembleResolvConfTask::resolved_isolation_config()`
  returns `None`, so it runs via `DirectProvider` on the rootfs filesystem rather than
  inside an isolation context.

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
- **All rootfs mutation goes through `RootfsOps`** (`src/rootfs/`), which applies the same
  traversal to every write. Paths are `RelPath` values — absolute forms are accepted and
  normalized, `..` is rejected at construction — so no combination of them names anything
  outside the rootfs. Only the *final* component may be a symlink, and it is replaced rather
  than followed, which is what Debian's symlinked `/etc/resolv.conf` requires.

  This replaced `sudo mv` / `sudo cp` / `sudo chmod` per operation. Those took path *strings*,
  so an `openat(O_NOFOLLOW)` check could only prove a path was safe at one instant and the
  command then resolved the name again — the window was real and previously documented here as
  unavoidable. It is not: see *Privilege boundary* below.
- **RAII lifecycle managers.** `RootfsMounts` and `RootfsResolvConf` (plus
  `TempFileGuard` in `src/phase/mod.rs`, which cleans up scripts and binaries staged
  into the rootfs) all guarantee cleanup via `Drop`, including on error paths. Mounts
  unmount in reverse order and `unmount()` is idempotent, collecting errors across entries.
  `RootfsResolvConf` detaches the rootfs's own resolv.conf with `RootfsOps::take`, which
  returns it as a value (file content + mode, or symlink target) rather than moving it to a
  backup path, and puts it back on teardown or `Drop`.

  Holding it in memory removes two failure modes a backup file had. A crash left the backup
  as an orphan the operator had to move back by hand, and an attacker who could pre-create the
  backup path as a *dangling* symlink defeated both the leftover check and the restore —
  `exists()` and `try_exists()` both follow links, so a dangling backup read as absent and the
  original was silently lost. The trade is that the original only survives as long as the
  process does.

## Isolation & command execution

- `IsolationProvider`/`IsolationContext` (`src/isolation/mod.rs`) abstract the backend.
  `ChrootProvider` runs inside a chroot; `DirectProvider` (`src/isolation/direct.rs`)
  executes on the host, translating absolute paths to rootfs-prefixed paths
  (`/bin/sh` → `<rootfs>/bin/sh`) and guarding against empty or post-teardown commands.
- Privilege is threaded through *command* execution as `Option<PrivilegeMethod>` — both
  `IsolationContext::execute()` and the `CommandExecutor` obtained via `ctx.executor()`
  take it, so escalation is uniform across the commands that genuinely are external
  programs (`mount`, `umount`, `chroot`, the bootstrap backend, provision scripts).

### Privilege boundary

Rootfs *mutation* does not use that path. `rootfs::open()` is called once per run in
`run_pipeline_phase`, and when `defaults.privilege` is set it spawns one helper —
`sudo <self> __rootfs-helper --rootfs <path>`, a hidden subcommand of this same binary — which
opens the rootfs descriptor and serves typed `Request`s over a pipe (`src/rootfs/helper.rs`).

Privilege cannot be attached to an arbitrary command any more. `CommandSpec`'s fields are
private, and the only constructor that sets `privilege` for a fixed program takes the closed
`PrivilegedProgram` enum (`mount`, `umount`, `chroot`, the bootstrap backends — programs with
no syscall equivalent in this crate). `CommandSpec::for_task_command` is the exception, since
a provision task names its own program; `tests/privilege_boundary_test.rs` guards it, because
Rust cannot restrict a constructor to a single module within a crate.

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
  env/privilege) with a builder API. `RealCommandExecutor` supports dry-run; tests use
  mock executors to assert on constructed commands without running anything.

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
  other direction (annotational `ipv4`/`ipv6` formats; duplicate mapping keys, which serde
  rejects but the YAML→JSON conversion resolves last-wins before the schema can see them; and
  non-finite floats like `.nan`, which that conversion collapses to `null`, so nullable fields
  schema-accept them) are pinned with per-side expectations in `schema_divergences_are_pinned`.
  The pinning documents each known divergence exactly, but constrains only the enumerated rows:
  the invariant is deliberately one-directional, so a newly discovered false-accept fails no
  test and should be added to that table. Semantic checks that JSON Schema cannot express (mount
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

- **`run_task_item()` teardown failure paths** (execute `Ok`/teardown `Err`, and
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
  `src/lib.rs`, using a recording executor that really runs `mv`/`cp`/`rm`/`ln` and a
  shell provision task against a temp rootfs: the temporary resolv.conf is restored
  after provision (a real provision command sits between the setup and restore
  sequences) and before assemble; assemble is gated on both the prepare/provision
  result and the restore result (including a real restore-`mv` failure, which strands
  the backup and skips assemble); an assemble failure propagates while the
  atomically-staged replace leaves the restored original in place; and both link- and
  generate-mode assemble tasks are exercised end-to-end. The remaining gap is the
  interplay with real mount/unmount failures — `RootfsMounts` unit tests cover those
  error paths independently via `MockMountExecutor`.
