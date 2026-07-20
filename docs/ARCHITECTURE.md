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
  `PhaseItem` with a no-op `execute()`; their real effect is bracketed around the *whole*
  phase by the RAII managers below, set up in `run_pipeline_phase()` between mount and execution.
- **Assemble operates on the final rootfs directly.** `AssembleResolvConfTask::resolved_isolation_config()`
  returns `None`, so it runs via `DirectProvider` on the rootfs filesystem rather than
  inside an isolation context.

`prepare`/`assemble` are **named-field structs** (`PrepareConfig { mount, resolv_conf }`,
`AssembleConfig { resolv_conf }`), not lists. This makes the singleton invariants structural:
"at most one mount" / "at most one resolv_conf" hold because each is an `Option` (a duplicate
YAML key is a `serde_yaml` parse error, an unknown key a `deny_unknown_fields` error), and the
`mount → resolv_conf` order is fixed by `items()` rather than by key order. The former
count/order validators (`validate_prepare_order`, and the count checks in
`validate_mounts`/`validate_resolv_conf`/`validate_assemble_resolv_conf`) were therefore
removed; only cross-field checks remain in `Profile::validate_*` (mounts → chroot + privilege;
prepare `resolv_conf` → chroot; `mount`/`umount` in `PATH`). Prepare and assemble may each
carry a `resolv_conf` task — they play different roles (temporary DNS during provisioning vs.
the permanent installed file).

## Filesystem safety: TOCTOU & RAII

The rootfs is an untrusted directory tree we mutate with elevated privileges, so two
patterns run throughout `src/isolation/`:

- **TOCTOU-safe path traversal.** `safe_create_mount_point()` never trusts a resolved
  path string: it opens the rootfs with `O_NOFOLLOW`, then walks each component with
  `openat(O_NOFOLLOW)` / `mkdirat`, treating `ELOOP`/`ENOTDIR` as a symlink attack
  (`RsdebstrapError::Isolation`). Verified absolute paths are cached and reused for the
  matching `umount` to avoid re-traversal. The assemble `resolv_conf` `/etc` handling
  applies a narrower fd-based check — a single `openat(O_NOFOLLOW)` on `<rootfs>/etc` to
  reject a symlinked `/etc` — but a TOCTOU window remains before the subsequent
  `mv`/`cp`/`ln` path-string commands, inherent to privilege escalation via external
  commands. Implemented with the `rustix` crate for memory-safe syscall wrappers.
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

## JSON Schema generation

`rsdebstrap schema` prints a JSON Schema for the YAML profile, generated **directly from the
Rust config types** via `schemars` (`profile_json_schema()` / `profile_json_schema_pretty()` in
`src/lib.rs`). There is no hand-written schema JSON: the Rust types are the single source of
truth, so the schema cannot describe a shape that `apply`/`validate` would not accept. All of it
is compiled behind the **default-on `schema` cargo feature**: `schemars`/`serde_json` are
optional dependencies enabled by it, every `JsonSchema` derive and `#[schemars(...)]` attribute
is `cfg_attr`-gated, and the `schema` subcommand plus `profile_json_schema*()` do not exist
under `--no-default-features` (for size-constrained `apply`/`validate`-only builds). The schema
test suites carry a crate-level `#![cfg(feature = "schema")]`, so a default `cargo test` — which
is exactly what CI's test job runs — still exercises every drift guard, while
`--no-default-features` compiles them to empty crates instead of failing. (In-file gating, not a
Cargo `[[test]]` stanza with `required-features`: an explicit test target makes manifest parsing
require the file, which breaks CI's sparse checkouts that fetch/build without `tests/`.) A missed
`cfg_attr` on a new field only surfaces in the schema-less build, which is why
`cargo check --all-targets --no-default-features` is part of the routine command set in AGENTS.md
**and runs in CI's test task** — the gate design is only real if that feature graph actually
compiles somewhere.

The non-obvious parts are all about keeping the schema faithful to the *deserializer*:

- **The YAML text layer is aligned with the JSON data model** (`src/de.rs`). `serde_yaml`'s text
  deserializer hands the raw scalar text to any field that asks for a string — `dir: null` would
  otherwise parse as the literal path `"null"` (and only outside internally tagged enums, whose
  content buffering resolves scalars first, so acceptance was context-dependent) — and it accepts
  an *empty* value as the default for container fields while rejecting an explicit `null`.
  String-typed fields therefore deserialize through the `deserialize_any`-based helpers in
  `src/de.rs`, which reject non-string scalars uniformly, and defaulted section/list/map fields
  (including `defaults.mitamae`, whose empty form serde_yaml already accepted) map an explicit
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
- **Custom-`Deserialize` types forward their schema to the real wire shape.** `Privilege` /
  `TaskIsolation` hand-write `Deserialize` for the `true`/`false`/map/null shorthand, so their
  `JsonSchema` forwards to a `#[serde(untagged)]` wire enum (`PrivilegeWire` / `TaskIsolationWire`)
  that carries the same map type plus a null unit variant — the schema's `anyOf[bool, map, null]`
  then mirrors deserialization. The map branch genuinely shares one definition with the visitor
  (`PrivilegeMethodMap` / `IsolationConfig`), but the *outer* acceptance set (bool/map/null) exists
  twice — as the wire enum's variants and as the visitor's `visit_*` methods — with no compile-time
  tie; the in-file `wire_parity` tests pin the two sets together by asserting acceptance
  equivalence over a battery of shapes. `ShellTask` / `MitamaeTask` have no such split: they
  forward to their hoisted `Raw*` DTOs, which *are* the actual deserialize path.
- **`script` xor `content`** is enforced at runtime by `resolve_script_source`; the schema mirrors
  it as a `oneOf` on the `Raw*` DTO. Each branch constrains the source to a *string*, not mere key
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
  that holds under `serde_json` and `serde_yaml` alike, not a parser quirk. The well-known serde
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
  once through a YAML text round-trip, because production parses YAML and `serde_yaml`'s
  acceptance surface is not identical to the JSON value model. The few intentional divergences in
  the other direction (annotational `ipv4`/`ipv6` formats; duplicate mapping keys, which serde
  rejects but the YAML→JSON conversion resolves last-wins before the schema can see them) are
  pinned with per-side expectations in `schema_divergences_are_pinned` so the set cannot grow
  silently. Semantic checks that JSON Schema cannot express (mount ordering, `copy` vs
  `name_servers` exclusivity, mitamae binary resolution) stay in `Profile::validate_*` and are out
  of scope here.

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
