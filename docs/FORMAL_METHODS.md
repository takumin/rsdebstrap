# Formal methods

How rsdebstrap decides what to prove, with which tool, and why two of them.

For the code map and build commands see [`AGENTS.md`](../AGENTS.md); for the internal design
this document verifies, see [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Why verify anything here

rsdebstrap builds a root filesystem by running external commands as root against a directory
tree it does not control. Two classes of bug in that setting are invisible to testing and
expensive in production:

- **A task escalates when the profile never asked it to.** The privilege setting passes through
  a four-state resolution model before it reaches the executor. A wrong arm in that model does
  not crash; it silently runs somebody's provisioning script under `sudo`.
- **The argument vector shifts under escalation.** When `sudo` becomes the exec'd program, the
  real command has to be re-inserted as `argv[0]`. An off-by-one there hands every flag the
  wrong value — as root, without an error.

Neither has a natural failing test, because neither is a crash. Both are total functions over
small data, which is exactly the shape a solver handles well.

## The layering rule

Verification tooling is not free to apply anywhere. Verus needs code written in its own subset
of Rust and cannot see `serde`, `clap`, or `std::process`; Kani needs bounded, finite reasoning
and chokes on unbounded loops and heavy `String` work. So the split follows the dependency
direction the code already has:

| Layer                | Where                              | Depends on                       | Tool                                                       |
| -------------------- | ---------------------------------- | -------------------------------- | ---------------------------------------------------------- |
| **Domain**           | `src/domain/`                      | nothing                          | **Verus** — deductive proof, unbounded, generic in payload |
| **Adapters**         | `src/config.rs`, `src/privilege.rs`, `src/isolation/mod.rs` | domain + serde  | exhaustive `cargo test` + `proptest`                       |
| **Infrastructure**   | `src/executor/`, `src/isolation/*`, `src/bootstrap/` | adapters + OS   | **Kani** — bounded model checking on the pure kernels      |

The dependency rule is what makes this work, not the tools. `src/domain/` may not `use` any
other module in this crate, has no I/O, no `serde`, no `anyhow`, no `tracing`. That constraint
is the price of admission for deductive proof: a function whose behaviour depends on the
filesystem cannot be reasoned about without modelling the filesystem.

Infrastructure code cannot be made pure — it exists to touch the OS — so nothing tries. Instead
the *decisions* inside it get factored into pure kernels that Kani can bound-check, with the
syscalls left around them. `src/executor/plan.rs` is the worked example: `plan_argv` is the
argv reshaping with the `$PATH` lookup and the `fork`/`exec` lifted out of it.

**Verus is not applied to the shipped crate, and cannot be.** It compiles with its own rustc
build and requires `verus!{}`-macro syntax throughout; `Privilege` and `TaskIsolation` carry
hand-written `serde` impls that would have to be `#[verifier::external_body]` — assumed, not
proved. So `verify/verus/resolution.rs` restates the domain model in Verus and proves the
properties there, and the correspondence to `src/domain/resolution.rs` is maintained by hand.
That is a real gap, and it is the reason the same properties are *also* discharged inside the
crate — see [Why both](#why-both).

## The resolution specification

`src/domain/resolution.rs` collapses a task's override against the profile default. `Tri<T>` is
the override — `Inherit`, `UseDefault`, `Disabled`, `Explicit(T)` — and `resolve` is the rule.

| id     | property                     | statement                                                                                    |
| ------ | ---------------------------- | -------------------------------------------------------------------------------------------- |
| **R1** | totality, determinism        | `resolve` is defined on every input and returns the same answer for the same one              |
| **R2** | failure characterisation     | resolution fails **iff** the state is `UseDefault` and no default is configured               |
| **R3** | provenance                   | a resolved value is either the state's own `Explicit` payload or the default it inherited     |
| **R4** | defaults-independence        | `Disabled` and `Explicit` resolve identically under any defaults                              |
| **R5** | closure                      | `collapse` of any resolution is `is_resolved()` — never `Inherit`/`UseDefault`                |
| **R6** | idempotence                  | re-resolving an already-resolved state is a no-op, even under a different default             |
| **R7** | `Inherit` ≡ `UseDefault`     | when a default exists, the two states are indistinguishable                                    |
| **R8** | refinement                   | `resolve_with_default` agrees with `resolve` wherever `resolve` cannot fail                    |

**R3 is the one that matters operationally.** Instantiated at privilege, it says a task cannot
end up running under `sudo`/`doas` unless the profile named that method — either on the task or
in `defaults.privilege`. There is no path through resolution that manufactures escalation.

**R7 used to be a comment.** `ARCHITECTURE.md` noted that `TaskIsolation` keeps both `Inherit`
and `UseDefault` even though they behave identically, "only for API symmetry with `Privilege`".
That is not a property of `TaskIsolation`; it is a consequence of the model whenever a default
exists, and it is now proved rather than asserted.

**R5 is what the accessors rely on.** `resolved_method()` and `resolved_config()` treat the
unresolved states as a logic error rather than a case to handle. R5 is why that is sound after
resolution has run.

### Where each property is discharged

- `tests/resolution_spec_test.rs` — R1–R8 exhaustively, plus `A1`–`A4` tying `Privilege` and
  `TaskIsolation` to the domain functions over their own full state spaces. Runs in
  `cargo test`, so it gates every commit.
- `verify/verus/resolution.rs` — R2–R8 as Verus `proof fn`s, universally quantified over the
  payload type. R1 has no lemma there: a Verus `spec fn` *is* a total function, so totality and
  determinism hold by construction rather than by argument.

### Why both

The Rust-side discharge is exhaustive but only over a two-element payload type. That is enough
to distinguish "the default's value" from "some other value", which is all the model can
observe — but it is an argument about the model, made outside the model. If someone adds a
payload type whose equality is not reflexive, or a fifth `Tri` variant, the enumeration silently
covers less than it claims to.

The Verus side is quantified over an abstract `T` and has no such blind spot, but proves things
about a hand-maintained restatement rather than about the code that ships.

Each covers the other's weakness. Neither alone would be worth the maintenance.

## Infrastructure properties

`src/executor/plan.rs`, verified by Kani over all inputs up to four arguments:

| id     | property                                                                     |
| ------ | ---------------------------------------------------------------------------- |
| **P1** | without escalation, argv is the caller's arguments unchanged                   |
| **P2** | with escalation, argv is exactly one slot longer and slot 0 holds the command  |
| **P3** | with escalation, the caller's arguments survive in order — none dropped or duplicated |

The bound is what makes these *bounded* proofs: `kani::any()` covers every value, but only up to
`MAX_ARGS` arguments. Insertion bugs do not start at five arguments, so the bound costs nothing
real — but it is a bound, and calling these results "verified for all argument vectors" would be
wrong.

## Running it

Neither tool is aqua-pinned. Both ship as GitHub Releases outside the aqua standard registry,
and Verus additionally has no semver-ordered tags to pin — so requiring them would make the
ordinary build depend on a manual install. `task verify` is therefore **opt-in locally and
informational in CI**: it is not part of `task all`, and `wc-verify.yml` is deliberately absent
from the `ci` status check, exactly like `coverage`.

```bash
task verify          # both
task verify:verus    # domain proofs
task verify:kani     # infrastructure harnesses
```

Install, once:

```bash
# Verus — put the extracted directory itself on PATH; the binary loads vstd.vir and the
# builtin rlibs from alongside itself, so copying the binary out will not work.
#   https://github.com/verus-lang/verus/releases

# Kani
cargo install --locked kani-verifier
cargo kani setup
```

`cargo kani setup` downloads the CBMC backend from GitHub Releases; in a sandbox without
github.com egress neither tool can be installed at all, and `task verify` will say so rather
than appearing to pass.

The Kani harnesses live behind `#[cfg(kani)]`, which no ordinary `cargo build` compiles. That
cfg is declared in `Cargo.toml`'s `[lints.rust]` so it does not trip `unexpected_cfgs`; the
trade-off is that only `task verify:kani` can tell you the harnesses have rotted.

One wrinkle worth knowing about: **Kani pins its own nightly toolchain**, which trails the MSRV
this crate declares (1.93-nightly against `rust-version = "1.97"` as of Kani 0.67). Cargo
refuses to build a package whose `rust-version` exceeds the active toolchain, so `cargo kani`
would abort before verifying anything. `task verify:kani` therefore drops that one manifest
field for the duration of the run and restores it afterwards — via a Taskfile `defer`, so an
interrupted run cannot leave the manifest edited. The MSRV is a promise about the shipped
binary, not a property of the harnesses, and `tests/msrv_test.rs` still gates the real thing.

## What is not verified

Named so the coverage is not overstated:

- **The `serde` layer.** `Privilege`/`TaskIsolation` deserialization is hand-written and stays
  under the existing differential and property tests (`tests/schema_test.rs`,
  `tests/schema_proptest.rs`). Verus cannot see it; Kani would drown in `String`.
- **TOCTOU-safe path traversal** (`safe_create_mount_point`). The property — a symlink anywhere
  in the traversal is always rejected — is worth proving, but it is a statement about `openat`
  semantics and needs a filesystem model before a solver can say anything. Next candidate.
- **Pipeline ordering and RAII teardown.** "Teardown runs even when execute fails", "the
  temporary resolv.conf is restored before assemble" are temporal properties over a state
  machine, not properties of a function. Neither Verus nor Kani is the right shape; a TLA+ or
  Alloy model of `run_pipeline_phase` would be. Currently held by the in-crate tests described
  in [`ARCHITECTURE.md`](ARCHITECTURE.md#known-test-gaps).
- **Everything the external tools do.** `mmdebstrap`, `chroot`, `sudo` are contracts, not code
  under analysis.
