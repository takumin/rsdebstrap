---
name: task-runner-ci-standards
description: >-
  Create, update, and verify a repository's task runner and CI/CD pipeline
  against a coherent, battle-tested standard — independent of language or tech
  stack. Use this skill whenever the user wants to set up, refactor, or audit CI
  (GitHub Actions and similar), scaffold or clean up a task runner (Taskfile,
  Makefile, justfile, npm/pnpm scripts, mise, cargo-make, ...), pin action/tool
  versions, harden workflow permissions, make local and CI run the exact same
  commands, add format/lint/test/build/release gates, or set up reproducible
  toolchains and signed releases. Trigger even when the request names a specific
  stack (Rust/cargo, Node, Go, Python, Docker) instead of the word "CI", and for
  phrasings like "make my CI follow best practices", "audit my GitHub Actions",
  "why is my pipeline flaky/slow", "set up a Taskfile", "harden my workflows",
  or "my local build passes but CI fails".
---

# Task Runner & CI Standards

A portable standard for how a repository's **task runner** and **CI/CD pipeline**
should be built — extracted from a production reference implementation and stated
so it applies to **any language or stack**. Use it to create a pipeline from
scratch, audit an existing one, or refactor a messy one toward the standard.

## The one idea everything follows from

> **The task runner is the single source of truth for how to build, test, lint,
> and release. CI is a thin, least-privilege orchestrator that calls those same
> tasks — it never re-implements them.**

A developer runs `task test` (or `just test`, `make test`, `pnpm test`) locally,
and CI runs the *identical* command. This one rule is what kills "works on my
machine / fails in CI" drift and keeps the whole system honest. Almost every
other standard below exists to protect or extend it.

## The standard at a glance (3 pillars, 15 principles)

Treat these as the audit criteria and the design targets. Depth, rationale, and
"what good vs. bad looks like" for each is in **`references/standards.md`** — read
it before designing or judging a pipeline.

**Pillar A — The task runner is the source of truth**
- **A1. One task per job, defined once.** Every real operation (format, lint,
  test, build, codegen, release) is a named task. Exactly one definition of "how".
- **A2. CI calls tasks, never re-implements them.** CI steps are `run: task <x>`.
  No build/test/lint logic lives in YAML. Local and CI run the same thing.
- **A3. Modular task files with one aggregate entrypoint.** Split by concern,
  include into a root file, expose a `default`/`all` that runs the full pipeline.
- **A4. Tasks are idempotent and incremental.** Fingerprint inputs→outputs so
  re-runs are cheap and skip when nothing changed; serialize unsafe steps.
- **A5. Matrices are generated from the task runner, not hand-written in CI.**
  A task emits the list of lint runners / build targets as JSON; CI consumes it.

**Pillar B — CI is least-privilege, pinned, and reproducible**
- **B6. Deny-by-default permissions.** `permissions: {}` at top; each job grants
  only the exact scopes it needs. Enforced by a policy linter.
- **B7. Pin everything to immutable refs.** Actions → full commit SHA + version
  comment; tools → exact versions; deps → lockfile. A bot keeps pins fresh.
- **B8. Hermetic, declarative toolchain.** Install CLI tools via a version
  manager (not `apt`/`curl | sh`); pin the compiler/runtime. Same versions
  locally and in CI.
- **B9. Every job is bounded and cancelable.** `timeout-minutes` on every job;
  `concurrency` groups cancel superseded PR runs but never cancel the trunk.
- **B10. One aggregated required status check.** A final job that `needs` all
  others and fails if any failed/cancelled — the single check branch protection
  requires.
- **B11. Reusable workflows.** Factor pipelines into callable workflows; the
  top-level workflow just orchestrates and passes least privilege per call.

**Pillar C — Gates & supply chain**
- **C12. Format / lint / generated-file drift are hard gates.** Run the
  formatter then fail on any diff; lint the whole tree and fail on any finding;
  regenerate generated artifacts and fail on drift (optionally auto-commit).
- **C13. Credential & checkout hygiene.** `persist-credentials: false`, fetch
  only what's needed, keep secrets out of untrusted PR execution.
- **C14. Cache: restore-always, save-on-trunk-only.** Keyed by lockfile hashes;
  PRs restore but don't write caches (prevents poisoning); only trunk saves.
- **C15. Releases are verifiable.** Checksums generated *and* verified; artifacts
  signed (keyless/OIDC) and attested (build provenance); release only on tags.

## Proportionality — apply the principle, size the mechanism

These are principles, not a fixed checklist to stamp on every repo. Match the
*mechanism* to the repo's actual surface area:

- A **pure library** (no shipped binary) keeps A1–A5, B6–B11, C12–C14, but skips
  the build matrix and signing/attestation of C15 — there's nothing to sign.
- A **single-target app** needs C15 but not a cross-compilation matrix.
- A **tiny script repo** may collapse the task runner to a handful of tasks and a
  single CI workflow — but still pins actions, sets permissions, and gates lint.

When in doubt, keep the security and source-of-truth principles (A1–A2, B6–B9,
C12–C13) — they cost little and pay off everywhere — and scale build/release
machinery to what actually ships. Explain the trade-off rather than over-building.

## How to use this skill

First **orient**: identify the stack (build/lint/test commands), the CI provider,
whether a task runner and a tool manager already exist, and what the repo
actually ships (library / app / one or more binaries / container). Then pick the
mode.

### Mode: VERIFY / AUDIT ("is my CI any good?", "audit my workflows")
1. Read **`references/standards.md`** for the depth behind each principle, then
   walk every item in **`references/verification-checklist.md`**.
2. For each principle record **PASS / WARN / FAIL / N/A** with concrete evidence
   (`file:line`) and a one-line concrete fix. Check, don't guess — open the
   workflow files, the task runner, the tool-manager config. Some criteria (branch
   protection, which checks are *required* to merge) live in repo settings, not
   files; grade those "can't verify from files — confirm in repo settings" instead
   of assuming.
3. Produce the audit report using the template in the checklist file. Within it,
   the FAIL list is ordered by **severity** (blast radius); the separate "order of
   work" is the recommended **fix sequence** — they are different orderings on
   purpose.
4. Change nothing unless the user asks; end by offering to apply the top fixes.

### Mode: CREATE ("set up CI", "scaffold a Taskfile", "add a pipeline")
1. Map the stack to concrete tools with **`references/technology-map.md`**
   (task runner, tool manager, action-pinner, policy linter, dep bot, per-language
   format/lint/test/build commands). Prefer tools already present in the repo.
2. Scaffold the **task runner** first (split by concern; A1–A5) from the skeletons
   in **`references/templates.md`**. Make `format`, `lint`, `test`, `build` real
   tasks; add `codegen`/`release` if the repo needs them.
3. Wire the **declarative toolchain + pins** (B7–B8).
4. Scaffold **CI** (reusable workflows + orchestrator + aggregated gate;
   least-privilege, pinned, timed, cached) from the same templates.
5. Add supporting config (editorconfig, formatter configs, dep-bot config; C12).
6. **Prove it**: run the tasks locally (`task format && task lint && task test &&
   task build`), and confirm the format gate is clean (`git diff --exit-code`
   after `task format`). Report what you ran and its result honestly.

### Mode: UPDATE / REFACTOR ("harden this", "make CI follow best practices")
1. **Audit first** (VERIFY mode) so changes are evidence-driven.
2. Apply fixes in priority order, smallest reviewable steps first:
   **(i) Security** — set `permissions`, pin actions to SHAs, add
   `persist-credentials: false`, add timeouts.
   **(ii) De-drift** — move any real logic out of CI `run:` blocks into tasks;
   make CI call the tasks (A2). This is usually the highest-value change.
   **(iii) Gates** — add the aggregated status check, format/lint/drift gates.
   **(iv) Perf/robustness** — caching discipline, concurrency, matrix-from-tasks.
3. Preserve the repo's existing conventions and tool choices; don't swap a
   working task runner for your favorite. Re-run the audit to confirm movement.

## Golden rules (do not violate without a stated reason)

- **No real work in CI YAML.** If a `run:` block does multi-step build/test/lint
  logic, stop and make it a task, then call the task. CI orchestrates; tasks work.
- **`permissions:` is always explicit and minimal.** Never rely on the default
  token scope. Start from `{}` and add per job.
- **Never a mutable action ref.** No `@v4` / `@main`. Always a full commit SHA
  with a trailing `# vX.Y.Z` comment, updated by a bot.
- **Every job has `timeout-minutes`.**
- **Exactly one aggregated required status check** gates merges.
- **Drift fails CI** — formatting, linting, and generated files.
- **Pins are bumped by a bot** (Renovate/Dependabot), not by hand.

## Reference files

Read the one that fits the moment; each is self-contained (snippets embedded, no
dependency on this repo's paths so the skill is portable):

- **`references/standards.md`** — the 15 principles in depth: rationale, "good vs.
  bad", and the concrete patterns (fingerprinting, matrix-from-tasks, the
  un-droppable lint gate, cache poisoning, keyless signing). Read before
  designing or auditing.
- **`references/verification-checklist.md`** — the auditable checklist and the
  audit-report template. Read in VERIFY/UPDATE mode.
- **`references/technology-map.md`** — abstract principle → concrete tool, per
  ecosystem, plus per-language command cheatsheets. Read in CREATE mode.
- **`references/templates.md`** — copy-paste skeletons: split task runner,
  reusable + orchestrator workflows, aggregated gate, tool-manager and dep-bot
  config, release/signing job. Read in CREATE/UPDATE mode.

> If you happen to be running inside the **rsdebstrap** repository itself, its
> live `Taskfile.yml` + `tasks/*.task.yml` and `.github/workflows/*.yml` are the
> canonical worked example of every principle here — read them as the reference
> implementation.
