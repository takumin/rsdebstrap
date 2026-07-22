# Verification checklist & audit report

Use this in **VERIFY** and **UPDATE** mode. Walk every item, **open the actual files**
(don't infer from the README), and record a verdict with evidence. The principle IDs
(A1…C15) map to `standards.md`.

## How to grade each item

- **PASS** — implemented as described.
- **WARN** — partially present, or present but weakened (e.g. a lint gate that exists but
  only checks changed lines).
- **FAIL** — absent or actively wrong (e.g. no `permissions:` anywhere).
- **N/A** — genuinely doesn't apply to this repo's surface (state *why*, per
  Proportionality in SKILL.md — e.g. "pure library, nothing to sign → C15 N/A").

Every non-PASS needs: the **evidence** (`file:line` or "no such file"), and a **one-line
fix**. Check, don't assume — a `lint` target existing is not proof it fails the build.

## Orientation (do this first)

- [ ] What does the repo **ship**? library / app / one-or-more binaries / container /
      docs-only. (Sets which C15 items are N/A.)
- [ ] What's the **stack** and its idiomatic format/lint/test/build commands?
- [ ] Is there a **task runner** already? (Taskfile, Makefile, justfile, package.json
      scripts, mise tasks, cargo-make…)
- [ ] Is there a **tool/version manager**? (aqua, mise, asdf, proto, nix, Dockerfile)
- [ ] What **CI provider** and which workflows/pipelines exist?
- [ ] Is there a **dependency bot** and an **action pinner**?

## Pillar A — Task runner is the source of truth

- [ ] **A1** Every real operation (format, lint, test, build, + codegen/release if
      applicable) is a **named task** with a single definition. *Check:* list the tasks;
      cross-reference against the operations the repo actually needs.
- [ ] **A2** CI steps **call tasks** (`run: task <x>` / `make <x>` / `pnpm <x>`) and
      contain **no real build/test/lint logic**. *Check:* scan every `run:` block — any
      multi-line block doing actual work that isn't in the task runner is a **FAIL**.
      *This is the highest-signal check in the whole audit.*
- [ ] **A3** Task files are **modular** with a **`default`/`all`** aggregate that runs the
      full pipeline. *Check:* is there one command that runs everything CI runs?
- [ ] **A4** Tasks are **incremental/idempotent** (input→output fingerprinting, non-mutating
      status guards, unsafe steps serialized). *Check:* does a second run no-op? do status
      checks avoid side effects?
- [ ] **A5** CI **matrices are generated from the task runner**, not hand-maintained in
      YAML. *Check:* is the list of targets/runners duplicated in a workflow, or emitted by
      a task?

## Pillar B — Least-privilege, pinned, reproducible

- [ ] **B6** `permissions: {}` at workflow top; **each job grants only what it needs**;
      enforced by a policy linter. *Check:* grep every workflow for `permissions:`; flag any
      workflow with none, or a broad top-level grant.
- [ ] **B7** **All** `uses:` are **full commit SHAs + version comment**; tools pinned to
      exact versions; deps have a committed lockfile. *Check:* grep for `@v` / `@main` /
      `@latest` in `uses:`; confirm lockfile is tracked.
- [ ] **B8** Toolchain is **declarative and hermetic** (version manager, not
      `apt`/`curl|sh`); compiler/runtime pinned. *Check:* look for `apt-get install` /
      `curl … | sh` in CI; look for a tool-manager config and a runtime-pin file.
- [ ] **B9** **Every job** has `timeout-minutes`; `concurrency` cancels superseded **PR**
      runs but **not** trunk. *Check:* every job block; the `cancel-in-progress` condition.
- [ ] **B10** A single **aggregated status check** job `needs` all others and fails on
      any failure/cancel. *Check:* is there one stable check to require in branch
      protection?
- [ ] **B11** Pipelines factored into **reusable/callable workflows**; top-level just
      orchestrates. *Check:* monolith vs. orchestrator + `workflow_call` files.

## Pillar C — Gates & supply chain

- [ ] **C12** **Format**, **lint**, and **generated-file** drift each **fail CI**. Lint is
      **whole-tree + fail-on-any-finding**, not changed-lines-only. *Check:* is there a
      `git diff --exit-code` after format? does lint exit non-zero on findings? are
      generated files regenerated and diffed?
- [ ] **C13** `persist-credentials: false` on checkout; minimal fetch; no secrets/write
      scope in workflows that execute untrusted PR code; `pull_request` not
      `pull_request_target` for untrusted input. *Check:* checkout options; trigger types.
- [ ] **C14** Caching is **restore-always / save-on-trunk-only**, keyed by lockfile hash.
      *Check:* is `save` gated to the trunk branch? can a PR write the shared cache?
- [ ] **C15** *(if it ships artifacts)* Checksums generated **and verified**; artifacts
      **signed** (keyless/OIDC) and **attested**; publish step **tag-gated**. *Check:* each
      sub-item; mark N/A with a reason if nothing ships.

## Cross-cutting

- [ ] A **dependency bot** (Renovate/Dependabot) keeps action SHAs, tools, and deps
      current — pins are bumped by automation, not by hand.
- [ ] **Local == CI:** the exact commands CI runs are runnable locally with one task each.
      (The real test of A2.)
- [ ] Formatter/editor config (`.editorconfig` + per-language formatter config) exists and
      the format gate enforces it.

---

## Audit report template

Produce this, **ordered worst-first** (FAILs, then WARNs, then a compact PASS list). Keep
fixes concrete and one line each. Do not modify files in VERIFY mode — end by offering to
apply the top fixes.

```markdown
# Task Runner & CI audit — <repo>

**Ships:** <library | app | binaries | container>   **Stack:** <lang/tooling>
**CI:** <provider>   **Task runner:** <tool | none>   **Tool manager:** <tool | none>

## Summary
<2–3 sentences: overall posture, the single highest-value fix, biggest risk.>
Score: A __/5   B __/6   C __/4(+N/A)

## FAIL (fix first)
- **[A2] CI re-implements the build.** `.github/workflows/ci.yml:41–63` runs a 20-line
  build inline; nothing equivalent in the task runner.
  → Move it into a `build` task; replace the steps with `run: task build`.
- **[B6] No permissions block.** `ci.yml` has no `permissions:` → inherits broad default.
  → Add `permissions: {}` at top; grant `contents: read` per job, `contents: write` only
  on release.
- **[B7] Mutable action refs.** `ci.yml:18` `actions/checkout@v4`.
  → Pin to SHA + `# v4.x`; add a pinner (pinact) to the format task and a dep bot.

## WARN
- **[C12] Lint doesn't gate.** `test` task prints clippy warnings but exits 0.
  → Make lint fail on any finding; add whole-tree mode.
- **[C14] PRs write the cache.** `ci.yml:70` saves cache on every event.
  → Gate `save` to `github.ref == 'refs/heads/main'`.

## PASS
A1, A3, B9 (timeouts present), C13 (persist-credentials false).

## N/A
- **C15 signing/attestation** — pure library, no shipped artifact. (Still add checksums if
  you cut GitHub releases.)

## Suggested order of work
1. Security: permissions, SHA-pin, persist-credentials, timeouts.  (low risk, high value)
2. De-drift: move build/test/lint logic into tasks; CI calls tasks.  (the keystone fix)
3. Gates: aggregated status check, format/lint/generated-file drift.
4. Perf/robustness: cache discipline, concurrency, matrix-from-tasks.
```

Order the work security → de-drift → gates → perf: security fixes are cheap and reduce
real risk immediately, de-drifting is the highest-leverage structural change, and
perf/robustness is refinement once the shape is right.
