# The Standards, in depth

Each principle below has the **why**, what **good** and **bad** look like, and (where
relevant) the concrete pattern that makes it real. The examples use Taskfile/GitHub
Actions/aqua because that is the reference implementation, but every principle is
tool-agnostic — see `technology-map.md` for the equivalents.

## Table of contents

- Pillar A — Task runner is the source of truth (A1–A5)
- Pillar B — CI is least-privilege, pinned, reproducible (B6–B11)
- Pillar C — Gates & supply chain (C12–C15)

---

## Pillar A — The task runner is the single source of truth

### A1. One task per job, defined once

**Why.** If "how to run the tests" exists in three places (a README, a CI YAML step,
and someone's shell history), they drift, and two of them are wrong. Naming each
operation once, in the task runner, gives the whole team and every machine a single
referent.

**Good.** `task test`, `task lint`, `task build`, `task fmt` each resolve to one
definition. Contributors discover them with `task --list`.

**Bad.** Test flags copy-pasted into a CI step and subtly different from local;
"the real build command" living only in a maintainer's memory.

### A2. CI calls tasks, never re-implements them

**Why.** This is the keystone. When CI runs the *same command* a developer runs, a
green local run predicts a green CI run, and a CI failure reproduces locally in one
command. The moment CI grows its own build logic, that guarantee is gone.

**Good.**
```yaml
- name: Test
  run: task test
- name: Build
  run: task build
```
CI is a wiring diagram: check out, install tools, call tasks, upload artifacts.

**Bad.** A CI step with fifteen lines of `cargo build ... && cp ... && tar ...` that
appears nowhere in the task runner. **This is the single most common and most costly
violation.** The fix is mechanical: move the block into a task, replace the step with
`run: task <name>`.

**Litmus test.** Could a new contributor reproduce a CI failure by running one
`task ...` command locally? If not, logic has leaked into CI.

### A3. Modular task files with one aggregate entrypoint

**Why.** A single 800-line task file is as unnavigable as a single 800-line function.
Splitting by concern (`format`, `test`, `build`, `lint`, `release`, `tool`) keeps each
file legible and lets CI include just what a job needs.

**Good.** A root file that `includes` per-concern files and defines a `default`/`all`
task chaining the full pipeline in dependency order:
```yaml
tasks:
  default:
    aliases: [all]
    cmds: [{task: tool}, {task: format}, {task: lint}, {task: test}, {task: build}]
```
Namespacing (`test:unit`, `build:release`) and internal-only helper tasks keep the
public surface clean.

**Bad.** Everything in one file; no top-level "run the whole pipeline" task, so
"did I run everything CI runs?" has no one-command answer.

### A4. Tasks are idempotent and incremental

**Why.** Re-running the pipeline should be cheap, or people stop running it locally
and let CI be their compiler. Fingerprinting (declare a task's input files and its
outputs) lets the runner skip work when nothing changed.

**Patterns worth stealing:**
- **Sources → generates.** Declare input globs and output paths; the runner skips the
  task when inputs are unchanged. For tasks with no natural file output, `touch` a
  sentinel (`.task/.done_<task>`) as the `generates` target.
- **Status guards that don't mutate.** To decide "is the toolchain already installed?"
  inspect state directly (`ls ~/.rustup/toolchains`, check a binary on `PATH`) rather
  than invoking a tool that would *install as a side effect*. Checks must be read-only.
- **Serialize unsafe steps.** A step several tasks depend on and that is not
  concurrency-safe (e.g. a toolchain installer) should run **once** per invocation, not
  race itself. Task's `run: once` / a lock / a sentinel all express this.

**Bad.** Every invocation rebuilds the world; contributors avoid the task runner
because it's slow, and local/CI drift creeps back in (A2 erodes).

### A5. Matrices are generated from the task runner, not hand-written in CI

**Why.** A build/lint matrix hand-maintained in YAML drifts from reality: someone adds
a lint task and forgets to add it to the CI matrix, so it never runs in CI. If the task
runner *emits* the matrix, adding a task automatically extends CI.

**Pattern.** A task prints the matrix as JSON; CI reads it into its native matrix:
```yaml
# task side: enumerate lint runners / build targets → compact JSON
matrix:
  cmds: ['task --list-all --json | jq -cM -f scripts/lint-matrix.jq']
```
```yaml
# CI side
jobs:
  matrix:
    outputs: {targets: "${{ steps.m.outputs.result }}"}
    steps: [{id: m, run: 'echo "result=$(task lint:matrix)" >> "$GITHUB_OUTPUT"'}]
  lint:
    needs: matrix
    strategy: {matrix: "${{ fromJson(needs.matrix.outputs.targets) }}", fail-fast: false}
    steps: [{run: 'task ${{ matrix.target }}'}]
```
The list of things to run lives with the definitions of those things — one source of
truth (A1) extended to CI fan-out.

---

## Pillar B — CI is least-privilege, pinned, and reproducible

### B6. Deny-by-default permissions

**Why.** The CI token is a credential to your repo. A compromised action or a malicious
PR runs with whatever scopes you grant. The default token is often far broader than any
job needs; an over-scoped token turns a small supply-chain slip into a repo takeover.

**Good.** Deny everything at the top, grant the minimum per job:
```yaml
permissions: {}          # top of every workflow
jobs:
  test:
    permissions: {contents: read}
  release:
    permissions: {contents: write}      # only this job can write
  build:
    permissions: {contents: read, id-token: write, attestations: write}
```
Enforce it with a policy linter (ghalint, zizmor) so a missing/too-broad `permissions`
block fails CI — humans forget, linters don't.

**Bad.** No `permissions:` block anywhere (inherits broad defaults); or a single broad
grant at workflow level shared by every job.

### B7. Pin everything to immutable refs

**Why.** `uses: some/action@v4` resolves to whatever the tag points at *today*. Tags are
mutable — an attacker (or a bad release) who moves `v4` runs their code in your pipeline
with your token. A full commit SHA is immutable. The same logic applies to CLI tools and
dependencies: unpinned means "whatever happened to be latest when this ran", which is
neither reproducible nor safe.

**Good.**
```yaml
uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```
The comment keeps it human-readable and lets the bot bump it. Tools pinned to exact
versions in the tool-manager config; dependencies committed as a lockfile.

**Bad.** `@v4`, `@main`, `@latest`; `npm install -g some-cli` (unversioned);
`.gitignore`-d lockfile.

**Automate it.** A pinning tool (pinact, ratchet) converts tags→SHAs and is run as part
of `task format`/a pre-commit so new actions are pinned automatically; a bot (Renovate,
Dependabot) proposes the bumps (B7 + C-automation).

### B8. Hermetic, declarative toolchain

**Why.** `apt-get install` and `curl | sh` give a different tool version on every runner
image and every developer laptop — the opposite of reproducible, and unpinned (B7). A
declarative version manager installs *exact, pinned* tool versions the same way
everywhere, and the pinned set is the same locally and in CI.

**Good.** All CLI tools (formatters, linters, the build helper, jq, etc.) declared with
pinned versions in a tool-manager config (aqua, mise, asdf, proto). The compiler/runtime
pinned in its idiomatic file (`rust-toolchain.toml`, `.nvmrc`, `.python-version`,
`go.mod`'s `go` directive). CI installs tools by calling the tool manager — often via a
task, so "install my tools" is also a single command.

**Nice touch — install only what a job needs.** Tag tools by purpose so a lint job
installs just the lint tools, not the whole build toolchain (faster, smaller blast
radius).

**Bad.** `run: sudo apt-get install -y shellcheck` (unpinned, slow, drifts);
tool versions differing between a contributor's machine and CI.

### B9. Every job is bounded and cancelable

**Why.** A hung job holds a runner until it times out at the platform maximum (often
hours), wasting minutes and blocking the queue. Superseded PR runs (you pushed again)
waste compute finishing work nobody wants. Both are cheap to prevent.

**Good.**
```yaml
timeout-minutes: 5            # on every job, sized to the job
concurrency:
  group: test-${{ github.ref }}
  cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}
```
Note the asymmetry: **cancel superseded runs on PR branches, never on the trunk** — a
main-branch run may be publishing artifacts or a release you don't want half-done.

**Bad.** No timeouts (hangs cost the platform maximum); `cancel-in-progress: true`
unconditionally (can abort a release mid-flight on main).

### B10. One aggregated required status check

**Why.** Branch protection lets you require checks by name. If you require each job
individually, adding a job means editing branch protection, and a *skipped* job can
count as "passed". A single aggregate job that depends on all others gives you one stable
check to require, and it goes red if anything failed or was cancelled.

**Good.**
```yaml
ci:
  needs: [format, lint, test, build, release]
  if: ${{ failure() || cancelled() }}   # runs only when something went wrong
  runs-on: ubuntu-latest
  timeout-minutes: 3
  steps: [{name: Failure, run: exit 1}]
```
Require just `ci` in branch protection. (The `if:` means the job normally no-ops and only
exists to fail the aggregate when a dependency failed/was cancelled.)

**Bad.** A dozen individually-required checks that must be re-configured whenever the job
list changes; merges allowed because a silently-skipped job "passed".

### B11. Reusable workflows

**Why.** Copy-pasted job definitions across workflows drift and multiply maintenance. A
callable/reusable workflow is defined once and invoked with least privilege per call;
the top-level workflow becomes a readable orchestrator.

**Good.** A top-level `ci.yml` whose jobs are thin calls:
```yaml
jobs:
  format:  {uses: ./.github/workflows/wc-format.yml,  permissions: {contents: read}}
  test:    {uses: ./.github/workflows/wc-test.yml,    permissions: {contents: read}}
  build:   {uses: ./.github/workflows/wc-build.yml,   permissions: {contents: read, id-token: write, attestations: write}}
```
Each `wc-*.yml` is `on: workflow_call`, self-contained, and reusable. A naming
convention (`wc-` = "workflow call") makes the split obvious.

**Bad.** One monolithic workflow with every step inlined and permissions granted broadly
because splitting them per job is too tedious.

---

## Pillar C — Gates & supply chain

### C12. Format / lint / generated-file drift are hard gates

**Why.** "We have a formatter" means nothing if unformatted code still merges. The gate
is what gives the standard teeth. Three drift gates matter:

- **Format:** run the formatter, then fail if anything changed.
  ```yaml
  - run: task format
  - run: git diff --exit-code        # non-zero if format changed files
  ```
- **Lint:** lint the **whole tree** (not just changed lines) and **fail on any finding**.
  Changed-lines-only lets pre-existing issues rot and lets a PR dodge the linter by not
  touching the offending line.
- **Generated files** (schemas, matrices, generated code): regenerate in CI and fail on
  drift, so a committed generated file can never lie about its source.

**The un-droppable gate pattern.** Keep the gate flags (fail-on-finding, whole-tree) in
a base variable the task always applies, and let CI only *append* flags (extra logging),
never *replace* them. That way CI can add debug output but can never silently turn off
the gate.

**Optional upgrade — auto-fix instead of just failing.** A bot job (e.g. autofix.ci) runs
`task format` + regenerates files and commits the fix back to the PR, so trivial drift is
repaired, not just reported.

**Bad.** A `lint` task that prints warnings and exits 0; a committed generated file no CI
job ever re-derives.

### C13. Credential & checkout hygiene

**Why.** By default some checkout actions leave the auth token in `.git/config` on the
runner; any later step (or compromised dependency) can read it. PR-triggered workflows
that check out and *execute* untrusted head code must never hold write scopes or secrets.

**Good.** `persist-credentials: false` on checkout; fetch only what's needed
(sparse-checkout / shallow) to shrink the surface and speed up; keep privileged work in
`workflow_run`/trunk contexts, not in workflows that run untrusted PR code. `pull_request`
(not `pull_request_target`) for untrusted contributions.

**Bad.** Default credential persistence; `pull_request_target` that checks out and runs
PR head code with secrets in scope (a classic exfiltration hole).

### C14. Cache: restore-always, save-on-trunk-only

**Why.** Caching is a correctness hazard, not just a speed knob. If PR runs can *write*
shared caches, a malicious or buggy PR poisons the cache for everyone. The safe shape:
everyone **restores**, only the **trunk** branch **saves**.

**Good.**
```yaml
- uses: actions/cache/restore@<sha>            # every run restores
  with: {key: deps-${{ hashFiles('**/lockfile') }}, restore-keys: 'deps-'}
# ... build ...
- uses: actions/cache/save@<sha>               # only main writes
  if: github.ref == 'refs/heads/main' && steps.cache.outputs.cache-hit != 'true'
```
Key caches by lockfile hash so a dependency change invalidates cleanly; use `restore-keys`
prefixes for warm partial hits. A dedicated warm-up job on trunk can populate caches other
jobs restore. Compiler caches (sccache, ccache) follow the same rule and are disabled on
release/tag builds for clean, reproducible artifacts.

**Bad.** `actions/cache` (restore+save) on every event, so PRs poison the shared cache;
cache keys that never invalidate.

### C15. Releases are verifiable

**Why.** Consumers need to prove an artifact is the one you built and wasn't tampered with.
Checksums detect corruption; signatures prove origin; attestations tie the artifact to the
exact build. This is the payoff of everything above — a reproducible, pinned build is what
makes a signature meaningful.

**Good (scale to what ships):**
- **Checksums:** generate `sha256sum` per artifact and **verify them in the same run**
  (generation without verification catches nothing).
- **Signing:** keyless/OIDC signing (cosign sign-blob with `id-token: write`) — no
  long-lived keys to leak.
- **Provenance:** build-provenance attestation (SLSA / `actions/attest-build-provenance`)
  binding artifact → workflow → commit.
- **Tag-gated:** the actual publish/release step runs only on a tag
  (`if: startsWith(github.ref, 'refs/tags/')`); PRs and branch pushes build and verify but
  do not publish. Merge/verify all per-target checksums into one `SHA256SUMS` before
  release.

**Bad.** Uploading binaries with no checksum or signature; a release job that fires on
every push; checksums generated but never checked.

---

## How the principles reinforce each other

They are a system, not a checklist:

- **A2** (CI calls tasks) only reproduces locally because of **B8** (same pinned tools
  everywhere) and **B7** (pinned deps) — otherwise "same command" still runs different
  code.
- **A5** (matrix from tasks) keeps CI fan-out honest with **A1** (one definition).
- **C15** (verifiable releases) is only trustworthy because **B7/B8** made the build
  reproducible and **B6/C13** kept the pipeline from being hijacked.
- **C12** (drift gates) is what stops entropy from quietly eroding **A1** and **B7** over
  time.

When auditing, a failure in one pillar usually predicts failures in another — follow the
thread.
