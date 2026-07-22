# Templates — copy-paste skeletons

Annotated skeletons for CREATE/UPDATE mode. They encode the principles; adapt the
commands to the stack (`technology-map.md`) and delete what doesn't apply
(Proportionality — SKILL.md). Placeholders look like `<this>`. Keep the *shape* even
when you change the tools.

---

## 1. Task runner — split by concern (Taskfile)

Root `Taskfile.yml` — orchestrator + full-pipeline entrypoint (A3):

```yaml
---
# yaml-language-server: $schema=https://taskfile.dev/schema.json
version: '3'
includes:
  tool: ./tasks/tool.task.yml
  format: ./tasks/format.task.yml
  lint: ./tasks/lint.task.yml
  test: ./tasks/test.task.yml
  build: ./tasks/build.task.yml
  release: ./tasks/release.task.yml
tasks:
  default:
    desc: Run the full local pipeline (identical to CI)
    aliases: [all]
    cmds:
      - task: tool
      - task: format
      - task: lint
      - task: test
      - task: build
```

A concern file with **incremental** behavior (A4) — `sources`→`generates`, sentinel for
tasks with no file output:

```yaml
---
version: '3'
tasks:
  default: {cmds: [{task: check}]}
  check:                       # `format` normally, or lint/test/build
    desc: <what it does>
    sources: ['**/*.<ext>', 'exclude: .git/**', 'exclude: <build-dir>/**']
    generates: ['.task/.done_{{.TASK}}']   # sentinel when there's no real output file
    cmds:
      - <format/lint/test/build command>
      - {cmd: 'touch .task/.done_{{.TASK}}', silent: true}
```

**Non-mutating status guard** (A4) — skip install when already present, without
side effects:

```yaml
  setup-toolchain:
    run: once                  # several tasks depend on this; don't race the installer
    status: ['command -v <tool> >/dev/null']   # read-only check, no install side effect
    cmds: ['<install pinned toolchain>']
```

**The un-droppable lint gate** (C12) — base flags the task always applies; CI may only
append:

```yaml
vars:
  LINT_ARGS: ['--fail-level any', '--whole-tree']   # the gate — never overridden
tasks:
  lint:
    cmds:
      - '<linter> {{.LINT_ARGS | join " "}} {{env "EXTRA_LINT_ARGS"}}'  # CI adds logging only
```

**Matrix from tasks** (A5) — emit JSON for CI to consume:

```yaml
  matrix:
    desc: Print the build/lint matrix as JSON for CI
    cmds: ['<enumerate targets> | jq -cM "<shape into {include:[...]}>"']
```

> **make / just / npm equivalents.** The shape is identical: a `default`/`all` target
> chaining `format lint test build`; per-concern targets; `make`'s prerequisite files give
> A4 incrementality natively; npm uses `"scripts"` with `pre*`/`post*` hooks. Keep the
> names and the gate behavior constant across whichever you pick.

---

## 2. CI — orchestrator + aggregated gate (GitHub Actions)

`.github/workflows/ci.yml` — thin orchestrator (A2, B6, B10, B11):

```yaml
---
name: CI
on:
  push: {branches: [main], tags: ['v*']}
  pull_request:
permissions: {}                              # deny by default (B6)
jobs:
  format:  {name: Format,  if: "${{ !startsWith(github.ref, 'refs/tags/') }}", permissions: {contents: read}, uses: ./.github/workflows/wc-format.yml}
  lint:    {name: Lint,    if: "${{ !startsWith(github.ref, 'refs/tags/') }}", permissions: {contents: read, checks: write, pull-requests: write}, uses: ./.github/workflows/wc-lint.yml}
  test:    {name: Test,    if: "${{ !startsWith(github.ref, 'refs/tags/') }}", permissions: {contents: read}, uses: ./.github/workflows/wc-test.yml}
  build:   {name: Build,   permissions: {contents: read, id-token: write, attestations: write}, uses: ./.github/workflows/wc-build.yml}
  release: {name: Release, needs: [build], permissions: {contents: write}, uses: ./.github/workflows/wc-release.yml}

  ci:                                        # single required status check (B10)
    needs: [format, lint, test, build, release]
    name: CI
    runs-on: ubuntu-latest
    timeout-minutes: 3
    if: ${{ failure() || cancelled() }}      # no-op unless something broke
    steps: [{name: Failure Status, run: exit 1}]
```

A reusable workflow `.github/workflows/wc-<name>.yml` (B11, B9, C13) — self-contained,
calls a task (A2):

```yaml
---
name: <Name>
on: {workflow_call: {}}
permissions: {}
concurrency:                                 # cancel superseded PR runs, never trunk (B9)
  group: <name>-${{ github.ref }}
  cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}
jobs:
  <name>:
    name: <Name>
    runs-on: ubuntu-latest
    timeout-minutes: 5                       # every job is bounded (B9)
    permissions: {contents: read}
    steps:
      - name: Checkout
        uses: actions/checkout@<full-sha> # v4.x
        with: {persist-credentials: false}   # credential hygiene (C13)
      - name: Setup tools
        uses: <tool-manager-install-action>@<full-sha> # vX   # pinned (B7,B8)
      - name: <Name>
        run: task <name>                     # CI calls the task (A2)
```

**Format-drift gate** (C12) — the whole reason the formatter has teeth:

```yaml
      - name: Format
        run: task format
      - name: Fail on drift
        run: |
          git add --all
          git diff --name-only --staged --exit-code   # non-zero if format changed files
```

**Caching — restore-always / save-on-trunk-only** (C14):

```yaml
      - name: Restore cache
        id: cache
        uses: actions/cache/restore@<full-sha> # vX
        with: {key: 'deps-${{ hashFiles("**/<lockfile>") }}', restore-keys: 'deps-', path: <cache-path>}
      # ... work ...
      - name: Save cache
        if: github.ref == 'refs/heads/main' && steps.cache.outputs.cache-hit != 'true'
        uses: actions/cache/save@<full-sha> # vX
        with: {key: '${{ steps.cache.outputs.cache-primary-key }}', path: <cache-path>}
```

**Matrix consumer** (A5) — pairs with the `matrix` task above:

```yaml
jobs:
  matrix:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions: {contents: read}
    outputs: {targets: "${{ steps.m.outputs.result }}"}
    steps:
      - {uses: actions/checkout@<full-sha>, with: {persist-credentials: false}}
      - {uses: <tool-manager-install-action>@<full-sha>}
      - {id: m, run: 'echo "result=$(task <name>:matrix)" >> "$GITHUB_OUTPUT"'}
  run:
    needs: matrix
    strategy: {fail-fast: false, matrix: "${{ fromJson(needs.matrix.outputs.targets) }}"}
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions: {contents: read}
    steps: [ ..., {run: 'task ${{ matrix.target }}'}]
```

---

## 3. Release with verification (C15) — only if the repo ships artifacts

```yaml
      - name: Checksum
        run: sha256sum "<artifact>" > "<artifact>.sha256sum"
      - name: Verify checksum            # generate AND verify, same run
        run: sha256sum -c "<artifact>.sha256sum"
      - name: Sign (keyless / OIDC)
        run: cosign sign-blob -y "<artifact>" --output-signature "<artifact>.sig" --output-certificate "<artifact>.cert"
      - name: Attest provenance
        uses: actions/attest-build-provenance@<full-sha> # vX
        with: {subject-path: "<artifact>"}
      - name: Publish
        if: startsWith(github.ref, 'refs/tags/')   # tag-gated
        run: <create release with artifacts + SHA256SUMS>
```
(Needs `permissions: {id-token: write, attestations: write, contents: write}` on the job.)

---

## 4. Supporting config

**Tool manager (B8)** — aqua example (`.aqua/aqua.yaml` + pinned pkgs); mise equivalent is
`.mise.toml` with `[tools]` pinned to exact versions:
```yaml
# aqua.yaml
registries: [{type: standard, ref: <pinned>}]
packages:
  - name: <owner>/<tool>@<exact-version>   # e.g. reviewdog/reviewdog@v0.21.0
```
```toml
# .mise.toml
[tools]
node = "20.11.1"
shellcheck = "0.10.0"
```

**Dependency bot (B7)** — Renovate keeping actions, tools, and deps current:
```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:best-practices", "helpers:pinGitHubActionDigests"],
  "automerge": true
}
```
(Dependabot equivalent: `.github/dependabot.yml` with `package-ecosystem: github-actions`
plus the language ecosystem.)

**Editor/format baseline (C12)** — `.editorconfig` so formatters and reviewers agree:
```ini
root = true
[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
```
Keep language formatter configs (`.rustfmt.toml`, `.prettierrc`, `ruff.toml`, …) *in sync*
with `.editorconfig`, and let the format gate enforce all of it.

**Action pinning (B7)** — wire `pinact run` into the `format` task (or a pre-commit hook)
so every newly added action is converted to a SHA automatically, and let the dep bot bump
the SHAs over time.

---

## Assembly order (CREATE mode)

1. Runtime/tool pins + tool-manager config (B7, B8) — nothing else is reproducible without
   this.
2. Task runner: `format`, `lint`, `test`, `build` as real tasks + the `default` aggregate
   (A1–A4). Verify each runs locally.
3. Reusable workflows that *call the tasks* (A2, B11) + the orchestrator + the aggregated
   `ci` gate (B10), all pinned/permissioned/timed (B6, B7, B9).
4. Gates: format/lint/generated-file drift (C12); caching discipline (C14).
5. Dep bot + action pinner (B7); editor/format configs (C12).
6. Release/signing only if artifacts ship (C15).
7. Prove it: run the full pipeline locally, confirm the format gate is clean, and report
   honestly what passed and what didn't.
