# Technology map — principle → concrete tool

The standards are abstract on purpose. This file maps them to real tools so you can
implement them in any ecosystem. **Prefer tools already in the repo**; only introduce a
new one when a principle is otherwise unmet. Everything below is a menu, not a mandate.

## Choosing the moving parts

| Role (principle) | Options (pick one, repo-appropriate) |
|---|---|
| **Task runner** (A1–A5) | [Task](https://taskfile.dev) (Taskfile.yml) · [just](https://just.systems) · GNU **make** · package.json **scripts** (Node) · **cargo-make** / cargo xtask (Rust) · **mise** tasks · **poe**/nox/tox/invoke (Python) · **mage**/Makefile (Go) |
| **Tool/version manager** (B8) | [aqua](https://aquaproj.github.io) · [mise](https://mise.jdx.dev) · asdf · proto · Nix/devbox · a pinned devcontainer image |
| **Runtime/compiler pin** (B8) | `rust-toolchain.toml` · `.nvmrc`/`.node-version`/Volta · `.python-version`/uv · `go` directive in `go.mod` · `.tool-versions` (asdf/mise) |
| **Action pinner** (B7) | [pinact](https://github.com/suzuki-shunsuke/pinact) · [ratchet](https://github.com/sethvargo/ratchet) · Dependabot (pins on update) |
| **Workflow policy linter** (B6, C13) | [ghalint](https://github.com/suzuki-shunsuke/ghalint) · [zizmor](https://github.com/woodruffw/zizmor) · [actionlint](https://github.com/rhysd/actionlint) (syntax/shell) · octoscan |
| **Lint aggregation / PR annotations** (C12) | [reviewdog](https://github.com/reviewdog/reviewdog) (unifies many linters, posts as checks/PR comments) · native problem matchers · SARIF upload |
| **Dependency bot** (B7, cross-cutting) | [Renovate](https://docs.renovatebot.com) (most flexible; automerge, tool-manager-aware) · Dependabot |
| **Auto-fix bot** (C12 upgrade) | [autofix.ci](https://autofix.ci) · pre-commit.ci · a `format`+commit job |
| **Signing** (C15) | [cosign](https://github.com/sigstore/cosign) keyless (OIDC) · minisign |
| **Attestation/provenance** (C15) | `actions/attest-build-provenance` · SLSA generators |
| **Compiler cache** (C14) | sccache (Rust/C/C++) · ccache · language build caches (Gradle, Turborepo, Nx) |

## The generic pipeline shape (any stack)

Every repo, regardless of language, wants these tasks. The commands differ; the *names*
and the *gate behavior* stay constant so CI and contributors learn one vocabulary.

| Task | Purpose | Gate (C12) |
|---|---|---|
| `tool` / `setup` | install pinned tools & toolchain (B8) | — |
| `format` | auto-format everything, in place | `git diff --exit-code` after |
| `lint` | static analysis, whole-tree | fail on any finding |
| `test` | unit/integration tests | non-zero on failure |
| `build` | produce the artifact(s) | non-zero on failure |
| `codegen` *(if any)* | regenerate schemas/clients/matrices | regenerate + diff |
| `release` *(if it ships)* | package, checksum, sign, attest (C15) | tag-gated |

## Per-language command cheat-sheet

Fill the generic tasks with these. Always prefer the **locked/frozen/offline** variant so
CI is reproducible (B7).

**Rust (cargo)**
- format: `cargo fmt --all` · lint: `cargo clippy --all-targets --all-features -- -D warnings`
- test: `cargo test --workspace --locked` · build: `cargo build --release --locked --frozen`
- pins: `rust-toolchain.toml`, `Cargo.lock` (commit it). offline: `cargo fetch --locked`.

**Node / TypeScript**
- format: `prettier --write .` (or Biome) · lint: `eslint .` (or `biome lint`)
- test: `vitest run` / `jest --ci` · build: `tsc -b` / `vite build` / framework build
- pins: `.nvmrc`/`packageManager` field, committed lockfile (`pnpm-lock.yaml`/`package-lock.json`).
  install: `pnpm install --frozen-lockfile` / `npm ci`.

**Python**
- format: `ruff format .` (or black) · lint: `ruff check .` (+ `mypy`/`pyright` for types)
- test: `pytest` · build: `python -m build` / `uv build`
- pins: `.python-version`, `uv.lock`/`poetry.lock`/`requirements.txt` (hashes). install: `uv sync --frozen`.

**Go**
- format: `gofmt -w .` / `goimports` · lint: `golangci-lint run`
- test: `go test ./... -race` · build: `go build ./...`
- pins: `go` directive in `go.mod`, `go.sum`. reproducible: `go build -trimpath`; `GOFLAGS=-mod=readonly`.

**Shell**
- format: `shfmt -w .` · lint: `shellcheck` (via reviewdog for annotations)

**YAML / GitHub Actions**
- format: `yamlfmt` · lint: `actionlint` (syntax+shell), `ghalint`/`zizmor` (policy), `pinact` (pins)

**TOML** — `taplo format` / `taplo lint`.  **Markdown** — `markdownlint`/`prettier`.
**Docker** — lint `hadolint`; build `docker build`; scan `trivy`/`grype`.
**Container images (C15)** — sign with cosign, attest with provenance, push by digest.

## CI provider mapping (the principles are portable)

The reference uses GitHub Actions, but the pillars translate:

| Principle | GitHub Actions | GitLab CI | Others |
|---|---|---|---|
| Call tasks (A2) | `run: task x` | `script: [task x]` | same everywhere |
| Least privilege (B6) | `permissions:` per job | protected/masked vars, no broad tokens | scope per platform |
| Pin refs (B7) | action SHAs | pinned image digests, includes by SHA | pin images/orbs by digest |
| Reusable (B11) | `workflow_call` | `include:` + `extends`/hidden jobs | templates/anchors |
| Aggregate gate (B10) | `needs:` + `failure()` | `needs:` + a final gate job | required pipeline status |
| Concurrency (B9) | `concurrency:` | `interruptible: true` + resource groups | provider setting |
| Matrix from tasks (A5) | `fromJson(task matrix)` | `parallel: matrix` fed by a job | generate then consume |

When a provider lacks a feature, keep the *principle* (e.g. emulate the aggregate gate with
a final "all-green" job) and note the gap rather than dropping the standard.
