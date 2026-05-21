# Roadmap

What's planned, what's shipped, and what's deliberately out of scope.

## Shipped

- **GitHub Actions cicd-goat coverage push (v1.3.0)** —
  Two new rules and one widened taint hop, plus five existing-rule
  widenings, close eleven ``greylag-ci/cicd-goat`` scenarios in one
  cycle (10 / 15 / 17 / 19 / 20 / 21 / 22 / 23 / 24 / 26 / 27).
  GHA-062 walks the workflow's containing repo for sibling IaC
  (``*trust-polic*.json`` whose ``StringLike :sub`` matches more
  than one repo, ``*.tf`` with a ``google_iam_workload_identity_
  pool_provider`` ``startsWith('<org>/')`` predicate). GHA-061
  fires when an App-token mint step
  (``actions/create-github-app-token`` and siblings) omits a
  ``permissions:`` filter on the token's scope. GHA-008 picks up a
  keyed-hex secret shape (40-char lowercase hex bound to a
  credential-named YAML key) for legacy-unprefixed vendor tokens.
  TAINT-002 widens to propagate through ``env: { LABELS: "${{ ... }}" }``
  shell-var indirection AND ``strategy.matrix.<axis>:
  ${{ fromJSON(needs.<job>.outputs.<name>) }}`` matrix-axis
  expansion (the GitHub Security Lab matrix-injection writeup
  shape). Five existing rules widened: GHA-016 trusted-installer
  (Codecov 2021), GHA-019 ArtiPACKED (.git-in-artifact upload),
  GHA-033 shell-trace + secret-env, GHA-049 github-actions[bot]
  identity assumption + ``git push``, GHA-057 third-party-webhook
  exfil POST. The CLI also gained a one-line stderr hint when
  ``--pipeline github`` is run alone in a repo that also ships
  ``package.json`` files (depth-bounded cwd walk, skips
  ``node_modules`` / build / vendor), since the npm provider
  catches dependency-confusion / lockfile-integrity issues the
  github pipeline can't see.
- **Auto-publish GitHub Release on tag push (v1.3.0)** —
  ``release.yml`` gained a ``publish-github-release`` job that
  extracts the matching ``## [X.Y.Z]`` section from
  ``CHANGELOG.md`` (literal awk field-equality match, not regex,
  since ``[X.Y.Z]`` brackets would be a character class) and runs
  ``gh release create $TAG --notes-file ... --verify-tag --latest``.
  The Marketplace tile for the bundled composite action follows
  the latest *published Release*, not the latest tag — v1.1.0 and
  v1.2.0 both shipped to PyPI on tag push without manually
  created Releases, which stranded the Marketplace tile on
  v1.0.5 for two cycles. The new job ``needs: [publish-pypi]`` so
  the Release only fires after the wheel is on PyPI, and is
  tag-push-gated so workflow re-runs against an existing tag
  don't race. Idempotent via ``gh release view ... || create``.
- v1.0.x — first production-stable release. Carries every v0.4 / v0.5
  / v0.6 item folded in from the pre-1.0 cycles
  (STRIDE threat model, MCP server, SCM provider, composite-action
  resolution, action-reputation pack, multi-scanner SARIF ingest,
  vulnerable-by-design `bench/`, taint engine spanning 8 rules
  across 5 providers, multi-provider scan mode, attestation content
  checks, GHA-04x PPE rules, extended obfuscated-exec catalog),
  plus the API-stability commitment on ``pipeline_check.__all__``.
  Mid-cycle: five-rule worm-mitigation pack (``DF-024``
  ignore-scripts, ``DF-025`` npmrc token in layer, ``GHA-048``
  workflow self-mutation, ``GHA-049`` cross-repo push, ``GHA-050``
  publish without OIDC) closing the legs of the Shai-Hulud /
  TanStack / axios npm-worm pattern that pure lockfile / SHA
  pinning is blind to.
- **npm + pypi dependency-supply-chain providers (v1.0.5)** —
  Two new hermetic providers for static manifest / lockfile
  analysis: ``--pipeline npm`` parses ``package.json`` +
  ``package-lock.json`` / ``npm-shrinkwrap.json`` (both schemas);
  ``--pipeline pypi`` parses ``requirements*.txt`` / ``*.in``.
  Fourteen rules total (NPM-001..007 + NPM-011, PYPI-001..006)
  covering floating version ranges, missing integrity hashes,
  non-registry sources, install-time lifecycle scripts in your
  own ``package.json``, mutable VCS refs, known-compromised
  package versions (curated registry seeded with event-stream /
  ua-parser-js / coa / rc / node-ipc on the npm side, ctx /
  requests-darwin-lite on the pypi side), ``.npmrc``
  ``ignore-scripts`` enforcement, ``package.json`` ``files``
  field listing secret-shaped paths, missing version / hash
  pins, HTTP indexes / ``--trusted-host``, and
  ``--extra-index-url`` dependency confusion. No network, no
  install, skips ``node_modules/``. Closes the gap between the
  existing CI-pattern rules (DF-024, GHA-044) and the dependency
  files themselves.
- **Maven dependency-supply-chain provider (v1.0.5)** —
  Third hermetic registry provider. ``--pipeline maven`` parses
  ``pom.xml`` and ``settings.xml`` with property substitution
  (``${log4j.version}``) resolved against ``<properties>`` before
  each rule fires. Seven rules (MVN-001..007) covering floating
  Maven version ranges (``[1.0,2.0)``, ``LATEST``, ``RELEASE``),
  mutable ``-SNAPSHOT`` dependencies, plaintext-HTTP repository
  URLs, dependencies omitting an explicit ``<version>`` (silently
  resolved by parent BOMs), lax ``<checksumPolicy>`` on non-Central
  repositories, known-compromised Maven Central versions (curated
  registry seeded with Log4Shell / Spring4Shell / Text4Shell), and
  ``<mirrorOf>*</mirrorOf>`` wildcard mirrors. Surfaces
  ``<dependencyManagement>`` entries separately from real
  consumption so version-management blocks don't fire consumption-
  side rules. Skips ``target/`` and ``.m2/``. Brings provider count
  to 22 and the Package-registries category to npm + PyPI + Maven.
- **SCM GitLab + Bitbucket platform parity (v1.0.1)** —
  ``--scm-platform gitlab`` and ``--scm-platform bitbucket`` ship
  a 7-rule universal subset against the GitLab and Bitbucket APIs.
  CODEOWNERS-file presence cross-check (SCM-017), PR-review
  bypass-allowance audit (SCM-018), and push-restriction
  allowlist audit (SCM-019) closed the remaining GitHub-side
  feature gaps in the same cycle.
- **Container image distribution (v1.0.1)** —
  ``ghcr.io/dmartinochoa/pipeline-check`` and
  ``docker.io/dmartinochoa/pipeline-check`` publish on every
  ``v*.*.*`` tag via ``.github/workflows/docker-publish.yml``,
  multi-arch (linux/amd64 + linux/arm64), with Docker Scout
  vuln-scan gating the promote-to-release-tag step and SLSA
  provenance + SBOM attestations bound to the digest.
  Quarantine-then-promote ensures a vulnerable image never escapes
  a throwaway tag. Together with the marketplace ``action.yml``,
  this covers every CI environment that can run a container.
  A standalone binary (shiv / PyInstaller) was the other half of
  the original "distribution beyond pip install" goal but was
  deferred: the container already serves the no-Python use case;
  a shiv ``.pyz`` still requires Python on the target so it adds
  little over ``pip install``; PyInstaller's interaction with
  boto3's dynamic service loading and pipeline-check's pkgutil-
  based plugin discovery is a known-fragile combination. Revisit
  if there's clear user demand for a no-Docker-no-Python path.
- **SLSA Build L3 provenance on the wheel (v1.0.4).** Every
  tagged release runs the ``slsa-framework/slsa-github-generator``
  reusable workflow inside GitHub's isolated builder, signing the
  sdist + wheel via Sigstore with a short-lived OIDC token. The
  in-toto provenance file (``pipeline-check.intoto.jsonl``) lands
  as a workflow-run artifact (the repo runs immutable releases, so
  the generator can't attach to the release directly). PyPI
  trusted publishing uses ``id-token: write`` with PEP 740
  ``attestations: true`` so the in-toto attestation rides
  alongside the wheel on the package index. README's "Verifying a
  release" section ships the ``slsa-verifier verify-artifact``
  recipe end-to-end (find the build run, download the wheel +
  provenance, verify source URI + tag, install). The scanner that
  flags missing provenance ships its own attested wheel.
- **LSP server (post-1.0.5)** — ``pipeline_check/lsp/`` is a
  ``pygls`` 2.x server runnable via ``python -m pipeline_check.lsp``,
  behind the ``pipeline-check[lsp]`` install extra so the base
  install stays slim. Editor diagnostics match
  ``pipeline_check --output json`` byte-for-byte modulo position
  translation. The TypeScript VS Code extension that consumes it
  lives in a separate repo (``pipeline-check-vscode``, mirroring
  the ``astral-sh/ruff`` + ``astral-sh/ruff-vscode`` split) and is
  tracked under Post-1.0 candidates.
- **Real-world GOAT corpus benchmark (post-1.0.5)** —
  `bench/goats/` ships a pinned-clone benchmark complementing
  the existing synthetic `bench/cases/` set. The runner
  (`bench/goat_runner.py`) shallow-clones each declared goat into
  a tmpdir, scans via the same CLI a user invokes (with automatic
  Jenkinsfile globbing for goats that ship multiple), and diffs
  findings against a committed `expected.txt` + `allowlist.txt` +
  `baseline.json` per goat. Initial corpus: ``cicd-goat`` (GHA +
  7 Jenkinsfiles, 9/9 recall), ``cfngoat`` (CloudFormation, 6/6
  recall), ``kubernetes-goat`` (27/27 recall across
  ``scenarios/``), ``terragoat`` (skipped pending direct-HCL
  parsing). 42 check IDs locked total, each entry hand-tied to a
  documented goat challenge or CIS benchmark control. CI workflow
  ``.github/workflows/goat-bench.yml`` runs nightly + on PRs that
  touch the rule pack; uploads a ``goat-bench-report`` artifact
  and posts a sticky PR comment. See ``docs/goat_bench.md``.
- v0.4.x / v0.5.x / v0.6.x — pre-1.0 milestone work folded into
  v1.0.x. See `CHANGELOG.md` for the per-version trail.
- v0.3.x — Kubernetes provider, docs site, attack chains engine,
  English variant enforcement, doc-claim drift guards, MANIFEST
  sdist filter, GitHub Actions workflow audit.
- v0.2.x — Cloud Build, Jenkins, Terraform, CloudFormation, JUnit
  and Markdown reporters, 13-standard mapping, autofix engine, HTML
  report interactivity.

## Post-1.0 candidates

Larger items proposed after v1.1.0. Not yet scoped to a specific
release; landing order is open.

### Self-hosted findings-history dashboard

Tiny FastAPI + static-HTML app that reads a local
``.pipeline-check-history/`` directory of past scan JSON outputs and
renders trend graphs, per-rule burn-down, and resource-level heatmap
progression. Stays no-SaaS / no-telemetry but gives teams the
visibility they currently leave the scanner to get from a SaaS
competitor. No DB; just a directory of timestamped JSON files the
user already produces from CI.

### Org-wide fleet scanning (``pipeline_check fleet``)

One command, N repos, one rolled-up posture digest. ``pipeline_check
fleet --repos repos.yml`` reads a list of repo coordinates
(``owner/name`` for GitHub, ``group/subgroup/project`` for GitLab,
``workspace/repo_slug`` for Bitbucket), shallow-clones each into a
per-repo tmpdir, runs the auto-detect scan against it, and emits a
unified digest covering every repo in one place.
``--from-org dmartinochoa`` skips the YAML and pulls the repo list
from the SCM provider's REST API (``$GITHUB_TOKEN`` /
``$GITLAB_TOKEN`` / ``$BITBUCKET_TOKEN`` per platform).
``--include`` / ``--exclude`` globs scope the set.

Output is a directory tree: each repo gets its own
``<repo>/findings.json``, ``<repo>/scan.sarif``, and optional
``<repo>/threats.md``, plus a top-level ``fleet.json`` roll-up and
``fleet.md`` digest. The digest groups findings by repo and severity,
ranks repos by score, and surfaces the org-wide A/B/C/D distribution
at the top. ``--baseline-dir`` reads a prior fleet run's per-repo
``findings.json`` baselines so the gate only fires on new regressions
across the org. Every existing scan flag (``--fail-on``, ``--min-grade``,
``--standard``, ``--checks``, ``--resolve-remote``) is forwarded
unchanged to each sub-scan, so a fleet run is just the existing
scanner running N times with results stitched.

Closes the "do we even have visibility?" gap that pushes security
teams from CLIs into SaaS posture-management tools. Compounds with the
self-hosted dashboard (above): the same dashboard reads a fleet
``--output-dir`` directly with no extra plumbing. The fleet command
itself stays no-SaaS, no-telemetry, no DB; just a directory of files
the user can grep, version, and feed into their existing reporting.

Architecture: ``pipeline_check/cli.py`` gains a ``fleet`` subcommand;
``pipeline_check/core/fleet.py`` owns shallow-clone, per-repo
orchestration, and digest emission. The repo-list YAML and
``--from-org`` parsing reuse the existing SCM platform helpers.
Cross-repo XPC chains stay out of scope for v1; the chain engine
already runs per-repo and "an attack chain spanning two repos in the
same org" is a separate (interesting) problem worth its own design.

### VS Code extension

The TypeScript half of the editor-surface push; the LSP server
itself is shipped (see Shipped). Extension lives in
``pipeline-check-vscode`` and spawns ``python -m pipeline_check.lsp``
over stdio JSON-RPC. Trade-off accepted: the stdio schema becomes
a stable contract between the two repos, in exchange for keeping
the TS / ``vsce publish`` toolchain out of the Python project.

### Live Azure + GCP posture (parity with the 71-rule AWS pack)

``--cloud azure --subscription ...`` and ``--cloud gcp --project ...``
using the official SDKs. AWS-only live cloud scanning is a glaring
multi-cloud asymmetry; closing it removes one of the most obvious
"but does it cover us?" objections. Phased: ship 10 to 15 core
rules per cloud first, expand.

### Cross-document taint resolver: GitLab `include:` chains

GitLab ``extends:`` job-template inheritance and ``include:`` local
files already resolved in v1.0.x. The remaining gap is ``include:``
cross-pipeline file inclusion from remote URLs / projects /
templates / components, which would need cross-document machinery
similar to the GHA ``--resolve-remote`` flow. Closes the last
known limitation in the TAINT-NNN engine's coverage.

### Pipeline graph DAG v2 (step-level)

Phase 1 (blast-radius heatmap) shipped in v1.0.x. Phase 2 lifts the
heatmap to step-level granularity: steps as nodes, ``needs:`` /
``depends_on:`` / sequence as edges, findings rendered as
severity-colored badges on each node. Steps with attestation
attached show a small chain icon; steps that are taint-engine sinks
(TAINT-NNN family) get a flame icon when an active path lands on
them. Requires extending the Scanner-to-reporter API so the parsed
pipeline structure flows through; the v1 heatmap intentionally
avoided that plumbing change.

### Reachability-aware attack chains

Phase 1 (shared-job intersection) shipped incrementally across the
chain pack: roughly 20 of the 38 chain rules now intersect their
anchor findings' ``job_anchors`` sets, promote the chain confidence
to HIGH when a shared job exists, and emit a "reachability
unconfirmed, co-occurrence only" note when it doesn't. Four chains
(AC-015 / AC-024 / AC-027 / AC-028) carry explicit
"Reachability-model note" or "Reachability-model carve-out"
comments documenting why shared-job reachability doesn't apply
(cross-provider scope, chart-file co-occurrence, Dockerfile-level
locality, repo-level worm topology). The remaining chains don't
yet carry an explicit reachability discussion; backfilling those
notes is a follow-up. AC-001 is the canonical intersection
example.

Phase 2 is the dataflow-DAG variant: walk the TAINT engine's DAG
between the two anchor findings and only fire when an executable
connection exists. This is the right paradigm for the cross-
provider chains (XPC-NNN and AC-024 / AC-016 class) where
shared-job has no meaning: the anchors live in different
documents (CI workflow + AWS state, package.json + workflow,
Helm chart + cluster RBAC). Requires extending TAINT findings to
expose their source / sink coordinates on a cross-document
graph; the v1.0.x TAINT engine carries this state per-workflow
but doesn't yet expose it to the chain engine.

### Pluggable LLM-assisted triage (opt-in, local)

A ``--triage`` flag pipes each finding through a local-only LLM
(Ollama, llama.cpp, LM Studio) plus the surrounding pipeline
snippet, asking for a short "is this actually exploitable in this
repo's context" verdict. Three labels: ``confirmed``,
``needs_review``, ``likely_fp``. Strict no-network default; remote
endpoints require an explicit ``--triage-endpoint URL`` flag and
print a one-line warning before sending. Output is advisory, never
gates the build, and is rendered as a separate column beside the
rule-engine confidence so the two signals stay distinguishable.

Opt-in by design: keeps the no-telemetry promise intact, gives
users with already-running local LLMs a high-leverage adoption
hook, and stays out of the rule-engine path so a hallucinating
model can't change a HIGH into a LOW.

### Dependency-supply-chain provider follow-ups

The original npm / pypi / maven follow-up plan landed across
v1.0.5 and v1.1.0: lockfile + manifest-format coverage
(``package-lock.json`` / ``npm-shrinkwrap.json`` / ``pnpm-lock.yaml``
/ ``yarn.lock`` / ``poetry.lock`` / ``Pipfile.lock`` /
``pyproject.toml``), the three-registry cooldown trilogy
(NPM-008 / PYPI-008 / MVN-008) behind ``--resolve-remote``, the
NPM-009 new-transitive-dep diff gate, the ``npm audit signatures``
and ``pip --require-hashes`` CI gates (GHA-059 / GL-034 / BB-030
and GHA-060 / GL-035 / BB-031), and Gradle property + version-
catalog resolution. See the Shipped section for the per-cycle
trail.

One gap remains: ``rootProject.ext.X`` cross-project indirection
on Gradle multi-project layouts. Would need pipeline-check to
learn ``settings.gradle`` resolution. Rarer in practice than the
three Gradle shapes already shipped; deferred.

Next: the XPC-NNN chain engine gains chains pairing NPM-008
cooldown-miss with DF-024 lifecycle-scripts-enabled so the
composite escalates when both gates fail in the same scan.

### Vulnerable-by-design benchmark: phase 2 (cross-scanner comparison)

Phase 1 in-repo cases shipped with v1.0.x; phase 2 is the
cross-scanner comparison matrix (vs Zizmor / Poutine / Checkov /
KICS / Trivy). Tracked under ``bench/COMPARISON.md`` with the
trade-offs that justify *not* shipping it yet: installing four
other scanners in CI is its own surface, and the case selection has
to stop being unilateral before the matrix earns credibility.
Probably warrants extraction to a separate ``pipeline-check-bench``
repo at that point; the in-repo phase 1 keeps the case fixtures
co-located with the rules they exercise so case + rule changes land
in the same PR.

### Continuing posture: proof-of-exploit backfill

Not a discrete milestone. The ``exploit_example`` field landed in
v1.0.x with a starter population; the posture going forward is
that every new HIGH / CRITICAL rule ships one, and existing rules
without an exploit example get backfilled opportunistically.

### Lower priority

- **GitHub App.** PR-comment integration with diff-level finding
  placement instead of the current SARIF-into-code-scanning flow.
  SARIF already reaches the GitHub Code Scanning UI on every push,
  so a separate App duplicates a path that mostly exists, takes on
  ongoing review surface, and competes with native SARIF for
  adoption attention. Revisit if SARIF feedback proves consistently
  inadequate in practice or if multiple users explicitly ask for
  inline diff comments.
- **SaaS API.** Hosted scan endpoint with auth and history. Scope
  is large (auth, multi-tenancy, history DB) and blurs OSS
  positioning. Revisit if a clear paid-tier story emerges; until
  then, the self-hosted dashboard above covers the same operator
  pain at a fraction of the surface.

## Internal cleanup

Small targeted refactors and audit findings from the 2026-05-20
sweep. Not user-facing, but each landing makes the next provider,
rule, or test cheaper to add. Landing order is open; each
subsection stands alone.

### Rule-infrastructure consolidation

Code-quality findings across the engine, parsers, and rule pack.

- ~~**Blob-rule factory to collapse the per-provider clone
  clusters.**~~ Landed. ``_primitives/blob_rule.py`` ships
  ``yaml_blob_check(rule, *, scanner, pass_desc, fail_desc,
  pass_recommendation=None)`` and 25 rule modules across
  ``dep_update`` / ``tls_bypass`` / ``pkg_insecure`` /
  ``docker_insecure`` / ``malicious_activity`` now thin through it
  (~190 lines deleted net). Provider-specific shapes that need step
  iteration (BK-008, DR-006), step-level ``Location`` anchors
  (GHA-017), or Jenkinsfile text input (JF-017 / JF-018 / JF-022 /
  JF-023 / JF-029) keep their bespoke check bodies. The
  ``malicious_activity`` fail prose moved to a shared
  ``_malicious.summarize_malicious_hits`` helper. Follow-up:
  ``checks/base.py`` now exports ``NO_ARTIFACT_DESC`` so the "No
  artifact production detected, check not applicable." string
  routes through one constant across 28 signing / SBOM /
  vuln-scanning / provenance rule modules instead of repeating
  inline.
- **Lift provider context loaders + base classes.** Load-loop
  consolidation done: `checks/_yaml_files.py:load_yaml_files`
  hosts the read + parse + warning loop, and 11 providers
  (github, gitlab, bitbucket, azure, cloudbuild, kubernetes,
  buildkite, drone, tekton, argo, circleci) route through it.
  ``jenkins`` parses Groovy, not YAML, and stays on its custom
  loader. The ``BaseCheck`` generic-on-context change is still
  open as a separate refactor.
- ~~**Legacy `TLS_BYPASS_RE` / `CURL_PIPE_RE` migration.**~~ Landed
  in the post-1.2.0 cycle. `bk008`, `dr006`, `argo008`, `tkn008`,
  `bk004` now route through `_primitives/tls_bypass.py` and
  `_primitives/remote_script_exec.py` (closing the helm / kubectl /
  ssh / docker / maven / gradle / aws coverage gap), the
  `_comment_tls_bypass` autofixer scans per-line through the
  primitive, and the legacy combined constants are gone from
  `checks/base.py`.
- ~~**Triplicated dependency-supply-chain plumbing.**~~ Landed.
  Registry-fetcher side: `_primitives/registry_fetcher.py` owns the
  ``FileSystemCache`` + ``HttpGetFetcher`` transport + dedup-fetch-
  parse loop; ``npm`` / ``pypi`` / ``maven`` are now thin ~170-line
  adapters supplying the per-ecosystem URL builder, cache-key
  normalizer, and JSON parser. Public surface preserved verbatim
  so ``core/providers/{npm,pypi,maven}.py`` needed no import
  changes. ``CompromisedPackage`` side: each provider's dataclass
  keeps its ecosystem-specific identifier fields (``name`` for
  npm/pypi, ``group_id`` + ``artifact_id`` for maven) but the
  triplicated ``matches(version)`` method now delegates to
  ``_primitives/compromised.py:match_version`` so a future
  extension (semver-range support, e.g.) lands in one place.
- ~~**Autofix roundtrip safety.**~~ Landed. ``generate_fix`` parses
  the patched text through ``yaml.safe_load_all`` and bails when the
  result no longer parses, the top-level Python type swapped, or the
  multi-doc count changed. ``None``-after / Dockerfile / scalar
  inputs are permitted. Bailout logs a WARNING breadcrumb.
- ~~**Autofix re-declares provider keyword sets.**~~ Landed. The
  GitLab top-level keyword set and the Cloud Build first-toplevel
  anchor regex both now import from the canonical
  ``gitlab/base.py`` / ``cloudbuild/base.py`` ``TOPLEVEL_KEYWORDS``
  (promoted from ``_TOPLEVEL_KEYWORDS``).
- ~~**CLI exit-code convergence.**~~ Landed. Every previously-direct
  ``sys.exit(N)`` in `cli.py` (list-checks empty-rows, ``--man``
  typo, MCP unavailable, eager printer commands, ``--config-check``
  fail, scan-failure traceback, gate failure, ``explain``) now
  routes through ``raise click.exceptions.Exit(N)``.
  ``_tolerate_unencodable_stdio()`` moved out of import-time side
  effects into ``main()`` so MCP / LSP callers don't inherit the
  Windows console stream reconfiguration.
- ~~**Chain-engine and CLI swallowing exceptions silently.**~~
  Landed for the chain engine. ``chains/engine.py`` now logs the
  chain id + traceback at WARNING and keeps the additive semantics.
  The cli.py call sites already echo to stderr (release of the
  audit predates the routine).
- ~~**Hot-path `looks_like_example` quadratic slice.**~~ Landed.
  Per-blob `(line_start, indent, name)` index keyed on `id(blob)`
  and bisected; `clear_blob_cache()` drops both caches together.
- **Smaller cleanups bundled with the above.** ~~Rule-metadata copy
  boilerplate (the 4-line `finding.cwe = list(rule.cwe); ...`
  block in ~20 orchestrators; `npm/pipelines.py` already extracted
  a private `_apply_rule_metadata` worth promoting)~~ — landed:
  every class-based orchestrator (gha, gitlab, bitbucket, azure,
  jenkins, circleci, cloudbuild, buildkite, drone, tekton, argo,
  dockerfile, helm, kubernetes, oci, scm, terraform, cloudformation,
  aws) now calls ``apply_rule_metadata(finding, rule)`` from
  ``checks/rule.py``. ~~Triplicated
  `_wants_ctx_kwarg` in `npm` / `pypi` / `maven` `pipelines.py`.~~
  Done: now `checks/rule.py:wants_ctx_kwarg`. ~~`SHA_RE`
  (`^[0-9a-f]{40}$`) compiled in 6+ rule files; export one from
  `_primitives/`.~~ Done (`_primitives/sha_ref.py`).
  ~~`custom/evaluator.py:460` bare `except Exception:` while
  compiling user JSONPath silently setting `path=None`.~~ Narrowed
  to `JsonPathError`. ~~`custom/loader.py:116` letting `OSError` /
  `UnicodeDecodeError` propagate raw while every provider wraps
  these into `warnings.append(...)`.~~ Wrapped in
  `CustomRuleError` (the loader is fail-fast, not
  warning-collecting). ~~Standards registration is a
  hand-maintained 15-item list when `chains/engine.py:_discover()`
  already demonstrates the `pkgutil.iter_modules` pattern; copy
  it over `standards/data/`.~~ Done: `standards/__init__.py`
  walks the subpackage at import time.

### Test-suite tightening

From an audit of the 6,700-test pytest suite (91.4% line coverage,
full sweep clean on `dev`). The suite is healthy; these are
tightening opportunities, not fires.

- ~~**CLI tests over-mock the Scanner.**~~ Landed. Five new tests
  in ``tests/test_cli.py::TestFlagMarshallingEndToEnd`` exercise
  ``--output-file`` (json + sarif), ``--baseline`` (gate-relative
  filtering + missing-path error), and ``--diff-base`` (leading-dash
  rejection) against the real Scanner / reporter / gate path. The
  mocked ``TestExitCodes`` / ``TestFlagWiring`` tests stay as they
  are — they cover exit-code wiring, which is what they were
  always meant to verify.
- ~~**MCP / Helm test-skip excepts are too broad.**~~ Landed. MCP
  import-time except narrowed to ``(ImportError, ModuleNotFoundError)``;
  the Helm e2e test only skips when
  ``HelmRenderError.__cause__`` is ``OSError`` or
  ``subprocess.TimeoutExpired``. Any other failure shape propagates.
- ~~**Subprocess-based stability tests are order-sensitive.**~~
  Landed. `tests/conftest.py` now snapshots ``os.getcwd()`` + the
  ``PIPELINE_CHECK_*`` env set before every test and re-asserts at
  teardown; a leak fails the offending test rather than the
  subprocess-based stability test that consumed the inherited
  state. Audit found no unrestored ``os.chdir`` callsites today,
  but the guard prevents regressions.
- ~~**Clock-sensitive GHA-042 reputation test.**~~ Landed. GHA-042
  picked up a module-level ``_now()`` indirection; the boundary
  test now freezes via ``monkeypatch.setattr`` and drops its
  ``seconds=1`` workaround. The same indirection got backfilled
  into NPM-008, PYPI-008, MVN-008, IAM-007, and GHA-047 so the
  whole cooldown / key-age family is on the same fault-line-free
  pattern.
- ~~**XPC chain test boilerplate duplicates nine times.**~~ Landed.
  Factories live in `tests/_chain_helpers.py`; mechanical
  assertions live once in
  `tests/test_chain_xpc_mechanical.py`, parametrized off a
  `MECHANICAL_CONTRACTS` list. Adding XPC-N is now one row instead
  of ~100 lines of clone.
- ~~**Standards-doc drift test is partially circular.**~~ Landed.
  `tests/test_generated_docs_in_sync.py::test_standards_doc_references_every_control`
  reads each `docs/standards/<name>.md` off disk and asserts every
  control id + title from the live registry appears verbatim,
  with no generator in the path.
- ~~**IAM-003 has no real-shape boto3 coverage.**~~ Landed. Four
  new tests in ``tests/aws/rules/test_iam003_real_shape.py`` use
  ``botocore.stub.Stubber`` to drive ``list_roles`` against a
  real ``boto3.client("iam")`` with paginated responses that
  carry ``PermissionsBoundary``. The shape that LocalStack drops
  and the synthetic-dict tests can't authenticate now has
  positive coverage (with-boundary / without / multi-page /
  trust-policy filter). Same fixture pattern can backfill the
  other pagination-dependent IAM rules when needed.
- ~~**Branch coverage for argo004 and k8s017.**~~ Landed. Both
  modules are at 100% line coverage after the
  ``podSpecPatch`` JSON / regex branches on argo004 and the
  ``_looks_literal`` / non-string-value / missing-name branches
  on k8s017 picked up positive + negative tests.

### Dogfood code-scanning cleanup

From a review of the repo's GitHub Code Scanning queue.
Pipeline-Check's own rules and the OpenSSF Scorecard upload both
flag real hardening gaps in the project's own workflows.

- ~~**Switch `pip install` to `--require-hashes`** in `release.yml`
  and `docs.yml` (GHA-060).~~ Landed in the post-1.2.0 cycle.
  `docs.yml` consumes the regenerated hash-locked
  `requirements-docs.txt`; `release.yml`'s SBOM step installs deps
  via `--require-hashes -r requirements.txt` and then drops the
  freshly built wheel on top with `--no-deps` so no unpinned
  registry resolution happens.
- ~~**Tighten elevated top-level GITHUB_TOKEN scopes** on
  `dogfood.yml`, `docker-publish.yml`, and `codeql.yml`.~~ Landed.
  Every elevated `security-events: write` / `packages: write` /
  `id-token: write` grant moved to a per-job `permissions:` block;
  workflow top-levels now hold `contents: read`.
- ~~**GHA-004 false positive on `scorecard.yml`.**~~ Landed.
  `ossf/scorecard-action` (publish-results OIDC) and
  `docker/build-push-action` with `provenance:` / `sbom:` (Sigstore
  signing) both joined GHA-004's OIDC-consumer allowlist.
- **Mark fixture Dockerfiles / workflows as Scorecard-exempt.**
  Roughly 15 `PinnedDependenciesID` errors hit
  `tests/fixtures/workflows/**` and `bench/cases/**` files that
  exist because they're insecure (they're negative test cases
  for the project's own rules). Either dismiss via the API with
  reason "used as a negative test case", or add path excludes to
  `.github/workflows/scorecard.yml`.
- **`master` branch protection** (Scorecard `BranchProtectionID`).
  Real gaps: no required reviewers, no required status checks,
  allow-deletion enabled. Tightening this also lifts the
  Scorecard score on the next run.

Out of scope for this cleanup: the Scorecard zero-score alerts
(`FuzzingID`, `CIIBestPracticesID`, `MaintainedID`,
`CodeReviewID`) are policy noise on a young / solo-maintainer
repo, not security gaps. Dismiss with reason rather than chase.

## Non-goals

Things that have come up but aren't planned. Stating them here saves
discussion later.

- **IaC autofix beyond comment-only TODOs.** Text patching Terraform
  HCL or CloudFormation YAML can't see the resource graph. Risk of
  silently breaking cross-resource references is too high. Comment-
  only TODOs are fine; transformative fixes aren't.
- **Generic SAST.** Pipeline-Check scans pipeline definitions, not
  application source. Bandit, Semgrep, CodeQL already do SAST well.
- **Telemetry or phone-home.** Not now, not later. The "no telemetry"
  promise on the landing page is load-bearing.
- **Vendoring rules from other tools.** No checkov / kics / trivy
  rule imports. Every rule here is hand-written so the recommendation
  prose, severity, and standards mapping all reflect the same point
  of view.

## How to propose changes

Open an issue with the `feature_request` template. For new providers
or attack chains, include a short rationale and 2 to 3 example
findings the rule would catch. For new rules within an existing
provider, an OWASP CICD-SEC or CIS Benchmark citation helps.
