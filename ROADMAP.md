# Roadmap

What's planned, what's shipped, and what's deliberately out of scope.

## Shipped

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

- **Blob-rule factory to collapse the per-provider clone clusters.**
  Several rule families exist as near-verbatim wrappers around a
  shared scanner: `dep_update` (5 providers), `tls_bypass` (7),
  `pkg_insecure` + `docker_insecure` (6 each), `malicious_activity`
  (6), plus the "No artifact production detected, check not
  applicable" string repeated in 56 places. A
  `_primitives/blob_rule.py` factory taking `(scanner, kind,
  prose_suffix)` collapses each cluster into a 3-line module.
  Removes roughly 300 lines of churn per new "applies to every CI
  provider" rule the project ships in the future.
- **Lift provider context loaders + base classes.** The `from_path`
  body (root check, glob, `read_text`, `safe_load_yaml_lines`,
  skip / warning bookkeeping) repeats near-verbatim in 11
  `<provider>/base.py` files (github, gitlab, circleci, bitbucket,
  azure, cloudbuild, buildkite, drone, tekton, kubernetes, jenkins).
  The 4-line `XxxBaseCheck.__init__` boilerplate that re-annotates
  `self.ctx` repeats in the same set. Hoist a `load_yaml_files(root,
  filenames, multi_doc)` helper next to `_yaml_lines.py` and make
  `BaseCheck` generic on its context type so providers declare
  `class FooBaseCheck(BaseCheck[FooContext])`. Knocks the
  per-provider boilerplate down to a few dozen lines.
- **Legacy `TLS_BYPASS_RE` / `CURL_PIPE_RE` migration.** Most
  providers moved to `_primitives/tls_bypass.py` (~20 patterns)
  and `_primitives/remote_script_exec.py`. Holdouts (`bk008`,
  `dr006`, `argo008`, `tkn008`, `bk004`) still pull from
  `checks/base.py` and so miss helm / kubectl / ssh / docker /
  maven / gradle bypasses every other provider catches. Migrate
  the holdouts, delete the legacy constants from `base.py`. Real
  coverage gap, small diff.
- **Triplicated dependency-supply-chain plumbing.** `npm/`, `pypi/`,
  and `maven/` each ship their own ~280-line `registry_fetcher.py`
  and their own `CompromisedPackage` dataclass + lookup helpers.
  The only ecosystem-specific bits are `BASE_URL`, the name
  normalizer, and `_parse_publish_times`. A generic
  `_primitives/registry_fetcher.py` parameterized on `url_builder
  + parser + normalizer` reduces three near-clones to three small
  adapters. Same shape for the compromised-package tables. This
  one earns its keep before adding a fourth ecosystem (Go modules,
  RubyGems, etc.).
- **Autofix roundtrip safety.** `core/autofix/_impl.py` rewrites
  YAML via line-oriented regexes. `_fix_gha008` misfires on flow
  mappings, block scalars, and already-quoted values; `_fix_gha015`
  leaks state across multi-doc streams. Wrap every generated patch
  in a `yaml.safe_load(after)` parse-check and bail returning
  `None` when the result no longer parses or its top-level
  structure changed. Cheap safety net for a feature users run
  unattended.
- **Autofix re-declares provider keyword sets.** `autofix/_impl.py`
  has its own copy of the GitLab top-level keywords (and the same
  pattern for cloudbuild) that already live in
  `gitlab/base.py:_TOPLEVEL_KEYWORDS`. Import the canonical set so
  the two can't drift the next time GitLab adds a top-level key.
- **CLI exit-code convergence.** `cli.py` mixes `sys.exit(3)`,
  `ctx.exit(3)`, and `sys.exit(_eager_print_...())` across paths
  with the same "info printed, exit cleanly" intent. Programmatic
  callers get `SystemExit` from some paths and click-controlled
  exit from others. Route every early exit through `ctx.exit()` /
  `raise click.exceptions.Exit()`. Also move
  `_tolerate_unencodable_stdio()` out of import-time side effects
  into `main()` so MCP / LSP callers don't inherit stream
  reconfiguration.
- **Chain-engine and CLI swallowing exceptions silently.**
  `chains/engine.py:73-79` plus several spots in `cli.py` do
  `except Exception: continue` with no logging, so a broken chain
  rule never surfaces. Log via `logging` at WARNING. Chains stay
  additive (don't fail the scan), but leave a breadcrumb.
- **Hot-path `looks_like_example` quadratic slice.**
  `_context.py:81-87` runs `re.finditer(..., blob[:line_start])`
  for every `_secrets` / `_malicious` match. For 50 matches in a
  5 KB blob that's 50 full-prefix slices + 50 full-prefix regex
  scans. Cache a sorted `(line_start, indent, name)` index keyed
  on `id(blob)` (the same trick `blob_lower` already uses) and
  bisect.
- **Smaller cleanups bundled with the above.** Rule-metadata copy
  boilerplate (the 4-line `finding.cwe = list(rule.cwe); ...`
  block in ~20 orchestrators; `npm/pipelines.py` already extracted
  a private `_apply_rule_metadata` worth promoting). Triplicated
  `_wants_ctx_kwarg` in `npm` / `pypi` / `maven` `pipelines.py`.
  `SHA_RE` (`^[0-9a-f]{40}$`) compiled in 6+ rule files; export
  one from `_primitives/`. `custom/evaluator.py:460` bare
  `except Exception:` while compiling user JSONPath silently
  setting `path=None`. `custom/loader.py:116` letting `OSError` /
  `UnicodeDecodeError` propagate raw while every provider wraps
  these into `warnings.append(...)`. Standards registration is a
  hand-maintained 15-item list when `chains/engine.py:_discover()`
  already demonstrates the `pkgutil.iter_modules` pattern; copy
  it over `standards/data/`.

### Test-suite tightening

From an audit of the 6,700-test pytest suite (91.4% line coverage,
full sweep clean on `dev`). The suite is healthy; these are
tightening opportunities, not fires.

- **CLI tests over-mock the Scanner.** `tests/test_cli.py:45-77`
  (`TestExitCodes`) and `tests/test_cli_branches.py:108-204`
  `patch("pipeline_check.cli.Scanner")` and return canned
  findings, so they exercise click wiring but skip every line of
  loader / rule / baseline / score / gate code. The unmocked
  `TestAutoDetect` (`test_cli.py:179-225`) and the disk-fixture
  sweep in `test_workflow_fixtures.py` cover the real path, but
  CLI-to-Scanner argument-marshalling regressions (the
  `--output-file` shape, `--baseline`, `--diff-base`) can only
  be caught by an unmocked CLI test. Add one end-to-end CLI test
  per flag-marshalling surface and let the mocked tests focus on
  exit-code wiring as advertised.
- **MCP / Helm test-skip excepts are too broad.**
  `tests/test_mcp_server.py:31-37` does
  `try: import mcp.types except Exception: _HAS_MCP = False`, so
  a real `AttributeError` / `TypeError` raised by
  `pipeline_check.mcp_server.server` at import silently skips
  every `TestServerRegistration` test. Same shape in
  `tests/helm/test_helm_provider.py:187-190` where
  `except HelmRenderError` converts every render failure into a
  `pytest.skip`. Narrow both to the specific signals (`ImportError`
  / `ModuleNotFoundError` for MCP; `OSError`, `FileNotFoundError`,
  `TimeoutExpired` for Helm, or only when `exc.reason == "helm
  exit"`) so a scanner-side bug can no longer hide behind a
  green-skip.
- **Subprocess-based stability tests are order-sensitive.**
  `tests/test_stability_contract.py::test_exit_2_on_*` and
  `::test_exit_0_on_clean_scan` `subprocess.run([sys.executable,
  "-m", "pipeline_check", ...])` against a `tmp_path` cwd. They
  pass in isolation and as a class but red intermittently when
  interleaved into the full suite, which points at test pollution
  leaking into the spawned process (a sibling test `os.chdir`ing
  without restoring, or a `PIPELINE_CHECK_*` env var sticking).
  Audit for unrestored `os.chdir` / `monkeypatch.delenv` paths and
  add a session-scoped guard that asserts cwd / env haven't drifted
  between tests.
- **Clock-sensitive GHA-042 reputation test.**
  `tests/github/test_action_reputation.py:324-358` subtracts an
  extra second from "now" to dodge sub-second drift between the
  test's `datetime.now` and the rule's. Author calls out the risk
  in the docstring. Inject an `_now()` indirection into
  `pipeline_check.core.checks.github.rules.gha042_young_action_repo`
  and freeze it in the test (one-line `monkeypatch.setattr`). Same
  shape exists across the cooldown / key-age tests in
  `tests/pypi/test_pypi008.py`, `tests/maven/test_mvn008.py`,
  `tests/npm/test_npm008.py`, `tests/aws/rules/test_iam007_key_age.py`,
  and `test_workflow_fixtures.py:85-110`, none flaky today but all
  ride the same wall-clock fault line.
- **XPC chain test boilerplate duplicates nine times.**
  `tests/test_chain_xpc001.py` through `tests/test_chain_xpc009.py`
  each carry their own `_failing` / `_passing` factories and the
  same three mechanical tests (engine dispatch, one-chain-per-combo,
  confidence inheritance). The only per-file variance is the
  resource pair. Factor the boilerplate into
  `tests/_chain_helpers.py` and parameterize the mechanical tests
  so adding chain ten doesn't carry forward 150 lines of clone.
  The chain-specific `test_fires_on_combined_*` cases stay per-file.
- **Standards-doc drift test is partially circular.**
  `tests/test_attack_chains_doc.py` and
  `tests/test_generated_docs_in_sync.py` invoke the generator
  and diff its output against the on-disk doc, so a bug inside
  the generator matches both sides and the drift test stays green.
  `test_rule_framework.py::test_generated_doc_references_every_rule`
  already mitigates this for provider docs by asserting each
  `rule.id` / `rule.title` appears in the rendered output
  independently of the generator. Add the equivalent guard for
  `gen_standards_docs.py`: assert each control id from
  `pipeline_check.core.standards.registry` appears verbatim in the
  rendered standards page, without re-running the generator.
- **IAM-003 has no real-shape boto3 coverage.**
  `tests/integration/test_localstack.py:105-110` documents that
  IAM-003 can't be asserted on LocalStack because pagination
  doesn't echo `PermissionsBoundary` back, and the mocked
  `tests/aws/test_iam.py::TestIAM003*` uses synthetic dicts. The
  rule has zero coverage against a real boto3 response shape.
  Capture one real `list_roles` paginator response (sanitized) into
  a fixture and replay it via `botocore.stub.Stubber`. Same gap
  shape may exist for other IAM rules; check pagination-dependent
  fields (boundary, attached policies, instance profiles).
- **Branch coverage for argo004 and k8s017.**
  `pipeline_check/core/checks/argo/rules/argo004_host_namespace.py`
  (64%) and
  `pipeline_check/core/checks/kubernetes/rules/k8s017_env_credential.py`
  (73%) carry the lowest non-deliberate coverage of any single rule
  file. Each is ~20 lines of unhit branches. Add one positive +
  negative test per missed branch.

### Dogfood code-scanning cleanup

From a review of the repo's GitHub Code Scanning queue.
Pipeline-Check's own rules and the OpenSSF Scorecard upload both
flag real hardening gaps in the project's own workflows.

- **Switch `pip install` to `--require-hashes`** in `release.yml`
  and `docs.yml` (GHA-060). These are the two project workflows
  still tripping the rule pipeline-check ships.
- **Tighten elevated top-level GITHUB_TOKEN scopes** on
  `dogfood.yml`, `docker-publish.yml`, and `codeql.yml` (Scorecard
  `TokenPermissionsID`). Push `security-events: write` /
  `packages: write` from the workflow top-level down to the single
  job that needs them so the rest of the workflow runs with
  `contents: read`.
- **GHA-004 false positive on `scorecard.yml`.** The rule flags
  the analysis job's `id-token: write` as unconsumed, but
  `ossf/scorecard-action` does consume it (the `publish_results:
  true` path posts to the OpenSSF Scorecard API via OIDC). Add
  `ossf/scorecard-action` to GHA-004's `_OIDC_ACTION_PREFIXES`
  allowlist in
  `pipeline_check/core/checks/github/rules/gha004_permissions.py`.
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
