# Roadmap

What's planned, what's shipped, and what's deliberately out of scope.

## Shipped

- v1.0.x — first production-stable release. Carries every v0.4 / v0.5
  / v0.6 item below the "Landed" markers of those pre-1.0 cycles
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
- **npm + pypi dependency-supply-chain providers (post-1.0.4)** —
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
- **SCM GitLab + Bitbucket platform parity** — ``--scm-platform
  gitlab`` and ``--scm-platform bitbucket`` ship a 7-rule
  universal subset against the GitLab and Bitbucket APIs.
  CODEOWNERS-file presence cross-check (SCM-017), PR-review
  bypass-allowance audit (SCM-018), and push-restriction
  allowlist audit (SCM-019) closed the remaining GitHub-side
  feature gaps in the same cycle.
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

Larger items proposed after v1.0.4. Not yet scoped to a specific
release; landing order is open.

### Dependency-supply-chain provider follow-ups (npm v2 / pypi v2 / maven v2)

*Shipped so far: NPM-001..008 + NPM-011, PYPI-001..006 + PYPI-008,
MVN-001..008 — static manifest / lockfile / .npmrc / pom.xml /
settings.xml / build.gradle(.kts) analysis plus the curated
compromised-package registries (npm, PyPI, Maven Central), the
``files``-field secret-leak detector, and the three-registry
cooldown trilogy (NPM-008 / PYPI-008 / MVN-008) behind
``--resolve-remote``.*
The follow-up rules below require either new infrastructure
(lockfile diff against a base ref) or different ecosystem
plumbing and so are deferred:

- **NPM-009** — transitive-dependency diff gate. When a CI run
  mutates the lockfile, fail if a new transitive dep appears that
  didn't exist in the base ref. The axios -> plain-crypto-js
  backdoor would have been caught here at PR review time. Pairs
  with the shipped NPM-008 (cooldown) and NPM-006 (known-bad
  registry). Needs base-ref lockfile-diff infra.
- **NPM-010** — ``npm audit signatures`` step missing from CI.
  Lockfile rules guarantee package contents match the recorded
  hash; ``npm audit signatures`` is what verifies those hashes are
  the ones the maintainer actually signed via the registry's
  trusted-publisher records. Lockfile pinning without signature
  verification is integrity theater. Belongs in the CI providers
  (GHA / GitLab / Bitbucket) rather than the npm provider.
- **yarn.lock + pnpm-lock.yaml parsers.** Coverage parity for the
  two non-npm lockfile formats; both ship distinct schemas that
  warrant separate parsers, deferred from the initial pack.
- **PYPI extensions.** ``pyproject.toml`` (PEP 621 / Poetry)
  parser (``Pipfile.lock`` and ``poetry.lock`` already ship).
  PYPI-007 publish-time hash verification step missing from CI.
- **Gradle property resolution.** ``build.gradle(.kts)`` parsing
  already ships under the maven provider (coordinate-string and
  map-form deps + ``maven { url ... }`` repositories), but
  ``${propName}`` and Gradle version-catalog references are left
  unresolved on the first cut. Resolving them lifts MVN-001 /
  MVN-008 hit rate on Gradle projects to Maven parity.

Architecture: extends the existing ``pipeline_check/core/checks/
npm/``, ``pypi/``, and ``maven/`` packages; ``--resolve-remote``
reuses the ``ActionRepoMetadata`` fetcher pattern but targets the
npm registry (``https://registry.npmjs.org/<pkg>``), PyPI JSON API
(``https://pypi.org/pypi/<pkg>/json``), and Maven Central search
API (``https://search.maven.org/solrsearch/select``); offline /
fixture mode reads JSON from disk for hermetic CI. The XPC-NNN chain engine
gains chains pairing NPM-008 cooldown-miss with DF-024 lifecycle-
scripts-enabled so the composite escalates when both gates fail
in the same scan.

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

### VS Code extension / LSP

Thin LSP wrapping the existing ``--explain`` output and per-rule
findings. The ruff lesson is that an editor surface drives more
adoption than any new rule pack. A few weeks of work to ship the
MVP.

Repo split (decided 2026-05-18): the LSP server lives in this repo
as ``pipeline_check/lsp/`` (``pygls``-based, runnable via
``python -m pipeline_check.lsp``) so ``Rule`` / ``Finding`` schema
changes and the server consuming them land in the same diff. The
VS Code extension itself lives in a separate repo
(``pipeline-check-vscode``, TypeScript) and spawns the server over
stdio JSON-RPC, mirroring the ``astral-sh/ruff`` +
``astral-sh/ruff-vscode`` split. Trade-off accepted: the stdio
schema becomes a stable contract between the two repos, in
exchange for keeping the TS / ``vsce publish`` toolchain out of
the Python project.

### Live Azure + GCP posture (parity with the 71-rule AWS pack)

``--cloud azure --subscription ...`` and ``--cloud gcp --project ...``
using the official SDKs. AWS-only live cloud scanning is a glaring
multi-cloud asymmetry; closing it removes one of the most obvious
"but does it cover us?" objections. Phased: ship 10 to 15 core
rules per cloud first, expand.

### Distribution beyond `pip install`

Standalone shiv or PyInstaller binary attached to every GitHub
release plus a ``ghcr.io/<owner>/pipeline-check`` container image.
Removes the Python-install friction for shops whose CI containers
don't ship Python (Go-shop CI, JVM-shop CI, container-only build
environments). Pure packaging move, no rule code change. The
marketplace ``action.yml`` already shipped is the GHA half of this;
the binary + container image cover every other CI.

### Vulnerable-by-design benchmark — phase 2 (cross-scanner comparison)

Phase 1 in-repo cases shipped with v1.0.x; phase 2 is the
cross-scanner comparison matrix (vs Zizmor / Poutine / Checkov /
KICS / Trivy). Tracked under ``bench/COMPARISON.md`` with the
trade-offs that justify *not* shipping it yet — installing four
other scanners in CI is its own surface, and the case selection has
to stop being unilateral before the matrix earns credibility.
Probably warrants extraction to a separate ``pipeline-check-bench``
repo at that point; the in-repo phase 1 keeps the case fixtures
co-located with the rules they exercise so case + rule changes land
in the same PR.

### Cross-document taint resolver: GitLab `include:` chains

GitLab ``extends:`` job-template inheritance and ``include:`` local
files already resolved in v1.0.x. The remaining gap is ``include:``
cross-pipeline file inclusion from remote URLs / projects /
templates / components — would need cross-document machinery
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

The chain engine today fires on co-occurrence: an ``AC-NNN`` chain
emits when both anchor rules emit findings, regardless of whether
the same execution path connects them. The next iteration walks the
dataflow graph between the two anchor findings and only fires when
an executable connection exists.

Cuts the chain-engine false-positive rate, promotes confidence on
every path that does fire to HIGH, and reuses the TAINT engine's
DAG (no separate machinery). Closes the biggest legitimate
criticism of the AC-* family: that co-occurrence is a weaker claim
than reachability.

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

### Rolling proof-of-exploit backfill

``exploit_example`` field landed in v1.0.x with a starter
population. Continuing population is ongoing: every new HIGH /
CRITICAL rule should ship one, and existing rules without an
exploit example should be backfilled opportunistically. Not a
discrete milestone, just a posture.

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
