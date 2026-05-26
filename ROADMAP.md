# Roadmap

What's planned, what's shipped, and what's deliberately out of scope.

## Shipped

- **Gradle multi-project ``rootProject.ext.X`` resolution
  (post-1.3.0)** — Closes the last remaining gap in the dependency-
  supply-chain provider follow-ups. The maven provider's Gradle path
  now walks upward from each ``build.gradle`` looking for
  ``settings.gradle`` / ``settings.gradle.kts`` to identify the
  multi-project root, reads the root's ``build.gradle*`` for
  ``ext { X = ... }`` / ``ext.X = ...`` / ``def X`` / ``val X``
  declarations, and exposes each value under both
  ``rootProject.ext.X`` and ``rootProject.X`` keys so a subproject's
  ``"${rootProject.ext.log4jVersion}"`` (and the shortened
  ``"${rootProject.springVersion}"``) version-spec resolves before
  the MVN-NNN rules see it. Five new tests in
  ``tests/maven/test_gradle.py`` cover the Groovy and Kotlin DSLs,
  the shortened accessor, the root-itself carve-out, and the
  silent-pass behavior on layouts without a ``settings.gradle``
  marker.
- **AC-031 attack chain: Argo CD PR generator x wildcard sourceRepos
  (post-1.3.0)** — Second Argo CD chain. CRITICAL severity,
  single-provider (``argocd``). Pairs ARGOCD-006 (ApplicationSet
  PR/SCM generator without a project allowlist) with ARGOCD-001
  (AppProject ``sourceRepos: ['*']``). Composite: a contributor PR
  in the matched org materializes a fresh ``Application`` under a
  wildcard-source-repos project; the controller renders attacker-
  supplied manifests into the cluster on the next sync. The
  default out-of-the-box AppProject ships with the wildcard, so
  the chain fires on most Argo CD installs where a PR generator is
  introduced without tightening the project. MITRE T1195.002 /
  T1199 / T1078.004. Chain count 40 -> 41.
- **AC-030 attack chain: Argo CD anonymous access x wildcard RBAC
  (post-1.3.0)** — First attack-chain pairing the v1.3.0 Argo CD
  provider's rules. CRITICAL severity, single-provider (``argocd``).
  Fires when ARGOCD-009 (anonymous access enabled in ``argocd-cm``)
  and ARGOCD-004 (wildcard authority grant in ``argocd-rbac-cm``)
  both fail against the same Argo CD instance. Composite: the
  anonymous principal resolves through the wildcard grant into
  unauthenticated control-plane authority, Argo CD's sync engine
  becomes a cluster-takeover primitive. MITRE T1190 / T1078.001 /
  T1098.003. Chain count 39 -> 40. The ``docs/attack_chains.md``
  hand-edited chain table also picked up the missing AC-028 /
  AC-029 rows.
- **XPC-010 attack chain: npm cooldown x Dockerfile lifecycle
  (post-1.3.0)** — Cross-provider chain pairing NPM-008 (manifest
  pinned an exact version published inside the cooldown window) and
  DF-024 (Dockerfile install runs lifecycle scripts). Either leg
  alone is bounded; together they are the consumer-side Shai-Hulud
  topology, the next ``npm ci`` inside the build container resolves
  a freshly published version AND runs its ``postinstall`` with the
  builder's NPM_TOKEN / GH_TOKEN / AWS_* in scope. Closes the
  "Next" item under Dependency-supply-chain provider follow-ups.
  Severity HIGH, MITRE T1195.002 / T1078.004 / T1546. Chain count
  38 -> 39. Activates on ``--pipelines npm,dockerfile`` (or any
  multi-provider run carrying both legs) with ``--resolve-remote``
  on for NPM-008's publish-time metadata.
- **Argo CD provider (post-1.3.0)** — New CD-side provider, kept
  disjoint from the existing ``argo`` (Argo Workflows) pack.
  ``--pipeline argocd`` parses ``Application`` / ``ApplicationSet`` /
  ``AppProject`` CRDs plus the ``argocd-cm`` / ``argocd-rbac-cm``
  ConfigMaps. Nine rules cover AppProject ``sourceRepos: '*'``
  (ARGOCD-001), wildcard destinations (ARGOCD-002), auto-sync
  ``prune: true`` without ``selfHeal`` (ARGOCD-003), ``argocd-rbac-cm``
  policies granting wildcard authority (ARGOCD-004), ``argocd-cm``
  repo entries storing plaintext credentials (ARGOCD-005),
  ApplicationSet PR / SCM generators without a project allowlist
  (ARGOCD-006), Helm ``valueFiles`` / parameters using generator
  placeholders without ``spec.goTemplate: true`` (ARGOCD-007),
  Application invoking a config-management plugin (ARGOCD-008), and
  ``argocd-cm`` with anonymous access enabled (ARGOCD-009). File
  discovery is disjoint from the Workflows provider, so
  ``--pipelines argo,argocd`` against a single directory produces
  non-overlapping findings. Standards mappings added in
  ``owasp_cicd_top_10``, ``cis_supply_chain``, and
  ``esf_supply_chain``. Provider count 22 -> 23; total-check claim
  810+ -> 820+. Twenty-two per-rule tests under ``tests/argocd/``.
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
- **Zizmor parity sweep (GHA-063 .. GHA-096, post-1.3.0)** —
  Full gap analysis against ``zizmorcore/zizmor`` v1.25.2. Every
  genuine gap landed: GHA-063 bot-conditions, GHA-064 unsound-
  contains, GHA-065 zero-width/bidi unicode, GHA-066 upload-artifact
  wildcard, GHA-067 cache-sensitive-files, GHA-068 deprecated-runner,
  GHA-069 orphan id-token:write, GHA-070 ssh-keyscan TOFU, GHA-071
  powershell-on-Linux, GHA-072 overprovisioned-secrets, GHA-073
  unused workflow_call.secrets, GHA-088 typosquat-uses, GHA-089
  archived-uses, GHA-090 impostor-commit, GHA-091 takeover-eligible
  org, GHA-092 TOCTOU PR head SHA, GHA-093 Living-off-the-Pipeline,
  GHA-094 branch-tip ref, GHA-095 ref-version-mismatch, GHA-096
  known-vulnerable action via GHSA. Plus widenings: GHA-004 top-level
  write-scope aggregation, GHA-053 PR label/milestone predicates,
  GHA-058 agentic AI tool after PR checkout, GHA-003 services
  sinks, GHA-050 attestation-disabled. ``--only-known-attacked``
  filter also landed.
- **cicd-goat 29/29 scenario coverage (v1.3.0 .. v1.4.0)** —
  Every scenario in the ``greylag-ci/cicd-goat`` 29-scenario matrix
  has at least one mapped rule. Final gaps closed with GHA-086
  (wildcard branch trigger + environment), GHA-087 (secret-derivation
  echo), local composite-action scanning, and multi-provider
  invocations.
- **Inline source-line ignore comments (post-1.3.0)** — Three
  directive variants: ``ignore[ID]``, ``ignore-next-line[ID]``,
  ``ignore-file[ID]``. Both ``#`` and ``//`` comment prefixes.
  Disabled via ``--no-inline-ignore``. 23 tests.
- **Autofix safety tiers (post-1.3.0)** — ``--fix`` runs safe fixers
  only; ``--fix=unsafe`` runs both. 109 safe, 2 unsafe. Missing
  labels default to unsafe.
- **Direct-HCL Terraform parsing (post-1.3.0)** — ``--tf-source``
  parses ``*.tf`` files directly via ``python-hcl2``. All 58 TF-NNN
  rules run unchanged. Variable/local substitution is best-effort.
  Closes the ``terragoat`` skip in ``bench/goats/``. 23 tests.
- **NuGet provider (v1.4.0)** — Fifth dependency-supply-chain
  provider. Parses ``*.csproj``, ``Directory.Packages.props``,
  ``packages.config``, ``NuGet.config``, ``packages.lock.json``.
  Nine rules (NUGET-001..009). Provider count 23 -> 24. 22 tests.
- **Live OSV advisory lookup (v1.4.0)** — Shared
  ``_primitives/osv_fetcher.py`` queries the OSV batch API. Four
  new rules: NPM-010, PYPI-009, MVN-009, NUGET-009.
- **Dependency-supply-chain provider follow-ups (v1.0.5 .. v1.4.0)** —
  Lockfile + manifest-format coverage, cooldown trilogy (NPM-008 /
  PYPI-008 / MVN-008), NPM-009 new-transitive-dep diff gate, CI
  hash-verification gates, Gradle property + version-catalog
  resolution, ``rootProject.ext.X`` cross-project indirection,
  XPC-010 cooldown + lifecycle chain. All gaps closed.
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
teams from CLIs into SaaS posture-management tools. The fleet command
stays no-SaaS, no-telemetry, no DB; just a directory of files
the user can grep, version, and feed into their existing reporting.

Architecture: ``pipeline_check/cli.py`` gains a ``fleet`` subcommand;
``pipeline_check/core/fleet.py`` owns shallow-clone, per-repo
orchestration, and digest emission. The repo-list YAML and
``--from-org`` parsing reuse the existing SCM platform helpers.
Cross-repo XPC chains stay out of scope for v1 of fleet itself; the
chain-engine widening that composes findings across the fleet corpus
lives in its own subsection below (and issue #173).

### Cross-repo XPC chains (org-spanning attack-chain composition)

The chain engine today fires per-repo, every ``AC-NNN`` / ``XPC-NNN``
rule reads one scan's findings and decides whether the composite
topology is present. Many real exploit shapes span two repos in the
same org with the anchors living in different scans (npm publish in
repo A consumed by floating versions in repo B, Argo CD config in
repo A pointing at app code in repo B, App-token mint in repo A
whose installation reaches repo B, reusable-workflow producer in
repo A called by consumer in repo B).

Activates only on fleet scans (depends on the fleet subsection
above), as a single pass after per-repo scans complete: index every
finding by anchor predicate, intersect anchor sets across the
corpus, emit ``CXPC-NNN`` findings scoped to the pair (or N-tuple)
of repos that share the topology. Reachability v1 is co-occurrence
across the corpus (MEDIUM confidence with a "cross-repo
co-occurrence, reachability unconfirmed" note); v2 promotes to HIGH
on identity-bound co-occurrence (same App-installation slug, same
OIDC subject pattern, same package name); v3 plugs into the dataflow
phase below for the cross-document DAG walk.

Initial pack: CXPC-001 (npm publish-side + floating consume-side on
the same package name), CXPC-002 (Argo CD wildcard ``sourceRepos`` +
weakened app-repo CI gates), CXPC-003 (over-broad App-token scope +
installation reaches partner repo), CXPC-004 (reusable-workflow
producer + consumer when the producer has an unguarded TAINT source,
widens TAINT-003 to the cross-repo split). Cross-org and
cross-platform composition stay out of scope.

Filed as #173.

### Live secret verification (verified / unverified / unknown)

Per-detector live probe on every secret-shaped finding, gated on
`--resolve-remote`. Verified findings get promoted to CRITICAL with
the resolved identity attached; revoked / rotated keys get demoted
toward LOW; unprobed detectors keep current severity. Detector
verifiers under ``_primitives/secret_verifiers/`` one module per
issuing service (AWS STS, GitHub `/user`, NPM `/-/whoami`, Slack
`auth.test`, GCP IAM `signBlob`, Anthropic / OpenAI / Twilio /
SendGrid / Stripe). Reuses the existing
`_primitives/registry_fetcher.py` transport + cache; values SHA-256d
before any cache write so plaintext never lands on disk. Inspiration:
trufflehog `--only-verified`. Filed as #175.

### Custom-rule entry point via OPA / Rego

Rego frontend for custom rules alongside the existing YAML loader.
Closes the "can we add an org-specific composite check without a
Python PR?" gap that Checkov, poutine, Snyk IaC, and Trivy all
already cover. Input document mirrors the rule-engine's parsed
pipeline shape (workflows, dockerfiles, terraform, k8s, scm,
plus `findings_so_far` so Rego packages can act as lightweight
composite chains). `--rego-rules ./policies/` discovers `.rego`
files; package path determines the synthesized rule id; the
existing `--checks` / `--ignore-file` / `--baseline` / standards
plumbing applies once the id is synthesized. Integration via
shell-out to a user-provided `opa` binary on `$PATH` (documented as
a soft dependency, fails cleanly when missing) keeps the wheel
Python-only. Filed as #176.

### VS Code extension

The TypeScript half of the editor-surface push; the LSP server
itself is shipped (see Shipped). Extension lives in
``pipeline-check-vscode`` and spawns ``python -m pipeline_check.lsp``
over stdio JSON-RPC. Trade-off accepted: the stdio schema becomes
a stable contract between the two repos, in exchange for keeping
the TS / ``vsce publish`` toolchain out of the Python project.

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
chain pack: roughly half of the chain rules intersect their anchor
findings' ``job_anchors`` sets, promote the chain confidence to
HIGH when a shared job exists, and emit a "reachability
unconfirmed, co-occurrence only" note when it doesn't. The
remaining chains (all cross-provider) now carry an explicit
"Reachability-model carve-out" section in their module docstring
documenting why shared-job reachability doesn't apply and what
the actual reachability claim is (per-scan co-occurrence, repo-
level co-occurrence, per-instance co-occurrence, Dockerfile-level
locality, chart-file co-occurrence). AC-001 is the canonical
intersection example; AC-028 / XPC-010 are the canonical carve-
out examples.

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

### OSC&R standard mapping

Add ``pipeline_check/core/standards/data/oscr.py`` as the 17th
standards mapping.  OSC&R (Open Software Supply Chain Attack Reference,
``pbom-dev/OSCAR``) is a MITRE ATT&CK-style matrix purpose-built for
software supply chain attacks: 12 tactics (Reconnaissance through
Impact), roughly 87 techniques.  The matrix fills a gap between
OWASP CI/CD Top 10 (which is CI/CD-specific but only 10 items) and
NIST 800-53 / ESF (which are broad frameworks, not attack catalogs).

Most existing rules already cover OSC&R techniques and need only the
mapping annotation: secrets-in-logs maps to Credential Access, dependency
confusion to Initial Access, injection to Execution, admin-bypass to
Defense Evasion, etc.  The initial lift is a mapping exercise, not a
rule-writing exercise.

Deliverables: ``oscr.py`` data file with technique-to-check mappings,
``docs/standards/oscr.md`` generated page, ``--standard oscr`` CLI
support (inherits from the existing standards plumbing), and an optional
``--oscr`` column in the findings table showing the matched OSC&R
technique ID per finding.

Informed by: ReversingLabs OSC&R glossary, ``pbom-dev/OSCAR`` repo.

### Supply-chain posture rule pack (gimmepatz / TVPO / OSC&R informed)

A themed rule pack closing gaps surfaced by cross-referencing
``6mile/gimmepatz``, ``6mile/tvpo``, ``SecureStackCo/
visualizing-software-supply-chain``, and the OSC&R technique list
against the existing 820+ checks.  Six rules, all static (no network
required unless noted).

**SCM-0xx: Codespace secrets scoped to all repos.**  GitHub SCM API
check.  Fires when an org-level codespace secret is visible to every
repo in the org instead of scoped to a named repo set.  A single
compromised codespace in any repo exposes the secret.  OSC&R
Credential Access; OWASP CICD-SEC-2.

**SCM-0xx: Classic PAT used where fine-grained token suffices.**
Fires when a workflow authentication step or SCM integration references
a classic PAT (``ghp_`` prefix) instead of a fine-grained token
(``github_pat_`` prefix).  Classic tokens carry org-wide scope and
cannot restrict to individual repos.  OSC&R Credential Access;
OWASP CICD-SEC-2.

**NPM-0xx: Publish token missing readonly or IP restriction.**
Extends the npm provider.  Fires when a ``.npmrc`` auth token used
in a publish workflow lacks ``//registry.npmjs.org/:_authToken``
combined with a ``//registry.npmjs.org/:always-auth`` or CIDR-
whitelisted configuration.  A leaked unrestricted publish token
enables full package hijack.  OSC&R Initial Access (registry
compromise); OWASP CICD-SEC-3.  Requires ``--resolve-remote`` for
live ``.npmrc`` inspection in referenced configs.

**GHA-0xx: Recursive PR auto-merge loop.**  Fires when a workflow
(a) triggers on ``pull_request`` or ``pull_request_target``, (b)
creates or updates a PR via ``gh pr create`` / ``peter-evans/
create-pull-request`` / similar, and (c) the target branch has an
auto-merge rule or the workflow itself calls ``gh pr merge --auto``.
The topology creates a persistence vector: the workflow's own PR
triggers itself on the next cycle, allowing an attacker to maintain
code injection across merges.  OSC&R Persistence (Scheduled Task /
Recursive PR); OWASP CICD-SEC-1.

**GHA-0xx (multi-provider): Pipeline missing security scan gate
before deploy.**  Meta-check firing at the workflow level.  Walks the
job DAG for deploy-shaped steps (``aws deploy``, ``kubectl apply``,
``helm upgrade``, publish-to-registry, environment-gated jobs) and
checks whether any upstream job or step invokes a recognized security
scanner (SAST, SCA, container scan, secret scan).  Recognized
scanners drawn from the ``top_actions.py`` catalog plus common CLI
invocations (``trivy``, ``grype``, ``semgrep``, ``bandit``,
``snyk test``, ``npm audit``, ``pip-audit``, ``gitleaks``).
Fires when a deploy step has zero security-scan predecessors in
the DAG.  Severity MEDIUM (advisory, not blocking).  OSC&R Defense
Evasion (bypass controls); OWASP CICD-SEC-7.  Extends to GitLab
and Azure DevOps as a second pass.

**GHA-0xx: Deployment secret passed as plaintext env var.**  Fires
when a ``deploy``-tagged or environment-gated job sets an environment
variable to a literal string matching a secret shape (AWS key,
GCP service-account JSON, API token regex) instead of referencing
``${{ secrets.NAME }}``.  Complements the existing ``gha033``
(secret echoed) and ``gha087`` (secret derivation echo) by catching
the inverse: a value that should be in the secrets store but isn't.
OSC&R Credential Access; OWASP CICD-SEC-2.

Informed by: ``6mile/gimmepatz`` (token scoping, PAT types, NPM
token hygiene), ``6mile/tvpo`` (SAST/SCA gate presence, credential
exposure), ``SecureStackCo/visualizing-software-supply-chain``
(build environment integrity, security-stage presence), OSC&R
technique catalog (recursive PR, defense evasion via missing gates).

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
  then the fleet command covers the same operator pain at a fraction
  of the surface.

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
