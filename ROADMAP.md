# Roadmap

What's planned, what's shipped, and what's deliberately out of scope.

## Shipped

### Unreleased (on ``dev``)

Nothing yet this cycle. PRs landing on ``dev`` add their thematic
entries here; the release commit collapses this into
``### vX.Y.Z (YYYY-MM-DD)``.

### v1.6.0 (2026-05-29)

- **Composer + RubyGems registry providers** — Two new
  dependency-supply-chain providers, both graduated to 10 rules in
  the same cycle they landed. ``--pipeline composer`` parses
  ``composer.json`` / ``composer.lock`` (COMPOSER-001..010);
  ``--pipeline rubygems`` parses ``Gemfile`` / ``Gemfile.lock``
  (GEM-001..010). Text-only static analysis, no runtime install.
  Plus NPM-013, NUGET-010, OCI-009 and the gomod / cargo / pulumi /
  nuget / maven / drone / argocd / helm / pypi rule-count deepenings
  that filled out the package-registry and GitOps packs. Provider
  count to 32.
- **Azure Cloud + GCP live cloud-posture providers (closes #163)** —
  Phase 1 seeded ``--pipeline azure-cloud`` and ``--pipeline gcp`` with
  15 rules each across identity, network, storage, compute, and logging.
  Phase 2 expanded both packs to 50 rules each, reaching parity with
  the AWS provider's coverage shape (71 rules). CIS Azure Foundations
  and CIS GCP Foundations standards mappings landed alongside.
  Provider rule counts: AZ 0 -> 50, GCP 0 -> 50.
- **Secret verifier expansion (phase 2)** — Twelve new live-verification
  probes for ``--verify-secrets``: DigitalOcean, Netlify, Terraform
  Cloud, Linear, Atlassian, Asana, New Relic, Telegram Bot, Replicate,
  Cohere, Mailchimp (datacenter-derived endpoint), Square. All probes
  are read-only, rate-limited, and identity-extracting where the API
  supports it. Verifier count 13 -> 25. 26 new tests.
- **Secrets-in-CI-logs detection (cross-provider)** — Four new rules
  detecting ``echo`` / ``printf`` / ``cat`` of secret-named variables,
  ``printenv`` / ``env`` environment dumps, and ``set -x`` shell trace
  with secret-bound variables in scope: GL-036 (GitLab CI), BB-032
  (Bitbucket Pipelines), ADO-031 (Azure DevOps), CC-032 (CircleCI).
  Shared detection logic in ``_primitives/log_leak.py``. Extends the
  existing GHA-033 pattern to every CI provider that supports inline
  scripts.
- **AI agent pipeline risk rules** — Two new rules expanding the
  GHA-058 agentic-CLI category. GHA-103 (CRITICAL) detects AI
  code-review bots (CodeRabbit, CodiumAI PR-Agent, Sourcery, Codeball,
  GitHub Copilot) running on ``pull_request_target`` or
  ``issue_comment`` triggers with write permissions and no
  ``environment:`` gate (the HackerBot-Claw vector). GHA-104 (HIGH)
  detects workflows where an agentic CLI generates code and pushes
  commits directly without routing through a PR review cycle. GHA rule
  count 93 -> 95.
- **Gitea / Forgejo Actions provider** — ``--pipeline gitea`` reuses
  the full GHA rule pack against ``.gitea/workflows/`` and
  ``.forgejo/workflows/`` YAML files. Auto-detected when either
  directory is present. GitHub-specific reputation rules pass silently
  when remote-resolve metadata is absent. Provider count 26 -> 27.
- **History dashboard enhancements (closes #160)** — The
  ``pipeline_check history`` dashboard gains per-rule burn-down
  sparklines, a resource-level heatmap of consistently failing file
  paths, and fleet directory integration so the history loader can
  read a fleet ``--output-dir`` directly with recursive
  ``**/findings.json`` discovery.
- **exploit_example backfill on all CRITICAL + HIGH rules** — Every
  CRITICAL rule (13) and every HIGH rule (36) now carries an
  ``exploit_example`` paired with the existing recommendation. Closes
  the "continuing posture: proof-of-exploit backfill" line item for
  the two top severities; MEDIUM / LOW remain opportunistic.
- **GitLab Code Quality output (``--output codequality``)** — Code
  Climate JSON shape that GitLab CI renders as inline MR annotations,
  the GitLab parallel of GitHub's SARIF code-scanning surface. One
  entry per ``(check_id, location)`` pair so aggregate findings produce
  one annotation per offending line. Stable SHA-1 fingerprint over
  ``(check_id, path, line, description)`` for cross-run dedupe. Zero
  new dependencies.
- **Inline explain mode (``--inline-explain``)** — Terminal flag that
  injects each failing finding's ``exploit_example`` under the
  Recommendation block in its panel, saving the
  ``pipeline_check --explain CHECK_ID`` round-trip during triage.
  Named with the ``inline-`` prefix to avoid colliding with the
  existing ``--explain CHECK_ID`` early-exit option.

### v1.5.0 (2026-05-27)

- **Build-time dependency SBOM generation** —
  ``--output cyclonedx`` emits a CycloneDX 1.6 JSON BOM of every
  build-time dependency the pipeline consumes. V1 ships extractors
  for GitHub Actions (action refs, reusable workflows, docker steps),
  Dockerfile (FROM base images), npm (package.json deps), and PyPI
  (requirements.txt entries). Each component carries a PURL
  identifier. ``BaseProvider.build_dependencies()`` is the extension
  point; providers not yet covered return an empty list. Deferred
  to v2: GitLab include refs, Helm chart deps, Maven, NuGet, OCI,
  SPDX output format. 49 tests.
- **OPA/Rego custom rule engine (closes #176)** —
  ``--rego-rules ./policies/`` discovers ``.rego`` files, extracts
  metadata via ``opa inspect --annotations``, evaluates policies via
  ``opa eval``, and funnels results through the existing
  Finding/scoring/gating/SARIF pipeline. Each ``.rego`` file declares
  rule ID, severity, and provider via OPA's ``# METADATA`` annotation
  block. Rego rules can target all 24 providers (the YAML DSL is
  limited to 7). The ``opa`` binary is a soft dependency (shell-out,
  documented install, clean error when missing). Config-file support
  via ``rego_rules:`` in ``.pipeline-check.yml`` / ``pyproject.toml``.
  ``findings_so_far`` input deferred to v2. 22 tests. See
  ``docs/writing_a_rego_rule.md``.
- **GitLab remote ``include:`` resolver (closes #164)** —
  Cross-document taint resolution for GitLab CI. When
  ``--resolve-remote`` is on, the provider fetches
  ``include: { project/remote/template/component }`` directives via
  the GitLab API and merges them into the pipeline document before
  rules run. TAINT-004 (dotenv artifact flow) and TAINT-008
  (extends-chain inheritance) now see jobs and templates from remote
  includes. Four include types: ``project:`` (file API with
  ``PRIVATE-TOKEN``), ``remote:`` (HTTPS-only direct fetch),
  ``template:`` (templates API), ``component:`` (URI-parsed to project
  file fetch). Recursive resolution with depth limit and cycle
  detection. Disk cache at
  ``~/.cache/pipeline-check/gitlab-resolver/``. New CLI options:
  ``--gitlab-token``, ``--gitlab-url``. Closes the last known gap in
  the TAINT engine's coverage.
- **Supply-chain posture rule pack** — Six rules
  informed by ``6mile/gimmepatz``, ``6mile/tvpo``,
  ``SecureStackCo/visualizing-software-supply-chain``, and the
  OSC&R technique catalog.  GHA-097 (recursive PR auto-merge loop,
  OSC&R PER-1), GHA-098 (deploy without security scan gate,
  OSC&R DE-4), GHA-099 (deploy env plaintext secret, OSC&R CA-6),
  SCM-048 (org codespace secrets scoped to all repos, new
  ``/orgs/{owner}/codespaces/secrets`` API fetch), SCM-049 (classic
  PAT detection via token-prefix inspection), NPM-012 (legacy
  publish token lacking ``npm_`` granular-token restrictions).
  All six mapped to OWASP, OSC&R, and all 16 standards.  Rule
  counts: GHA 87 -> 90, SCM 47 -> 49, npm 11 -> 12.
- **OSC&R standard mapping** — 16th standards mapping.
  OSC&R (Open Software Supply Chain Attack Reference,
  ``pbom-dev/OSCAR``) is a MITRE ATT&CK-style matrix for software
  supply chain attacks: 12 tactics, 86 techniques.  610 checks
  mapped to 61 of 86 techniques; 25 attacker-side techniques
  (reconnaissance, resource development, runtime exploitation) left
  unmapped with documented gaps.  Control IDs use a
  ``<tactic-abbreviation>-<sequence>`` scheme minted by this project
  (not upstream).  ``--standard oscr`` inherits from existing
  standards plumbing.  Generated docs page at
  ``docs/standards/oscr.md``.  Standards count 15 -> 16.
  Informed by ReversingLabs OSC&R glossary.
- **Live secret verification (closes #175)** —
  ``--resolve-remote --verify-secrets`` probes every credential-shaped
  finding against its issuing API. Three buckets: VERIFIED (active
  token, promotes to CRITICAL with the resolved identity attached),
  UNVERIFIED (revoked or rotated, demotes to LOW), UNKNOWN (no
  verifier or probe inconclusive, severity unchanged). Initial
  verifier pack: GitHub PAT, GitLab PAT, NPM token, Slack token,
  Anthropic, OpenAI, Hugging Face, Stripe, and SendGrid API keys.
  ``--verify-secrets-show-identity`` opts into full identity strings
  in output. Raw secret values are never persisted; cache keys are
  SHA-256 digests. Stderr nudge printed when secrets found without
  verification enabled. Inspired by trufflehog ``--only-verified``.
  Verifier modules under ``_primitives/secret_verifiers/``, one per
  issuing service.
- **Secret verifier expansion phase 1** —
  Four new live-verification probes: Docker Hub PAT
  (``/v2/user`` bearer probe, identity extraction), PyPI upload
  token (405-based auth confirmation against ``upload.pypi.org``),
  Google Cloud API key (Generative Language API endpoint probe
  with ``INVALID_ARGUMENT`` / ``API_KEY_INVALID`` classification),
  JWT (issuer-based routing with Auth0 / Okta / Azure AD / Google
  userinfo probes; GitHub OIDC tokens recognized with
  ``sub``-extracted identity but not probed since they are
  short-lived). Verifier count 9 -> 13. 18 new tests.
- **Org-wide fleet scanning phase 2 (closes #161)** —
  ``--from-org ORG`` enumerates repos from the SCM API (GitHub, GitLab,
  Bitbucket backends with pagination, archived repos excluded).
  ``--include`` / ``--exclude`` glob filters on repo name.
  ``--jobs N`` for parallel clones and scans (auto-detected worker
  count by default). ``--scan-flags`` forward arbitrary flags to each
  per-repo subprocess via ``shlex.split``. Multi-platform YAML
  coordinates (``gitlab:group/sub/project``,
  ``bitbucket:workspace/slug``). Cross-repo CXPC chain evaluation runs
  automatically after all per-repo scans complete. Still deferred:
  ``--baseline-dir`` regression diffing, per-repo SARIF output,
  per-repo ``threats.md``.
- **Cross-repo XPC chains (closes #173)** — Four
  ``CXPC-NNN`` chains that fire only during fleet scans, composing
  findings across repo boundaries. CXPC-001: npm publish-side cooldown
  (NPM-008) + floating consumer in a partner repo (NPM-001/NPM-002),
  HIGH, T1195.002 / T1078.004. CXPC-002: Argo CD wildcard
  ``sourceRepos`` (ARGOCD-001) + weakened CI gate in a partner repo
  (GHA-002/TAINT-001/TAINT-002), CRITICAL, T1195.002 / T1199 /
  T1078.004. CXPC-003: unscoped App-token mint (GHA-061) + credential
  exposure in a partner repo (GHA-005/GHA-008), HIGH, T1078.004 /
  T1098.001. CXPC-004: tainted reusable-workflow producer
  (TAINT-001/002/003) + any GHA consumer finding in a partner repo,
  HIGH, T1195.002 / T1199. All four use v1 co-occurrence reachability
  at MEDIUM confidence. Chain engine gained
  ``evaluate_cross_repo(findings_by_repo)``. Chain count 41 -> 45.
- **cicd-goat 38-scenario coverage push** —
  Three new rules, one widening, three attack chains close every
  pipeline-check-side gap in the expanded 38-scenario corpus.
  GHA-100 (``cosign verify`` without ``--certificate-identity`` +
  ``--certificate-oidc-issuer``, scenario 35, solo catch across all
  scanners). TAINT-009 (environment-protected secret flows to
  unprotected consumer job via ``needs.<job>.outputs``, scenario 36,
  solo catch). GHA-102 (``actions/checkout`` with
  ``submodules: recursive`` on a PR trigger, scenario 38, solo catch).
  GHA-063 widened to promote severity to CRITICAL when the bot-actor
  gate combines with ``gh pr merge --auto`` or the
  ``hmarr/auto-approve-action`` family (Synacktiv confused-deputy
  primitive). AC-032 (cosign-unbound artifact to deploy,
  GHA-100 + GHA-098), AC-033 (environment-secret laundering,
  TAINT-009 + GHA-098), AC-034 (submodule-poisoned PR to credential
  exfiltration, GHA-102 + GHA-037/GHA-004). GHA rule count
  90 -> 93; chain count 45 -> 48. 40 tests. Remaining gap:
  scenarios 20, 29, 34 need cicd-goat comparison-config fixes
  (upstream PRs filed); scenario 37 is blocked by cicd-goat's
  ``if: false`` safety model (filed upstream).

### v1.4.0 (2026-05-22)

- **NuGet provider** — Fifth dependency-supply-chain
  provider. Parses ``*.csproj``, ``Directory.Packages.props``,
  ``packages.config``, ``NuGet.config``, ``packages.lock.json``.
  Nine rules (NUGET-001..009). Provider count 23 -> 24. 22 tests.
- **Live OSV advisory lookup** — Shared
  ``_primitives/osv_fetcher.py`` queries the OSV batch API. Four
  new rules: NPM-010, PYPI-009, MVN-009, NUGET-009.
- **Zizmor parity sweep (GHA-063 .. GHA-096)** —
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
- **Inline source-line ignore comments** — Three
  directive variants: ``ignore[ID]``, ``ignore-next-line[ID]``,
  ``ignore-file[ID]``. Both ``#`` and ``//`` comment prefixes.
  Disabled via ``--no-inline-ignore``. 23 tests.
- **Autofix safety tiers** — ``--fix`` runs safe fixers
  only; ``--fix=unsafe`` runs both. 109 safe, 2 unsafe. Missing
  labels default to unsafe.
- **Direct-HCL Terraform parsing** — ``--tf-source``
  parses ``*.tf`` files directly via ``python-hcl2``. All 58 TF-NNN
  rules run unchanged. Variable/local substitution is best-effort.
  Closes the ``terragoat`` skip in ``bench/goats/``. 23 tests.
- **Gradle multi-project ``rootProject.ext.X`` resolution** —
  Closes the last remaining gap in the dependency-supply-chain
  provider follow-ups. The maven provider's Gradle path now walks
  upward from each ``build.gradle`` looking for ``settings.gradle``
  to identify the multi-project root, reads the root's
  ``build.gradle*`` for ``ext { X = ... }`` / ``ext.X = ...`` /
  ``def X`` / ``val X`` declarations, and exposes each value under
  both ``rootProject.ext.X`` and ``rootProject.X`` keys. Five new
  tests cover the Groovy and Kotlin DSLs.
- **AC-031 attack chain: Argo CD PR generator x wildcard sourceRepos**
  — Second Argo CD chain. CRITICAL severity. Pairs ARGOCD-006
  (ApplicationSet PR/SCM generator without a project allowlist) with
  ARGOCD-001 (AppProject ``sourceRepos: ['*']``). Chain count
  40 -> 41.
- **AC-030 attack chain: Argo CD anonymous access x wildcard RBAC** —
  First attack-chain pairing the Argo CD provider's rules. CRITICAL
  severity. Fires when ARGOCD-009 (anonymous access) and ARGOCD-004
  (wildcard authority grant) both fail against the same instance.
  Chain count 39 -> 40.
- **XPC-010 attack chain: npm cooldown x Dockerfile lifecycle** —
  Cross-provider chain pairing NPM-008 (cooldown window) and
  DF-024 (Dockerfile install runs lifecycle scripts). Severity HIGH.
  Chain count 38 -> 39.
- **Dependency-supply-chain provider follow-ups (v1.0.5 .. v1.4.0)** —
  Lockfile + manifest-format coverage, cooldown trilogy (NPM-008 /
  PYPI-008 / MVN-008), NPM-009 new-transitive-dep diff gate, CI
  hash-verification gates, Gradle property + version-catalog
  resolution, ``rootProject.ext.X`` cross-project indirection,
  XPC-010 cooldown + lifecycle chain. All gaps closed.

### v1.3.0 (2026-05-21)

- **Argo CD provider** — New CD-side provider, kept
  disjoint from the existing ``argo`` (Argo Workflows) pack.
  ``--pipeline argocd`` parses ``Application`` / ``ApplicationSet`` /
  ``AppProject`` CRDs plus the ``argocd-cm`` / ``argocd-rbac-cm``
  ConfigMaps. Nine rules (ARGOCD-001..009). Provider count
  22 -> 23. 22 tests.
- **GitHub Actions cicd-goat coverage push** —
  Two new rules and one widened taint hop, plus five existing-rule
  widenings, close eleven ``greylag-ci/cicd-goat`` scenarios in one
  cycle. GHA-062, GHA-061, GHA-008 keyed-hex shape, TAINT-002
  widened for matrix-axis expansion. Also: GHA-016, GHA-019, GHA-033,
  GHA-049, GHA-057 widenings.
- **Auto-publish GitHub Release on tag push** —
  ``release.yml`` gained a ``publish-github-release`` job that
  extracts the matching ``## [X.Y.Z]`` section from ``CHANGELOG.md``
  and runs ``gh release create``. Closes the Marketplace-tile gap
  that stranded the tile on v1.0.5 for two cycles.
- **Org-wide fleet scanning phase 1 (closes #161)** —
  ``pipeline_check fleet --repos repos.yml`` reads a YAML list of
  ``owner/repo`` coordinates, shallow-clones each, runs per-repo
  scans, and writes ``fleet.json`` aggregate + ``fleet.md`` digest.

### v1.0.x – v1.2.0

- v1.0.x — first production-stable release. Carries every v0.4 / v0.5
  / v0.6 item (STRIDE threat model, MCP server, SCM provider,
  composite-action resolution, action-reputation pack, multi-scanner
  SARIF ingest, taint engine spanning 8 rules across 5 providers,
  multi-provider scan mode, attestation content checks, GHA-04x PPE
  rules, extended obfuscated-exec catalog), plus the API-stability
  commitment on ``pipeline_check.__all__``. Mid-cycle: five-rule
  worm-mitigation pack (DF-024, DF-025, GHA-048, GHA-049, GHA-050).
- **npm + pypi dependency-supply-chain providers (v1.0.5)** —
  ``--pipeline npm`` and ``--pipeline pypi``. Fourteen rules total
  (NPM-001..007 + NPM-011, PYPI-001..006).
- **Maven dependency-supply-chain provider (v1.0.5)** —
  ``--pipeline maven``. Seven rules (MVN-001..007). Provider count
  to 22.
- **SCM GitLab + Bitbucket platform parity (v1.0.1)** —
  ``--scm-platform gitlab`` and ``--scm-platform bitbucket`` with a
  7-rule universal subset.
- **Container image distribution (v1.0.1)** —
  ``ghcr.io/dmartinochoa/pipeline-check`` and Docker Hub, multi-arch,
  with Docker Scout gating and SLSA provenance + SBOM attestations.
- **SLSA Build L3 provenance on the wheel (v1.0.4)** — Every
  tagged release runs ``slsa-framework/slsa-github-generator`` with
  Sigstore signing. PyPI trusted publishing with PEP 740 attestations.
- **LSP server (v1.1.0)** — ``pipeline_check/lsp/`` is a
  ``pygls`` 2.x server behind the ``pipeline-check[lsp]`` extra.
  Editor diagnostics match ``pipeline_check --output json``.
- **Real-world GOAT corpus benchmark (v1.1.0)** —
  `bench/goats/` ships pinned-clone benchmarks: ``cicd-goat`` (9/9),
  ``cfngoat`` (6/6), ``kubernetes-goat`` (27/27), ``terragoat``
  (pending curation). 42 check IDs locked. CI workflow runs nightly
  + on PRs. See ``docs/goat_bench.md``.

### Pre-1.0

- v0.4.x / v0.5.x / v0.6.x — pre-1.0 milestone work folded into
  v1.0.x. See `CHANGELOG.md` for the per-version trail.
- v0.3.x — Kubernetes provider, docs site, attack chains engine,
  English variant enforcement, doc-claim drift guards.
- v0.2.x — Cloud Build, Jenkins, Terraform, CloudFormation, JUnit
  and Markdown reporters, 13-standard mapping, autofix engine, HTML
  report interactivity.

## Known issues

Bugs found in a full feature review (2026-05-29). Each was confirmed
by reading the code path, not just inferred. File references are
approximate line anchors at review time.

The **high** and **medium** severity findings from this review are
fixed in v1.6.0 (see the ``### Fixed`` block in ``CHANGELOG.md``):
the remote-resolve redirect SSRF, the PyPI / Google secret-verifier
false-positives, the OSV truncated-batch caching, the host-blind
GitLab include cache key, the cross-repo reverse-direction dedup, the
terminal Rich-markup leak, the autofix line-ending flip on Windows,
the docker / package flag fixers reclassified ``unsafe``, and the
``history --dir`` fleet-aggregate ingestion. The **low** severity
items below remain open.

### Low

- **JWT verifier uses wrong userinfo endpoints.** For Microsoft Entra
  it builds ``{issuer}/openid/userinfo`` instead of the Graph
  ``oidc/userinfo`` endpoint, and the Google entry points at a
  deprecated host (``jwt.py:67``). Active tokens come back
  UNKNOWN/UNVERIFIED (false negative, no false CRITICAL).
- **``--diff-base`` under-scans from a repo subdirectory.**
  ``changed_files`` (``diff.py:50``) treats git's repo-root-relative
  output as cwd-relative. Launched from a subdir, the path intersection
  misses real changes and ``_filter_context_by_diff`` drops files that
  actually changed, the opposite of the module's stated over-scan
  guarantee.
- **Terraform diff filter drops renamed-module resources.**
  ``_filter_terraform_by_diff`` (``scanner.py:796``) matches a module
  call label against the changed file's parent directory name. When the
  source directory differs from the call label (the common case,
  ``module "vpc" { source = "./modules/networking" }``), changed
  resources are dropped and never scanned.
- **GitLab ``project:`` include with a list-valued ``file:`` fails.**
  ``_fetch_project`` does ``str(file_path)`` (``gitlab/resolver.py:107``);
  GitLab allows ``file:`` to be a list, so ``str([...])`` builds a bogus
  URL that 404s and the includes are silently dropped.
- **SARIF ingest under-grades a missing ``level``.** A result with no
  ``level`` and no ``security-severity`` maps to INFO
  (``sarif_ingest.py:119``); the SARIF 2.1.0 default is ``warning``, so
  findings from tools that omit per-result level can be filtered out by
  a severity gate.
- **Fleet GitHub enumerator crashes on a null ``clone_url``.**
  ``r.get("clone_url", default)`` (``fleet.py:325``) only fills the
  default when the key is absent; a ``"clone_url": null`` value passes
  ``None`` into ``git clone`` and raises ``TypeError`` mid-enumeration.
  The GitLab and Bitbucket paths guard this with ``isinstance``; GitHub
  does not.
- **Rego/custom evaluator edge cases.** The regex haystack is truncated
  to 100 KB before matching (``evaluator.py:271``), so a ``$``-anchored
  pattern can match the truncation boundary instead of the real end;
  and numeric / length operators treat ``bool`` as a number
  (``evaluator.py:363``) since ``bool`` subclasses ``int``, so a YAML
  ``true`` compares as ``1`` rather than failing the type check.
- **Passing Rego findings drop metadata.** ``make_passing_findings``
  (``rego_runner.py:222``) does not copy ``cwe`` / ``incident_refs`` /
  ``exploit_example`` the way the YAML path and failing Rego findings
  do, and K8s Rego violations default ``resource`` to ``<unknown>``
  because ``input_data`` has no top-level ``path`` key
  (``rego_runner.py:173``).
- **Cosmetic.** ``history._svg_line_chart`` renders a real chart for an
  all-zero dataset instead of the "no data" placeholder
  (``history.py:362``); ``inline_ignore`` captures ``reason=`` with
  ``\S+`` so multi-word reasons truncate at the first space
  (``inline_ignore.py:31``); gate baseline matching does not normalize
  path separators, so a baseline written on one OS can fail to suppress
  on another (``gate.py:429``).

## Candidates

Larger items not yet scoped to a specific release. Landing order
is open.

### ``--inline-explain`` across every reporter

Today the flag affects only ``--output terminal`` (and ``both`` via
the terminal half). JSON and HTML include ``exploit_example``
unconditionally; SARIF, JUnit, markdown, and codequality drop the
field entirely. Lift the gate from the terminal reporter into a
``Finding``-layer decision (e.g. pre-filter or a render context
shared by every reporter) so all formats can honor the flag
uniformly. Includes wiring ``exploit_example`` into the SARIF
``help.text``, the JUnit ``<failure>`` body, the markdown comment
template, and the Code Quality ``description``. Help text in
``cli.py`` already names the current carve-outs so users aren't
misled in the interim.

### VS Code extension

The TypeScript half of the editor-surface push; the LSP server
itself is shipped (see v1.1.0). Extension lives in
``pipeline-check-vscode`` and spawns ``python -m pipeline_check.lsp``
over stdio JSON-RPC. Trade-off accepted: the stdio schema becomes
a stable contract between the two repos, in exchange for keeping
the TS / ``vsce publish`` toolchain out of the Python project.

### Pipeline graph DAG v2 (step-level)

Phase 1 (blast-radius heatmap) shipped in v1.0.x. Phase 2 lifts the
heatmap to step-level granularity: steps as nodes, ``needs:`` /
``depends_on:`` / sequence as edges, findings rendered as
severity-colored badges on each node. Requires extending the
Scanner-to-reporter API so the parsed pipeline structure flows
through; the v1 heatmap intentionally avoided that plumbing change.

### Reachability-aware attack chains

Phase 1 (shared-job intersection) shipped incrementally across the
chain pack. Phase 2 is the dataflow-DAG variant: walk the TAINT
engine's DAG between the two anchor findings and only fire when an
executable connection exists. Requires extending TAINT findings to
expose their source / sink coordinates on a cross-document graph;
the v1.0.x TAINT engine carries this state per-workflow but doesn't
yet expose it to the chain engine.

### Pluggable LLM-assisted triage (opt-in, local)

A ``--triage`` flag pipes each finding through a local-only LLM
(Ollama, llama.cpp, LM Studio) plus the surrounding pipeline
snippet, asking for a short "is this actually exploitable in this
repo's context" verdict. Three labels: ``confirmed``,
``needs_review``, ``likely_fp``. Strict no-network default; remote
endpoints require an explicit ``--triage-endpoint URL`` flag.
Output is advisory, never gates the build.

### Cross-scanner comparison benchmark

The ``greylag-ci/cicd-goat`` 38-scenario matrix already tracks
pipeline-check against other scanners per-scenario. A broader
comparison matrix (vs Zizmor / Poutine / Checkov / KICS / Trivy)
across multiple goat repos would earn external credibility. Probably
warrants extraction to a separate ``pipeline-check-bench`` repo.

### ~~Live Azure + GCP cloud-posture parity~~ shipped

Shipped in v1.6.0 (closes #163). Both providers now ship 50 rules
each across identity, network, storage, compute, and logging, with
CIS Azure Foundations and CIS GCP Foundations standards mappings.

### ~~Self-hosted findings-history dashboard~~ shipped

Shipped in v1.6.0 (closes #160). ``pipeline_check history`` renders
posture trends from a directory of ``findings.json`` snapshots, with
per-rule burn-down sparklines, a resource-level heatmap, and fleet
``--output-dir`` recursive loading.

### GitHub Actions dependency locking support

GitHub's 2026 Actions security roadmap introduces a ``dependencies:``
YAML section that locks all direct and transitive action dependencies
by commit SHA (analogous to Go's ``go.sum``). When the feature ships:
a rule flagging workflows missing the section, a rule checking SHA
consistency, and parser support. First-mover advantage: no scanner
currently validates this section.

### SDLC posture graph from fleet data

The fleet scanner and CXPC chain engine already compute cross-repo
relationships. Expose the implied graph as a JSON graph and a
lightweight HTML visualization bundled in the fleet report. This is
what commercial ASPM tools (Cycode, Legit Security, Apiiro) sell as
"pipeline topology." Builds on the fleet phase 2 infrastructure.

### AI agent pipeline risk rules

The HackerBot-Claw campaign (February 2026) demonstrated AI prompt
injection against Claude-based code reviewers in CI. Current
coverage: GHA-058 (agentic CLI with bypass flags / PR-checkout
topology), GHA-103 (AI review bot on untrusted trigger without
environment gate), GHA-104 (AI agent auto-push without PR review).
Remaining gaps: overly permissive AI agent tokens (broader than
GHA-061's App-token scope check), AI-generated IaC changes that
modify security-sensitive resources, multi-step agent chains where
the AI is both the reviewer and the committer.

### ~~Gitea / Forgejo provider~~ shipped

Shipped in v1.6.0. ``--pipeline gitea``
reuses :class:`GitHubContext` and the full GHA rule pack against
``.gitea/workflows/`` and ``.forgejo/workflows/`` directories.

### Secret verifier expansion (phase 3)

Phases 1 and 2 brought verifier count from 9 to 25. Remaining
high-value additions that are blocked on detector or pairing gaps:

- AWS (STS ``GetCallerIdentity``) — needs paired access-key + secret;
  the detector only captures the access-key ID.
- Azure (Microsoft Graph ``/me``) — Azure tokens are opaque JWTs
  without a stable prefix pattern; needs a detector first.
- JFrog — Artifactory Cloud tokens lack a reliable prefix that
  distinguishes them from generic base64; self-hosted instances
  require a user-supplied URL.
- Datadog, PagerDuty — API keys are 32-40 char hex without a
  distinctive prefix; too generic for shape-only detection.
- Twilio — ``SK`` prefix detector exists but verification needs the
  paired auth token (same paired-credential gap as AWS).
- Generic entropy-based detection for tokens from services without
  a dedicated verifier.

### ~~Secrets-in-CI-logs detection~~ shipped

Shipped in v1.6.0. GL-036, BB-032, ADO-031, CC-032 cover GitLab,
Bitbucket, Azure DevOps, and CircleCI; GHA-033 already covered GitHub
Actions. Shared logic in ``_primitives/log_leak.py``.

### ~~GitLab Code Quality output format~~ shipped

Shipped in v1.6.0. See the v1.6.0 entry above.

### Auto-remediation PRs (``pipeline_check fix-pr``)

A subcommand that runs the scan, applies safe fixers, and opens a
PR via ``gh pr create`` / GitLab API. The scanner already computes
unified diffs; this is plumbing. Closes the gap between "patch on
disk" and "PR in your inbox" that drives adoption in orgs that scan
in CI but never act on findings.

### Fixer discoverability (``--list-fixers``)

Surface the 111 autofixers via ``--list-fixers [--safety safe|unsafe
|all]`` so users can discover which rules have fixers, which tier
each belongs to, and why ``--fix`` didn't patch a specific finding.

### Self-hosted runner security rules

Detect workflows that run on ``self-hosted`` without environment
gates, ``runs-on`` labels that accept any contributor's PR with no
branch restriction, and persistent runner tokens without rotation.
Complements GHA-068 (deprecated runner image). StepSecurity's
``harden-runner`` is a runtime agent; these would be static rules.

### ~~Inline explain mode (``--inline-explain``)~~ shipped

Shipped in v1.6.0. The flag uses the ``inline-`` prefix because
``--explain CHECK_ID`` was already taken as an early-exit option.
Renders the rule's ``exploit_example`` (when present) under each
failing finding's panel; recommendation was already inline. See the
v1.6.0 entry above.

### Suppression expiry warnings

``--warn-expiring-suppressions 7d`` surfaces about-to-expire
``.pipelinecheckignore`` entries in stderr before they silently flip
from suppressed to CI-blocking.

### Config-strict mode

``--config-strict`` promotes unknown config keys in
``.pipeline-check.yml`` / ``pyproject.toml`` to hard errors (like
ruff ``--config-strict``). Catches typos in ``fail_on: HIGH``
before they silently disable gating.

### Continuing posture: proof-of-exploit backfill

Every CRITICAL (13) and HIGH (36) rule now carries an
``exploit_example`` after the dev-cycle backfill. New rules at those
severities ship one from the start. MEDIUM and LOW backfill remains
opportunistic and is not a release-blocking milestone.

### Lower priority

- **GitHub App.** Installable GitHub App with persistent webhook-
  driven scanning and checks-API integration. The ``action.yml``
  already ships inline PR review comments, which covers the
  single-repo feedback loop. The App adds persistent config,
  auto-scan on push, and cross-repo dashboards. Revisit if multiple
  users request always-on scanning without workflow setup.
- **SaaS API.** Hosted scan endpoint with auth and history. Scope
  is large (auth, multi-tenancy, history DB) and blurs OSS
  positioning. Revisit if a clear paid-tier story emerges.

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
