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

### Zizmor parity sweep (GHA-063 .. GHA-07x)

Gap analysis against `zizmorcore/zizmor` v1.25.2 (37 audits at time of
review, 2026-05-22). Pipeline-check's 65-rule GHA pack already covers
the majority by direct or near equivalent (e.g., zizmor
``template-injection`` -> GHA-003, ``unpinned-uses`` -> GHA-001,
``hardcoded-container-credentials`` -> GHA-039, ``unpinned-images`` ->
GHA-051, ``self-hosted-runner`` -> GHA-012, ``insecure-commands`` ->
GHA-031 / GHA-038, ``secrets-inherit`` -> GHA-034,
``use-trusted-publishing`` -> GHA-050, ``dangerous-triggers`` ->
GHA-002 / GHA-009, ``github-env`` -> TAINT family, ``artipacked`` ->
GHA-019 / GHA-037, ``github-app`` -> GHA-061).

The items below are the genuine gaps worth chasing. Each lands as one
new GHA-NNN rule (or a widening of an existing one). Pedantic /
ergonomic zizmor audits (``anonymous-definition``,
``undocumented-permissions``, ``concurrency-limits``, ``misfeature``,
``superfluous-actions``) are excluded by design, they don't carry a
real-world exploit shape and chasing them dilutes the
exploit-evidenced posture the rule pack stands on. ``forbidden-uses``
(config-driven allow/deny list of action references) maps to the
existing custom-rule loader and doesn't need a new built-in rule.

**ID-numbering note (2026-05-22).** The IDs in this section are
placeholders, not reservations. The first three sweep batches landed
under sequential numbers (``GHA-063`` through ``GHA-071``) without
matching the original placeholders in this section:

* ``GHA-063`` landed as **bot-conditions** (originally placeholder
  for ref-version-mismatch).
* ``GHA-064`` landed as **unsound-contains** (originally placeholder
  for impostor-commit).
* ``GHA-065`` landed as **zero-width / bidi unicode** (originally
  placeholder for typosquat-uses).
* ``GHA-066`` landed as **upload-artifact wildcard** (originally
  placeholder for archived-uses).
* ``GHA-067`` landed as **cache-sensitive-files** (originally
  placeholder for bot-conditions, now ``GHA-063``).
* ``GHA-068`` landed as **deprecated-runner** (originally placeholder
  for overprovisioned-permissions).
* ``GHA-069`` landed as **orphan id-token: write** (originally
  placeholder for overprovisioned-secrets).
* ``GHA-070`` landed as **ssh-keyscan TOFU** (originally placeholder
  for stale-action-refs).
* ``GHA-071`` landed as **powershell-on-Linux** (originally
  placeholder for unsound-contains, now ``GHA-064``).
* ``GHA-072`` landed as **overprovisioned-secrets** (originally
  placeholder for agentic-actions widening; that widening landed
  as a widening of **GHA-058**, no new ID).
* ``GHA-073`` landed as **unused workflow_call.secrets** (originally
  placeholder for upload-artifact wildcard, now ``GHA-066``).

The struck-through items below are now shipped at the IDs listed
inline. Remaining items keep their original placeholder IDs and
will be renumbered when they land.

Suggested landing order, highest signal first:

- ~~**GHA-063: action SHA pin does not match its version comment.**~~
  Landed as **GHA-095**. ``Workflow.raw_text`` captures the on-disk
  text PyYAML strips comments from; a new
  ``ActionMetadataFetcher.fetch_tag_shas`` resolves each comment-
  mentioned tag via ``/commits/{tag}`` and folds the result into
  ``ActionRepoMetadata.tag_shas``. ``v``-prefix swaps (``v4`` vs
  ``4``) are tried both ways; unresolvable comment tags pass
  silently. HIGH severity. 13 per-rule tests + 11 parser tests +
  6 fetcher tests.
- ~~**GHA-064: action ref points at a commit absent from the claimed
  repository.**~~ Landed as **GHA-090**. Mirrors zizmor's
  ``impostor-commit``. SHA membership check via
  ``/repos/{o}/{r}/commits/{sha}`` gated on ``--resolve-remote``.
  HIGH severity. 8 per-rule tests + 4 fetcher tests.
- ~~**GHA-065: action repository typosquats a high-traffic action.**~~
  Landed as **GHA-088**. Offline Damerau-Levenshtein edit-distance
  check against a curated top-actions list. HIGH severity.
  14 per-rule tests + 13 primitive tests.
- ~~**GHA-066: action repository is archived or deleted upstream.**~~
  Landed as **GHA-089**. Reads the archived bit from the same
  per-action repo fetch the reputation rules use. MEDIUM severity.
  8 per-rule tests.
- ~~**GHA-067: bot-actor condition is spoofable.**~~ Landed as
  **GHA-063**. Fires when a job-level or step-level ``if:``
  expression compares ``github.actor`` /
  ``github.triggering_actor`` / ``github.event.sender.login`` to
  a literal ``*[bot]`` string, or invokes
  ``contains(github.actor, 'bot')`` /
  ``endsWith(github.actor, '[bot]')`` / swap-argument variants.
  Paired ``github.event.*.user.type == 'Bot'`` predicates stay
  silent (account type is set by GitHub and can't be spoofed by
  a re-run). HIGH severity. 11 per-rule tests + safe/unsafe
  fixture pair.
- ~~**GHA-068: job permissions are excessive for the work it performs.**~~
  Landed as a widening of **GHA-004** (no new ID). Top-level write-scope
  aggregation across inheriting jobs: when a workflow-level
  ``permissions:`` block grants a write scope that no inheriting job
  (no job-level override, not a reusable-workflow caller) consumes,
  the rule now flags the excess grant. Per-job overprovisioning was
  already condition 5; this closes the workflow-level gap. 8 new tests
  under ``TestGHA004TopLevelAggregation``.
- ~~**GHA-069: secrets context broader than the consuming step.**~~
  Landed as **GHA-072**. Fires when a job-level ``env:`` entry
  binds ``${{ secrets.* }}`` and at most one step references it,
  OR when a workflow-level ``env:`` binds a secret and at most
  one job references it. HIGH severity. 9 per-rule tests +
  safe/unsafe fixture pair.
- ~~**GHA-070: workflow `uses:` reference is the latest commit on a
  branch.**~~ Landed as **GHA-094**. Fires when a SHA-pinned
  ``uses:`` matches the current tip of a branch in the upstream
  repo. MEDIUM severity. 9 per-rule tests + 4 fetcher tests.
- ~~**GHA-071: contains() called with string-shaped left
  operand.**~~ Landed as **GHA-064**. Fires when an ``if:``
  expression invokes ``contains('<haystack-with-comma>',
  <expr>)`` (either quote style). ``fromJSON('["main", ...]')``
  array-literal forms and no-comma substring searches
  (``contains('refs/heads/release', github.ref)``) stay silent.
  HIGH severity. 8 per-rule tests + safe/unsafe fixture pair.
- ~~**GHA-072: agentic AI tool invoked after PR checkout.**~~ Landed
  as a widening of **GHA-058** (no new ID). Fires when an agentic
  CLI runs after PR-head checkout with write-scope token in scope.
  HIGH severity. 9 new tests under ``TestGHA058PRCheckoutTopology``.
- ~~**GHA-073: actions/upload-artifact wildcard path uploads.**~~
  Landed as **GHA-066**. Fires on the ``**/*`` / ``.`` / ``./`` /
  ``${{ github.workspace }}`` / ``${{ github.workspace }}/**``
  ``path:`` shapes across string / list / multi-line block scalar
  forms. HIGH severity. 10 per-rule tests + safe/unsafe fixture
  pair.
- ~~**GHA-074: workflow caches credential-shaped files.**~~ Landed
  as **GHA-067**. Fires on ``actions/cache`` whose ``path:``
  covers ``~`` (all spellings), ``~/.docker``, ``~/.npmrc``,
  ``~/.aws``, ``~/.azure``, ``~/.gcloud``, ``~/.kube``, ``~/.ssh``,
  ``~/.gnupg``, ``~/.netrc``, ``~/.gradle/gradle.properties``,
  ``~/.m2/settings.xml``. HIGH severity. 12 per-rule tests +
  safe/unsafe fixture pair.
- ~~**GHA-075: shell defaulted to powershell on a Linux / macOS
  step.**~~ Landed as **GHA-071**. Fires when the effective
  shell for a ``run:`` step (step override > job defaults >
  workflow defaults) is ``pwsh`` or ``powershell`` on a non-
  Windows runner. Self-hosted label lists stay silent (OS
  unidentifiable). LOW (advisory) severity. 9 per-rule tests +
  safe/unsafe fixture pair.
- ~~**GHA-076: runs-on uses a deprecated runner image.**~~ Landed
  as **GHA-068**. Fires on ``ubuntu-18.04``, ``ubuntu-20.04``,
  ``macos-10.15``, ``macos-11``, ``macos-12``, ``windows-2016``,
  ``windows-2019`` across string / list / ``labels:`` shapes for
  ``runs-on:``. Self-hosted labels stay silent (GHA-012's
  territory). MEDIUM severity. 10 per-rule tests + safe/unsafe
  fixture pair.
- ~~**GHA-077: known-vulnerable action ref via live GHSA feed.**~~
  Landed as **GHA-096**. Queries the GitHub Advisory Database
  (``GET /advisories?type=reviewed&ecosystem=actions&affects=o/r``)
  for each referenced action. Version matching checks tag-extracted
  versions against each advisory's ``vulnerable_version_range``;
  SHA / major-tag refs fire at MEDIUM confidence. Gated on
  ``--resolve-remote``. HIGH severity. 12 per-rule tests +
  6 fetcher tests + 20 version-range primitive tests.
- ~~**GHA-078: workflow body contains zero-width / bidi
  unicode.**~~ Landed as **GHA-065**. Walks every string value in
  the parsed workflow document for any of 15 suspicious
  codepoints (``U+200B``-``U+200F`` zero-width and bidi marks,
  ``U+202A``-``U+202E`` LRE / RLE / PDF / LRO / RLO,
  ``U+2066``-``U+2069`` LRI / RLI / FSI / PDI, ``U+FEFF`` BOM).
  Any single occurrence fires. CRITICAL severity, the entire
  signal is steganographic. 8 per-rule tests + safe/unsafe
  fixture pair.

Each entry is sized to land as a single PR with the rule module,
per-rule tests, ``docs/providers/github.md`` regeneration, and a
``CHANGELOG.md`` entry. Total provider claim moves from 65 -> 65 + N.
No new attack chains in this sweep, the chain engine already covers
the cross-rule compositions worth firing.

Second pass, drawn from zizmor's open feature-request backlog
(non-``new-audit`` issues with real attack shape):

- ~~**GHA-079: ssh-keyscan trust-on-first-use.**~~ Landed as
  **GHA-070**. Fires on ``ssh-keyscan ... >> known_hosts``,
  ``-o StrictHostKeyChecking=no``, ``-o
  StrictHostKeyChecking=accept-new``, and ``-o
  UserKnownHostsFile=/dev/null`` across ``ssh`` / ``scp`` /
  ``rsync``. HIGH severity. 9 per-rule tests + safe/unsafe
  fixture pair.
- ~~**GHA-080: TOCTOU on PR head SHA between checkout and use.**~~
  Landed as **GHA-092**. Fires when a job captures the PR head SHA
  in one step and checks out the same expression in a later step
  (the force-push race window). HIGH severity. 12 per-rule tests.
- ~~**GHA-081: if predicate over an attacker-controlled PR label,
  title, or body.**~~ Landed as a widening of **GHA-053** (no new
  ID). ``_UNTRUSTED_CONTEXTS`` picked up
  ``github.event.pull_request.labels``,
  ``.milestone.title`` / ``.description``,
  ``.requested_reviewers``, ``.assignees``. The canonical
  ``contains(github.event.pull_request.labels.*.name,
  'safe-to-test')`` foot-gun now fires GHA-053 directly.
- ~~**GHA-082: action `uses:` points at a takeover-eligible org.**~~
  Landed as **GHA-091**. Reads from ``ctx.action_fetch_failures``
  (the set of slugs whose repo fetch returned 404). Unanimous-
  failure heuristic filters rate-limit noise. HIGH severity.
  9 per-rule tests.
- ~~**GHA-083: Living-off-the-Pipeline indicators.**~~ Landed as
  **GHA-093**. Three shapes: STEP_SUMMARY secret exfil, workflow-
  command log injection with attacker-controlled context, and
  mask-after-print ordering. HIGH severity. 15 per-rule tests.
- ~~**GHA-084: orphan `id-token: write` scope.**~~ Landed as
  **GHA-069**. Fires when a job effectively holds
  ``id-token: write`` (job-level, workflow-inherited, or
  ``permissions: write-all``) but no step invokes a known OIDC
  consumer (curated list covering cloud-credentials, trusted-
  publishing, and Sigstore signing actions; plus the conditional
  ``docker/build-push-action`` with ``provenance:`` / ``sbom:`` /
  ``attestations:`` truthy). MEDIUM severity. 11 per-rule tests +
  safe/unsafe fixture pair.
- ~~**GHA-085: workflow declares a secret it never references.**~~
  Landed as **GHA-073**. Fires when an ``on.workflow_call.
  secrets.<name>`` declaration is never referenced via
  ``${{ secrets.<name> }}`` anywhere in the workflow body. MEDIUM
  severity. 8 per-rule tests + safe/unsafe fixture pair.

Two existing-rule widenings worth bundling into the same sweep:

- ~~**Widen GHA-003 to ``services.*.options:`` and
  ``services.*.env:``.**~~ Landed in v1.4.0. Both YAML paths now
  flagged for script-injection sinks. 3 new tests.
- ~~**Widen GHA-050 to "attestation explicitly disabled."**~~ Landed
  in v1.4.0. Fires on ``pypa/gh-action-pypi-publish`` with
  ``attestations: false`` and ``docker/build-push-action`` with
  ``provenance: false`` / ``sbom: false`` / ``attestations: false``.
  5 new tests.

One CLI ergonomics item:

- ~~**``--only-known-attacked`` filter.**~~ Landed in v1.4.0.
  Filters rule set to rules with ``Rule.incident_refs`` non-empty.
  Composes with ``--checks`` via intersection.

Out of scope from zizmor that we explicitly decline:

- ``anonymous-definition`` / ``undocumented-permissions`` / pedantic
  persona. Pipeline-check has no pedantic mode and isn't adding one,
  the no-pedantic posture is part of why the false-positive rate
  stays where it is.
- ``concurrency-limits``. CI ergonomics, not security.
- ``misfeature``. Too vague to map to a rule with a
  ``recommendation`` line that survives review.
- ``superfluous-actions``. Build-speed concern dressed as a security
  rule, the runner pre-installing ``node`` doesn't change the threat
  model when you ``setup-node`` to pin a version.
- ``forbidden-uses``. Already expressible through the custom-rule
  YAML loader, a built-in flavor would duplicate that surface.

### cicd-goat scenario coverage push

Gap analysis against `greylag-ci/cicd-goat`'s 29-scenario matrix.
**Status: 29 of 29 (100%) coverage.** Every scenario in the matrix
now has at least one pipeline-check rule mapped in
``tools/scenarios.yaml``. The comparison shipped across v1.3.0
through v1.4.0; the final gaps closed with GHA-086 (scenario 25),
GHA-087 (scenario 27), and the multi-provider invocations for
scenarios 11 / 20 / 29.

The items below document the work that closed the gap (all shipped).

- ~~**Local composite-action scanning (scenario 18).**~~ Landed.
  ``GitHubContext.from_path`` walks every loaded workflow for
  ``uses: ./path`` (``parse_uses`` ``kind="local-action"``),
  resolves ``<repo_root>/<path>/action.yml`` (or ``action.yaml``)
  on disk via a new ``checks/github/local_actions.py`` module, and
  synthesizes the body as a ``__composite__`` job that flows back
  through the existing rule pack the same way remote composites do
  under ``--resolve-remote``. On by default (no network call). Repo-
  root inference handles the canonical ``.github/workflows`` layout
  plus an ad-hoc-directory fallback; ``./../path`` traversal is
  bounded against the resolved repo root; missing ``action.yml``
  files dedup-warn; composite-of-composite chains recurse to depth
  3 (hard ceiling 10). Closes cicd-goat scenario 18 (GHA-003 fires
  on the composite step's ``${{ inputs.message }}`` -> ``run:``
  splice). Side-effect: every existing ``runs.steps``-shaped rule
  (GHA-001 / GHA-004 / GHA-039 / GHA-051 / ...) now applies to
  composite bodies without per-rule changes. Twelve tests under
  ``tests/github/test_local_composite_actions.py``.
- ~~**TAINT-003: cross-``workflow_call`` source -> sink (scenario 28).**~~
  Already shipped, missed in the initial roadmap analysis.
  ``rules/taint003_reusable_workflow_taint.py`` walks every
  ``jobs.<id>.uses: <callee>`` reference, finds tainted ``with:``
  values that interpolate an attacker-controllable source, and
  resolves the callee body when it's loaded into the same scan
  (local ``./.github/workflows/<file>.yml`` references via
  ``--gha-path``, or remote refs fetched via ``--resolve-remote``).
  Paths whose callee actually consumes ``${{ inputs.<name> }}``
  unquoted in a sink fire CONFIRMED with HIGH confidence; the rest
  stay at MEDIUM. Verified end-to-end against cicd-goat scenario
  28's exact shape (``github.event.pull_request.body`` -> ``with:
  build-args:`` -> callee's ``./build.sh ${{ inputs.build-args }}``):
  the rule fires CONFIRMED + HIGH confidence in one step. The
  scenario-18 local-composite-action work above means the same
  ``with:`` -> ``inputs.<name>`` -> ``run:`` boundary now also
  applies to composite ``action.yml`` bodies discovered on disk.
- ~~**GHA-NNN: wildcard branch trigger + environment binding
  (scenario 25).**~~ Landed as **GHA-086**. Fires when the
  workflow's ``on: push: branches:`` filter contains at least one
  wildcard pattern (``*``, ``?``, ``+``, ``[...]``) AND at least
  one job binds ``environment: <name>``. ``branches-ignore``
  (restricts triggers) and ``tags:`` (higher-privilege creation)
  are deliberately not flagged. MEDIUM severity. Skips into
  ID 086 to leave GHA-063..085 available for the Zizmor parity
  sweep above; the cicd-goat pack will fill back from 086 as
  its remaining items land. 14 per-rule tests plus the standard
  safe/unsafe fixture pair. Mapped to OWASP CICD-SEC-1 /
  CICD-SEC-5; ESF-C-APPROVAL / ESF-C-ENV-SEP; CIS 5.1.4 / 5.2.1.
- ~~**GHA-NNN: secret-derivation echo (scenario 27 derived-value
  half).**~~ Landed as **GHA-087**. Fires on a single ``run:``
  line that combines (1) a secret reference (``${{ secrets.* }}``
  context, or ``$NAME``/``${NAME}`` expansion of a step ``env:``
  bound to ``secrets.*``); (2) a transform on that reference
  (hash / encode / truncate / bash slice); (3) a print sink on
  the same line (``echo`` / ``printf`` / ``tee`` head, or
  redirect to ``$GITHUB_OUTPUT`` / ``$GITHUB_STEP_SUMMARY`` / a
  file). HIGH severity. GHA-033's recommendation was tightened
  in the same cycle to drop the "log a fingerprint" suggestion
  that GHA-087 now flags. 15 per-rule tests plus the standard
  safe/unsafe fixture pair. Mapped to OWASP CICD-SEC-10 /
  CICD-SEC-6; ESF-D-SECRETS; CIS 2.3.7; NIST 800-53 IA-5 / AU-9;
  NIST CSF PR.AA-01 / PR.DS-01; SOC2 CC6.1; PCI-DSS v4 8.2.1 /
  10.3.2.

The remaining scenarios that were ❌ at time of review are now
all resolved:

- Scenarios 10 / 22 (AWS / GCP OIDC over-broad trust) -> GHA-062.
- Scenarios 11 / 20 / 29 (pip-no-hashes / dependency confusion /
  npm lifecycle script) -> GHA-060 / NPM-001 / NPM-004 via
  multi-provider invocation (``--pipeline npm,pypi``).
- Scenarios 17 / 21 / 26 (ArtiPACKED / matrix expansion /
  app-token scope) -> GHA-019 + GHA-037 / TAINT-002 / GHA-061.

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

### ~~Inline source-line ignore comments~~

Landed. Three directive variants: ``ignore[ID]`` (same line),
``ignore-next-line[ID]`` (following line), and ``ignore-file[ID]``
(entire file). Multiple IDs are comma-separated. An optional
``reason=<text>`` suffix is captured for audit trails. Both ``#``
and ``//`` comment prefixes are recognized (YAML, Dockerfile, HCL,
Groovy). Pre-parse regex extraction runs on the raw file content
before YAML parsers strip comments, then feeds through the same
``core/gate.py`` plumbing as ``--ignore-file``. Disabled via
``--no-inline-ignore``. 23 tests under
``tests/test_inline_ignore.py``.

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

### ~~Autofix safety tiers (`--fix=safe` default, `--fix=unsafe` opt-in)~~

Landed. Every ``@register()`` call carries ``safety="safe"`` or
``safety="unsafe"``. ``--fix`` (bare flag) runs safe fixers only;
``--fix=unsafe`` runs both; ``--fix=unsafe-only`` runs only unsafe.
109 fixers labeled safe, 2 labeled unsafe (GHA-003 template-injection
env-var extraction, GHA-034 secrets-inherit rewrite). Missing labels
default to unsafe so new fixers without a label are conservative.
``tests/test_autofix_safety.py`` enforces every fixer has an explicit
label. 9 new tests.

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

### ~~Direct-HCL Terraform parsing (no `--tf-plan` requirement)~~

Landed. ``--tf-source <dir>`` parses ``*.tf`` files directly via
``python-hcl2`` (behind the ``[hcl]`` install extra) and synthesizes
the same ``TerraformResource`` objects the plan-JSON path produces,
so all 58 existing TF-NNN rules run unchanged. Variable and local
substitution is best-effort: ``variable`` blocks with a ``default``
and ``locals`` blocks with literal values resolve; unresolvable
``var.<name>`` / ``module.X.output.Y`` / ``data.<x>.<y>`` references
stay as opaque ``${...}`` strings and findings on those resources get
confidence-demoted one rung (HIGH -> MEDIUM, MEDIUM -> LOW). Local
child modules (``source = "./..."`` / ``"../..."``) are walked
recursively to depth 3; remote registry modules are skipped. The
plan-JSON path stays canonical (``--tf-plan`` keeps its semantics);
``main.tf`` presence auto-detects to ``--tf-source .`` when no
``--tf-plan`` is provided. Closes the ``terragoat`` skip in
``bench/goats/``. 23 new tests under
``tests/terraform/test_hcl_parser.py``.

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

~~One gap remains: ``rootProject.ext.X`` cross-project indirection
on Gradle multi-project layouts. Would need pipeline-check to
learn ``settings.gradle`` resolution. Rarer in practice than the
three Gradle shapes already shipped; deferred.~~ Landed
post-1.3.0: the maven provider now walks upward from each
``build.gradle`` looking for ``settings.gradle`` /
``settings.gradle.kts`` to identify the multi-project root, reads
that root's build script for ``ext { X = ... }`` declarations, and
exposes them through both ``rootProject.ext.X`` and
``rootProject.X`` accessor keys so a subproject's version-spec
interpolation resolves. See Shipped.

~~Next: the XPC-NNN chain engine gains chains pairing NPM-008
cooldown-miss with DF-024 lifecycle-scripts-enabled so the
composite escalates when both gates fail in the same scan.~~
Landed as XPC-010 (see Shipped).

Next, paired:

- ~~**Live OSV / GHSA lookup for pinned dep versions (NPM-010 /
  PYPI-009 / MVN-009 / NUGET-009).**~~ Landed. Shared
  ``_primitives/osv_fetcher.py`` queries the OSV batch API
  (``api.osv.dev/v1/querybatch``) for every exact name+version
  pair behind ``--resolve-remote``. Results cached 24 hours via
  ``FileSystemCache``. Four new rules: NPM-010, PYPI-009,
  MVN-009, NUGET-009, all CRITICAL severity on advisory hit.
  Batch size 1000 per request to handle large dependency trees.

- ~~**NuGet provider (``--pipeline nuget``).**~~ Landed. Fifth
  dependency-supply-chain provider. Parses ``*.csproj``
  (``<PackageReference>``), ``Directory.Packages.props`` (central
  package management), ``packages.config`` (legacy),
  ``NuGet.config`` (sources + ``packageSourceMapping``), and
  ``packages.lock.json``. Nine rules (NUGET-001..009): floating
  ranges, wildcard prereleases, missing versions, HTTP sources,
  compromised versions, missing lockfile, missing source mapping,
  cooldown gate, and OSV advisory lookup. Provider count 23 -> 24.
  22 tests under ``tests/nuget/``.

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

## Bug backlog (2026-05-25 audit)

Confirmed bugs from a full-codebase review. Ordered by severity
(crash first, then wrong-result by blast radius, then minor).
Each item is standalone and can land as its own commit.

### Crash

- **CFN `resolve_literal` infinite recursion on circular `Ref`.**
  `cloudformation/base.py:resolve_literal` recursively resolves
  `{"Ref": "ParamName"}` against `params[inner]`. A malformed
  template with `Parameters: { A: { Default: { Ref: A } } }` (or
  a two-step chain) triggers unbounded recursion and a
  `RecursionError` that propagates to the scanner. Callers in
  `phase4.py` do not catch it. Fix: add a `seen` set and bail on
  cycles.

- **Fleet scanner passes non-existent `--no-color` flag.**
  `fleet.py:_scan_repo` (line 506) includes `"--no-color"` in the
  subprocess command but the CLI's `scan` command has no such
  option. Click rejects it immediately, so every fleet sub-scan
  fails with a usage error and no `findings.json` is produced.
  Fix: remove the flag or add the corresponding Click option.

### Wrong result (high impact)

- **`--quiet` suppresses file output, autofix, and all reporters.**
  `cli.py` (line 3070) gates the entire report-output block
  behind `if not quiet:`. When `--quiet` is active,
  `--output sarif --output-file results.sarif` writes no file,
  `--output json --output-file results.json` writes no file, and
  `--fix --apply` does not apply fixes. A CI lane relying on
  `--quiet --output sarif --output-file` silently produces no
  artifact. Fix: move file-write and autofix logic outside the
  `if not quiet:` guard; only suppress terminal/stderr output.

- **CC-031 OIDC parameter names use underscores, real configs use
  hyphens.** `cc031_oidc_trust.py:_OIDC_ROLE_PARAMS` lists
  `role_arn`, `aws_role_arn`, etc. but CircleCI orbs use
  `role-arn`, `aws-role-arn` (the rule's own `exploit_example`
  shows the hyphenated form). `_has_oidc_role_param` does
  `p in job_cfg` against a dict whose keys use hyphens, so the
  match never succeeds and the rule never fires on real configs.
  Fix: change the param set to use hyphens.

- **OSV `_extract_severity` does not recognize `"MODERATE"`.**
  `osv_fetcher.py:_extract_severity` accepts `CRITICAL`, `HIGH`,
  `MEDIUM`, `LOW` from `database_specific.severity` but GitHub
  Advisory Database uses `"MODERATE"` (not `"MEDIUM"`). When
  the advisory has `"severity": "MODERATE"`, the match fails and
  the function defaults to `"HIGH"`. Fix: map `"MODERATE"` to
  `"MEDIUM"`.

- **GL-012 misses `cache:` in list form.** `gl012_cache_key.py`
  `_scan_cache` starts with `if not isinstance(cache, dict):
  return`, so it only handles the dict form. Since GitLab CI
  v14.2, `cache:` can be a list of cache configs. When cache is
  a list, the function returns early without scanning any entry.
  Fix: iterate list elements, scanning each as a dict.

- **GL-012 misses `default.cache:`.**  The rule scans
  `doc.get("cache")` (top-level) and per-job `job.get("cache")`
  but not `default: { cache: { key: ... } }`, which is valid
  GitLab CI syntax for setting a default cache across all jobs.
  Fix: scan `doc.get("default", {}).get("cache")`.

### Wrong result (medium impact)

- **GHA-053 / GHA-052 substring matching causes false positives.**
  Both `_matches_untrusted` functions use Python's `in` operator.
  Untrusted strings like `"github.event.pull_request.labels"` are
  substrings of safe fields like `labels_url` and `assignees_url`.
  Fix: match on word boundaries or use a regex.

- **`CACHE_TAINT_RE` uses `page` instead of `pages` in GHA
  helpers.** `_helpers.py` line 78 uses singular `page\.` in the
  event-type alternation, but the GitHub webhook field is `pages`
  (plural, used by `page_build` events). A cache key containing
  `${{ github.event.pages[0].title }}` is missed. Fix: change
  `page` to `pages` in the regex.

- **`_DEP_UPDATE_TOOL_EXEMPT_RE` does not handle reversed argument
  order.** `base.py` exemption regex
  `\bpip3?\s+install\s+(?:--upgrade|-U)\s+(?:pip|setuptools|...)`
  requires `--upgrade` before the package name. But pip accepts
  both orders (`pip install pip --upgrade`). The reversed form
  is caught by `DEP_UPDATE_RE` but missed by the exemption,
  producing a false positive. Fix: add an alternation for the
  reversed order.

- **TKN-003 false positive on non-first `$(params.X)` in quoted
  strings.** `tkn003_param_injection.py` regex
  `(?<!")$(params.[A-Za-z0-9_-]+)` uses a single-char negative
  lookbehind. In `echo "$(params.a) $(params.b)"`, only the first
  ref is suppressed; the second fires even though it's equally safe
  (inside double quotes). Fix: use a more robust quoting analysis.

- **`_coerce_env` does not split multi-value env vars for
  `helm_values`, `helm_set`, `gha_search_path`.** `config.py`
  `_coerce_env` splits comma-separated values for `checks`,
  `standards`, etc. but not for `helm_values`, `helm_set`, or
  `gha_search_path` (all `multiple=True` click options). Setting
  `PIPELINE_CHECK_HELM_VALUES=a.yaml,b.yaml` produces one string
  instead of a tuple of two paths. Fix: add these keys to the
  split logic.

- **`_yaml_lines.py` `_LineLoader` missing `flatten_mapping`.**
  The line-tracking loader's `construct_mapping` omits
  `self.flatten_mapping(node)`, so YAML merge keys (`<<:
  *anchor`) trigger a `ConstructorError`. All callers catch
  `yaml.YAMLError` and skip the file, so entire files using merge
  keys (common in GitLab CI, Drone, Kubernetes) are silently
  dropped from the scan. Fix: add `self.flatten_mapping(node)`
  before the key iteration loop.

### Wrong result (minor)

- **`is_quoted_assignment` regex fails on nested `}` in GitHub
  expressions.** `base.py:_QUOTED_ASSIGNMENT_RE` uses `[^}]*` to
  match `${{ ... }}` expressions, stopping at the first `}`. An
  expression like `${{ format('{0}', github.ref) }}` is not
  recognized as a quoted assignment, causing false positives. Minor
  because `format()` inside variable assignments is uncommon.

- **GitLab `_NON_JOB_KEYS` includes `"script"`, missing
  `"pages"`.** `gitlab/_taint_graph.py` `_NON_JOB_KEYS` lists
  `"script"` (not a valid GitLab CI top-level keyword) and
  omits `"pages"` (a reserved top-level keyword). A job named
  `script` would be excluded from taint analysis; a `pages:`
  block could be incorrectly included.

- **GL-033 line number always defaults to 1.**
  `gl033_global_script_taint.py` uses `_line_of(block) if
  isinstance(block, dict) else 1`, but `before_script` /
  `after_script` values are always lists, never dicts. The
  condition is always False, so line is always 1 instead of the
  actual source line. Fix: call `_line_of(block)` unconditionally,
  falling back to 1 if it returns None.

- **NuGet `_parse_lock_json` crashes on non-dict JSON.**
  `nuget/base.py:_parse_lock_json` calls `data.get(...)` without
  checking that `data` is a dict. A lock file containing `null`,
  `[]`, or a scalar causes an `AttributeError`. Caught by the
  broad `except Exception` in `NuGetContext.from_path`, so no
  tool crash, but error message is misleading. Fix: guard with
  `isinstance(data, dict)`.

- **AC-009 narrative prose mislabels GHA-002 as script injection.**
  `ac009_supply_chain_repo_poisoning.py` lines 27 and 114 describe
  GHA-003's behavior ("interpolates PR-controlled context into a
  `run:` block") but attribute it to GHA-002. The match logic is
  correct; the user-facing narrative is factually wrong about what
  GHA-002 detects. Fix: update the prose to describe GHA-002
  accurately (PR-head checkout on `pull_request_target`).

- **Chain engine sort uses alphabetical severity ordering.**
  `chains/engine.py` line 90 sorts by `c.severity.value` (a string),
  producing alphabetical order (CRITICAL < HIGH < INFO < LOW <
  MEDIUM) instead of rank order. Latent: currently all instances of
  a chain share the same severity, so the bug doesn't manifest. Fix:
  sort by a numeric rank.

- **SARIF `rank` field placed on `result` object (spec violation).**
  `sarif_reporter.py` line 499 puts `"rank"` directly on the SARIF
  `result` object. SARIF 2.1.0 defines `rank` on
  `reportingDescriptor` (rule), not `result`. The schema sets
  `additionalProperties: false` on `result`, so strict validators
  reject the output. Fix: move into `result.properties` bag.

- **SARIF `help.text` can be empty string (spec violation).**
  `sarif_reporter.py` line 423 emits `f.recommendation` as
  `help.text`. Custom rules that omit `recommendation` produce
  `""`, violating the spec (section 3.12.3 requires non-empty
  `multiformatMessageString.text`). Fix: fall back to `f.title`
  when recommendation is empty.

- **SARIF fingerprint instability across platforms.**
  `sarif_reporter.py` `_normalize_path` lowercases paths on Windows
  but not on Linux/macOS. A mixed-case workflow file produces
  different fingerprint hashes on each platform. Teams running CI
  on Linux and local dev on Windows see findings flip-flop as
  distinct alerts. Fix: always lowercase (or never).

- **SARIF `_artifact_uri` does not percent-encode spaces.**
  `sarif_reporter.py` line 667 does `resource.replace("\\", "/")`
  but does not URI-encode spaces or reserved characters (`#`, `?`).
  Files with spaces in the name produce invalid URI-references.
  Fix: use `urllib.parse.quote(..., safe="/")`.

- **PR diff reporter does not escape backticks in resource names.**
  `pr_diff_reporter.py` line 52 wraps the resource in backticks
  without escaping embedded backticks. A resource containing `` ` ``
  breaks the Markdown inline code span. Minor/cosmetic.

- **GHA-002 fixer creates duplicate `with:` key.** `autofix/_impl.py`
  line 87: when any key sits between `uses:` and `with:` (e.g.,
  `if:`, `env:`), the regex misses the existing `with:` block and
  inserts a new one, creating duplicate YAML keys. The
  `_roundtrip_safe` check does not catch this. Fix: scan forward
  past intervening keys to find existing `with:`.

- **GHA-003 fixer creates duplicate `env:` key.** `autofix/_impl.py`
  line 837: env-var indirection inserts a new `env:` block without
  checking if the step already has one. Same duplicate-key issue as
  GHA-002; the injected env var is silently lost by YAML parsers.
  Fix: detect existing `env:` and merge into it.

- **File-wide idempotency markers suppress unfixed occurrences.**
  Multiple comment-only fixers (K8S-001, DF-001, GHA-034, etc.)
  use `if MARKER in content: return None` for the entire file. If
  one occurrence is already annotated, the fixer skips the rest.
  Fix: use per-match dedup (the `_todo_already_above` pattern from
  `helm.py`).

- **`_scan_for_key` matches keyword at any nesting depth.**
  `autofix/_impl.py` line 354: scans all lines deeper than
  `parent_indent` for the keyword. A deeply nested key (e.g.,
  `timeoutInMinutes` inside a step's `inputs:`) is incorrectly
  treated as job-level, causing the fixer to skip insertion. Fix:
  constrain to lines at exactly `parent_indent + 2` (direct
  children).

- **GHA-067 misses `$HOME/` prefix variants for sensitive paths.**
  `gha067_cache_sensitive_paths.py` line 130: `_SENSITIVE_PATHS`
  includes `~/.aws`, `~/.docker`, etc. and standalone `$HOME` /
  `${HOME}` but not the combined `$HOME/.aws`, `${HOME}/.docker`
  forms. A cache `path: "$HOME/.ssh"` escapes detection. Fix: add
  `$HOME/` and `${HOME}/` prefixed variants for each sensitive
  subdirectory.

- **GHA-062 module-level `_IAC_SCAN_CACHE` never cleared.**
  `gha062_oidc_iac_subject.py` line 166: the dict persists across
  invocations in long-running processes (LSP server). If files
  change between scans within the same process, stale results are
  returned. Not a problem for CLI mode. Fix: add a
  `clear_iac_scan_cache()` call in the scanner teardown path, or
  use a bounded LRU with mtime checks.

### Taint engine detection gaps

- **Step/needs output refs with `||` operator missed.** Taint graph
  `_STEP_OUTPUT_REF_RE` and `_NEEDS_OUTPUT_REF_RE` (lines 144,
  162) require `\s*}}` immediately after the output name. Refs
  using `${{ steps.x.outputs.y || '' }}` (common defensive
  pattern) are invisible to the consumer pass. Fix: allow
  `[^}]*\}\}` or stop at the output name boundary.

- **Matrix axis refs with operators missed.** Same issue as above:
  `_MATRIX_AXIS_REF_RE` (line 186) requires `\s*}}` immediately
  after the axis name. `${{ matrix.target || 'staging' }}` and
  `${{ format('{0}', matrix.target) }}` escape detection.

- **`UNTRUSTED_CONTEXT_RE` missing `review_comment.body`.**
  `_helpers.py` line 51 covers `review.body` but not
  `review_comment.body` (separate webhook payload field, equally
  attacker-controllable). GHA-053 correctly includes it in its own
  tuple, creating an inconsistency: GHA-003 and the taint engine
  miss this source. Fix: add `review_comment` to the regex.

- **`_GITHUB_OUTPUT_WRITE_RE` misses `echo` with flags.**
  `_taint_graph.py` line 102: regex expects `echo\s+["']?<name>=`
  immediately. `echo -n "title=..."` (suppress newline, common
  idiom) is not matched; tainted output writes go undetected.
  Fix: allow optional flags `(?:-[neE]+\s+)*` after `echo`.

- **`_GITHUB_OUTPUT_WRITE_RE` only matches `>>` (append).**
  `_taint_graph.py` line 107: requires `>>` but a single `>`
  redirect to `$GITHUB_OUTPUT` also works. Minor since `>` is
  rare (documentation always shows `>>`). Fix: change to `>>?`.

- **`UNTRUSTED_CONTEXT_RE` missing `github.event.commits[*]`.**
  `_helpers.py` covers `head_commit.message` / `.author.name` /
  `.email` but not the `commits[]` array on push events. Every
  commit in the array has attacker-controllable `message`,
  `author.name`, and `author.email` fields. Fix: add
  `commits(?:\[\d+\])?\.(?:message|author\.(?:name|email))` to
  the regex.

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
- ~~**Lift provider context loaders + base classes.**~~ Both
  halves landed. Load-loop consolidation: `checks/_yaml_files.py:
  load_yaml_files` hosts the read + parse + warning loop, and 11
  providers (github, gitlab, bitbucket, azure, cloudbuild,
  kubernetes, buildkite, drone, tekton, argo, circleci) route
  through it. ``jenkins`` parses Groovy, not YAML, and stays on
  its custom loader. ``BaseCheck`` generic-on-context: ``BaseCheck``
  is now ``Generic[_ContextT]`` and each provider's subclass
  parameterizes it (``GitHubBaseCheck(BaseCheck[GitHubContext])``,
  ``AWSBaseCheck(BaseCheck[boto3.Session])``, ...), so
  ``self.context`` carries the concrete type and the per-subclass
  ``self.ctx`` alias is now redundant for type-narrowing purposes.
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
- ~~**Mark fixture Dockerfiles / workflows as Scorecard-exempt.**~~
  Landed. ``scorecard.yml`` gained a SARIF-filtering step that
  strips results whose ``artifactLocation.uri`` starts with
  ``tests/`` or ``bench/`` before upload, so negative test cases
  no longer produce PinnedDependenciesID noise in the Security tab.
- ~~**`master` branch protection** (Scorecard `BranchProtectionID`).~~
  Landed. Required reviewers (1), required status checks
  (``test (3.12)``, ``test (3.13)``), stale-review dismissal,
  no force-push, no deletion.

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
