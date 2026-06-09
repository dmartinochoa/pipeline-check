"""OpenSSF Scorecard v5. CI/CD posture checks.

Scorecard is a set of automated checks that score open-source projects
on supply-chain posture. Many of its checks. Dangerous-Workflow,
Pinned-Dependencies, Token-Permissions, Signed-Releases, SBOM,
Vulnerabilities, Dependency-Update-Tool, are exactly the signals this
scanner already produces from pipeline config, so the mapping is
largely 1:1.

Scorecard checks we do NOT evidence (require repo/registry introspection
outside this scanner's scope):
  Binary-Artifacts, CI-Tests, CII-Best-Practices, Contributors,
  Fuzzing, License, Maintained, Packaging, Security-Policy, Webhooks.

Branch-Protection is now evidenced directly by the SCM provider's
``SCM-001`` / ``SCM-002`` / ``SCM-006`` / ``SCM-007`` / ``SCM-008``
rules, which read the GitHub REST API's ``branches/.../protection``
endpoint. ``Code-Review`` upgrades from "partially evidenced" to
"evidenced" via ``SCM-002``. ``SAST`` adds ``SCM-003`` (default
code scanning) to the registry/build-side vulnerability scanning
already covered. ``Dependency-Update-Tool`` and ``Vulnerabilities``
are evidenced by ``SCM-005`` (Dependabot security updates).
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="openssf_scorecard",
    title="OpenSSF Scorecard",
    version="5",
    url="https://github.com/ossf/scorecard/blob/main/docs/checks.md",
    controls={
        "Branch-Protection": (
            "Default branch is protected against force-push, "
            "deletion, and direct push without review"
        ),
        "Code-Review":            "Changes merged to the default branch require review",
        "Dangerous-Workflow":     "No dangerous patterns in CI workflows (untrusted checkout, script injection)",
        "Dependency-Update-Tool": "Project uses an automated dependency-update tool (Dependabot / Renovate)",
        "Pinned-Dependencies": (
            "Dependencies (actions, images, includes, packages) are "
            "pinned to immutable references from trusted sources"
        ),
        "SAST":                   "Project uses static analysis / vulnerability scanning",
        "SBOM":                   "Releases publish a software bill of materials",
        "Signed-Releases":        "Release artifacts are cryptographically signed",
        "Token-Permissions":      "CI tokens are scoped to the minimum required permissions",
        "Vulnerabilities":        "Project scans for and resolves known vulnerabilities",
    },
    mappings={
        # ── Pinned-Dependencies ──────────────────────────────────────
        "CB-005":   ["Pinned-Dependencies"],
        "CB-009":   ["Pinned-Dependencies"],
        "ECR-002":  ["Pinned-Dependencies"],
        "ECR-006":  ["Pinned-Dependencies"],                           # ECR pull-through untrusted upstream
        "CA-002":   ["Pinned-Dependencies"],                           # CodeArtifact public upstream
        "GHA-001":  ["Pinned-Dependencies"],
        "GHA-110": ["Pinned-Dependencies"],  # CI env disables Go module verification
        "GHA-040":  ["Pinned-Dependencies"],                           # known-compromised action ref
        "GHA-018":  ["Pinned-Dependencies"],                           # insecure package registry
        "GHA-025":  ["Pinned-Dependencies"],
        "GHA-088":  ["Pinned-Dependencies"],                           # typosquat uses
        "GHA-089":  ["Pinned-Dependencies"],                           # archived upstream
        "GHA-090":  ["Pinned-Dependencies"],                           # impostor-commit
        "GHA-091":  ["Pinned-Dependencies"],                           # repojacking
        "GHA-092":  ["Dangerous-Workflow"],                            # TOCTOU PR head SHA
        "GHA-093":  ["Dangerous-Workflow"],                            # LOTP indicators (workflow-command abuse)
        "GHA-094":  ["Pinned-Dependencies"],                           # stale-action-refs
        "GHA-096":  ["Pinned-Dependencies"],                           # known-vulnerable action ref (GHSA)
        "GL-001":   ["Pinned-Dependencies"],
        "GL-037": ["Pinned-Dependencies"],  # CI env disables Go module verification
        "GL-005":   ["Pinned-Dependencies"],
        "GL-042":   ["Pinned-Dependencies"],    # include: component unpinned
        "GL-009":   ["Pinned-Dependencies"],
        "GL-018":   ["Pinned-Dependencies"],
        "GL-028":   ["Pinned-Dependencies"],
        "GL-030":   ["Pinned-Dependencies"],
        "BB-001":   ["Pinned-Dependencies"],
        "BB-009":   ["Pinned-Dependencies"],
        "BB-014":   ["Pinned-Dependencies"],
        "ADO-001":  ["Pinned-Dependencies"],
        "ADO-005":  ["Pinned-Dependencies"],
        "ADO-009":  ["Pinned-Dependencies"],
        "ADO-018":  ["Pinned-Dependencies"],
        "ADO-025":  ["Pinned-Dependencies"],
        "JF-001":   ["Pinned-Dependencies"],
        "JF-009":   ["Pinned-Dependencies"],
        "JF-018":   ["Pinned-Dependencies"],
        "CC-001":   ["Pinned-Dependencies"],
        "CC-033": ["Pinned-Dependencies"],  # CI env disables Go module verification
        "CC-003":   ["Pinned-Dependencies"],
        "CC-018":   ["Pinned-Dependencies"],
        "CC-029":   ["Pinned-Dependencies"],
        "GCB-001":  ["Pinned-Dependencies"],
        # Lockfile-integrity rules: package-source bypass of the lockfile
        # is a form of unpinned dependency ingestion.
        "GHA-021":  ["Pinned-Dependencies"],
        "GHA-029":  ["Pinned-Dependencies"],
        "GL-021":   ["Pinned-Dependencies"],
        "GL-027":   ["Pinned-Dependencies"],
        "BB-021":   ["Pinned-Dependencies"],
        "BB-027":   ["Pinned-Dependencies"],
        "ADO-021":  ["Pinned-Dependencies"],
        "ADO-028":  ["Pinned-Dependencies"],
        "JF-021":   ["Pinned-Dependencies"],
        "JF-031":   ["Pinned-Dependencies"],
        "CC-021":   ["Pinned-Dependencies"],
        "CC-028":   ["Pinned-Dependencies"],
        "BK-014":   ["Pinned-Dependencies"],                           # bk lockfile-bypass / insecure pkg install
        "TKN-014":  ["Pinned-Dependencies"],                           # tkn lockfile-bypass / insecure pkg install
        "ARGO-014": ["Pinned-Dependencies"],                           # argo lockfile-bypass / insecure pkg install
        "DR-010":   ["Pinned-Dependencies"],                           # drone lockfile-bypass / insecure pkg install
        # NPM / PyPI / Maven manifest static analysis. Scorecard's
        # Pinned-Dependencies covers "actions, images, includes, and
        # packages" — these are the package-leg failures: floating
        # range, no integrity hash, mutable VCS ref, non-registry
        # source, dep-confusion mirror, compromised version.
        "NPM-001":  ["Pinned-Dependencies"],                           # floating range in package.json
        "NPM-002":  ["Pinned-Dependencies"],                           # lock entry missing integrity
        "NPM-003":  ["Pinned-Dependencies"],                           # non-registry source (git/path/tarball)
        "NPM-005":  ["Pinned-Dependencies"],                           # git dep with mutable ref
        "NPM-006":  ["Pinned-Dependencies", "Vulnerabilities"],        # compromised npm version
        "PYPI-001": ["Pinned-Dependencies"],                           # requirements lacks ==pin
        "PYPI-002": ["Pinned-Dependencies"],                           # hash pinning missing
        "PYPI-003": ["Pinned-Dependencies"],                           # http index / --trusted-host
        "PYPI-018": ["Pinned-Dependencies"],  # --no-binary forces sdist build
        "PYPI-004": ["Pinned-Dependencies"],                           # VCS dep without commit SHA
        "PYPI-015": ["Pinned-Dependencies"],  # direct artifact URL
        "PYPI-005": ["Pinned-Dependencies"],                           # --extra-index-url (dep confusion)
        "PYPI-017": ["Pinned-Dependencies"],  # remote --find-links
        "PYPI-016": ["Pinned-Dependencies"],  # primary index repointed
        "PYPI-006": ["Pinned-Dependencies", "Vulnerabilities"],        # compromised PyPI version
        "MVN-001":  ["Pinned-Dependencies"],                           # floating Maven range
        "MVN-002":  ["Pinned-Dependencies"],                           # mutable SNAPSHOT dep
        "MVN-003":  ["Pinned-Dependencies"],                           # plaintext-HTTP repository
        "MVN-004":  ["Pinned-Dependencies"],                           # missing <version>
        "MVN-005":  ["Pinned-Dependencies"],                           # lax checksumPolicy
        "MVN-006":  ["Pinned-Dependencies", "Vulnerabilities"],        # compromised Maven version
        "MVN-007":  ["Pinned-Dependencies"],                           # settings.xml wildcard mirror
        "MVN-008":  ["Pinned-Dependencies", "Vulnerabilities"],        # cooldown gate (--resolve-remote)
        "MVN-009":  ["Pinned-Dependencies", "Vulnerabilities"],        # OSV advisory (--resolve-remote)
        # ── Maven extended pack ──
        "MVN-010":  ["Token-Permissions"],                             # plaintext server password
        "MVN-011":  ["Token-Permissions"],                             # repo URL credentials
        "MVN-012":  ["Pinned-Dependencies"],                           # build plugin floating
        "MVN-013":  ["Pinned-Dependencies"],                           # build extension floating
        "MVN-014":  ["Pinned-Dependencies"],                           # wrapper sha256 missing
        "MVN-015": ["Pinned-Dependencies"],  # build-time plugin exec bound to lifecycle
        "MVN-016": ["Pinned-Dependencies"],  # gradle allowInsecureProtocol
        "MVN-017": ["Token-Permissions"],  # settings.xml privateKey + plaintext passphrase
        "MVN-018": ["Pinned-Dependencies"],  # distributionManagement release accepts snapshots
        "NPM-008":  ["Pinned-Dependencies", "Vulnerabilities"],        # cooldown gate (--resolve-remote)
        "NPM-009":  ["Pinned-Dependencies"],                           # new-transitive-dep diff gate
        "NPM-010":  ["Pinned-Dependencies", "Vulnerabilities"],        # OSV advisory (--resolve-remote)
        "PYPI-008": ["Pinned-Dependencies", "Vulnerabilities"],        # cooldown gate (--resolve-remote)
        "PYPI-009": ["Pinned-Dependencies", "Vulnerabilities"],        # OSV advisory (--resolve-remote)
        # ── nuget (dep supply-chain) ─────────────────────────────
        "NUGET-001": ["Pinned-Dependencies"],                          # floating NuGet version range
        "NUGET-002": ["Pinned-Dependencies"],                          # wildcard prerelease version
        "NUGET-003": ["Pinned-Dependencies"],                          # missing explicit version
        "NUGET-004": ["Pinned-Dependencies"],                          # HTTP-only package source
        "NUGET-005": ["Pinned-Dependencies", "Vulnerabilities"],       # known-compromised package version
        "NUGET-006": ["Pinned-Dependencies"],                          # no lock file for reproducible restores
        "NUGET-007": ["Pinned-Dependencies"],                          # multiple sources without packageSourceMapping
        "NUGET-008": ["Pinned-Dependencies", "Vulnerabilities"],       # cooldown gate (--resolve-remote)
        "NUGET-009": ["Pinned-Dependencies", "Vulnerabilities"],       # OSV advisory (--resolve-remote)
        "NUGET-010": ["Token-Permissions"],                            # NuGet.config cleartext feed credential
        # ── NuGet extended pack ──
        "NUGET-011": ["Pinned-Dependencies"],
        "NUGET-013": ["Pinned-Dependencies"],
        "NUGET-014": ["Token-Permissions"],
        "NUGET-015": ["Pinned-Dependencies"],
        "NUGET-016": ["Pinned-Dependencies"],
        "NUGET-017": ["Pinned-Dependencies"],  # public gallery active alongside private feed, not disabled
        "NUGET-018": ["Dangerous-Workflow"],
        # ── Composer / PHP ──
        "COMPOSER-001": ["Pinned-Dependencies"],
        "COMPOSER-002": ["Pinned-Dependencies"],
        "COMPOSER-004": ["Token-Permissions"],
        "COMPOSER-007": ["Pinned-Dependencies", "Vulnerabilities"],
        "COMPOSER-008": ["Pinned-Dependencies"],
        "COMPOSER-009": ["Token-Permissions"],
        "COMPOSER-010": ["Pinned-Dependencies"],
        "COMPOSER-013": ["Pinned-Dependencies"],  # config.disable-tls
        # ── RubyGems / Bundler ──
        "GEM-001": ["Pinned-Dependencies"],
        "GEM-002": ["Pinned-Dependencies"],
        "GEM-004": ["Token-Permissions"],
        "GEM-005": ["Pinned-Dependencies"],
        "GEM-006": ["Pinned-Dependencies", "Vulnerabilities"],
        "GEM-008": ["Pinned-Dependencies"],
        "GEM-009": ["Token-Permissions"],
        "GEM-010": ["Pinned-Dependencies"],
        "GEM-011": ["Pinned-Dependencies"],  # Bundler plugin install-time exec
        "GEM-012": ["Pinned-Dependencies"],  # per-gem :source override
        "GEM-013": ["Pinned-Dependencies"],  # insecure git transport
        # Reusable workflow / services-image / cross-step pinning
        "GHA-017":  ["Pinned-Dependencies"],                           # package install insecure source
        "GHA-051":  ["Pinned-Dependencies"],                           # services / container image unpinned
        "BB-029":   ["Pinned-Dependencies"],                           # step + service image not digest-pinned
        "BB-030":   ["Signed-Releases", "Pinned-Dependencies"],        # npm install without audit signatures
        "BB-031":   ["Pinned-Dependencies"],                           # pip install without --require-hashes
        # Helm: stale Chart.lock is a pin-drift failure
        "HELM-008": ["Pinned-Dependencies"],                           # stale Chart.lock > 90 days
        # Cloud Build curl-pipe / TLS / pkg integrity surface
        "GCB-010":  ["Pinned-Dependencies", "Dangerous-Workflow"],     # remote script piped to shell
        "GCB-011":  ["Pinned-Dependencies"],                           # TLS / cert verification bypass
        "GCB-013":  ["Pinned-Dependencies"],                           # pkg install bypasses registry integrity
        # Dockerfile env-bypass pack disables the trusted-source
        # channel for any in-image install
        "DF-009":   ["Pinned-Dependencies"],                           # ADD where COPY suffices
        "DF-021":   ["Pinned-Dependencies"],                           # pip TLS bypass / http index
        "DF-022":   ["Pinned-Dependencies"],                           # npm install (not npm ci)
        "DF-024":   ["Pinned-Dependencies", "Dangerous-Workflow"],     # npm install runs lifecycle
        "DF-026":   ["Pinned-Dependencies"],                           # NODE_TLS_REJECT_UNAUTHORIZED=0
        "DF-027":   ["Pinned-Dependencies"],                           # PYTHONHTTPSVERIFY=0
        "DF-028":   ["Pinned-Dependencies"],                           # GIT_SSL_NO_VERIFY=1
        "DF-029":   ["Pinned-Dependencies"],                           # REQUESTS_CA_BUNDLE neutered

        # ── Dangerous-Workflow ───────────────────────────────────────
        "CB-010":   ["Dangerous-Workflow"],                            # fork PR builds without actor filter
        "CB-011":   ["Dangerous-Workflow"],                            # malicious buildspec indicators
        "CP-003":   ["Dangerous-Workflow"],                            # polling source = source poisoning window
        "CP-007":   ["Dangerous-Workflow"],                            # v2 PR trigger all branches
        "GHA-002":  ["Dangerous-Workflow"],
        "RUN-001":  ["Dangerous-Workflow"],
        "RUN-002":  ["Dangerous-Workflow"],
        "RUN-003":  ["Dangerous-Workflow"],
        "RUN-004":  ["Dangerous-Workflow"],
        "RUN-005":  ["Dangerous-Workflow"],
        "GHA-003":  ["Dangerous-Workflow"],
        "GHA-119":  ["Dangerous-Workflow"],# untrusted context into an agentic AI CLI
        "GHA-120":  ["Dangerous-Workflow"],# trust_remote_code model load = code exec
        "GHA-122":  ["Dangerous-Workflow"],# unsafe pickle deser of fetched artifact = code exec
        "GHA-117":  ["Dangerous-Workflow"],# IaC apply on untrusted PR trigger
        "GHA-118":  ["Dangerous-Workflow"],# untrusted content into $GITHUB_ENV / $GITHUB_PATH
        "GHA-009":  ["Dangerous-Workflow"],
        "GHA-010":  ["Dangerous-Workflow"],
        "GHA-011":  ["Dangerous-Workflow"],
        "GHA-013":  ["Dangerous-Workflow"],
        "GHA-023":  ["Dangerous-Workflow"],
        "GHA-026":  ["Dangerous-Workflow"],
        "GHA-107":  ["Dangerous-Workflow"],   # harden-runner in audit mode (egress not blocked)
        "GHA-108":  ["Dangerous-Workflow"],   # no runtime egress control on OIDC/deploy workflow
        "GHA-109":  ["Dangerous-Workflow"],   # harden-runner not the first step
        "GHA-027":  ["Dangerous-Workflow"],
        "GHA-028":  ["Dangerous-Workflow"],
        "GHA-038":  ["Dangerous-Workflow"],                            # ACTIONS_ALLOW_UNSECURE_COMMANDS
        "GL-002":   ["Dangerous-Workflow"],
        "GL-045":   ["Dangerous-Workflow"],# trust_remote_code model load = code exec
        "GL-047":   ["Dangerous-Workflow"],# unsafe pickle deser of fetched artifact = code exec
        "GL-048":   ["Dangerous-Workflow"],# untrusted MR context into agentic CLI = prompt injection
        "GL-049":   ["Code-Review"],# agentic CLI output lands without review
        "GL-011":   ["Dangerous-Workflow"],
        "GL-012":   ["Dangerous-Workflow"],
        "GL-023":   ["Dangerous-Workflow"],
        "GL-025":   ["Dangerous-Workflow"],                            # malicious activity
        "GL-026":   ["Dangerous-Workflow"],
        "GL-033":   ["Dangerous-Workflow"],                            # global before_script taint
        "GL-034":   ["Signed-Releases", "Pinned-Dependencies"],        # npm install without audit signatures
        "GL-035":   ["Pinned-Dependencies"],                           # pip install without --require-hashes
        "BB-002":   ["Dangerous-Workflow"],
        "BB-035":   ["Dangerous-Workflow"],   # trust_remote_code model load = code exec
        "BB-036":   ["Dangerous-Workflow"],   # untrusted PR context into agentic CLI = prompt injection
        "BB-037":   ["Dangerous-Workflow"],   # unsafe pickle deser of fetched artifact = code exec
        "BB-039":   ["Code-Review"],   # agentic CLI output lands without review
        "BB-018":   ["Dangerous-Workflow"],
        "BB-023":   ["Dangerous-Workflow"],
        "BB-025":   ["Dangerous-Workflow"],                            # malicious activity
        "BB-026":   ["Dangerous-Workflow"],
        "ADO-002":  ["Dangerous-Workflow"],
        "ADO-034":  ["Dangerous-Workflow"],   # trust_remote_code model load = code exec
        "ADO-035":  ["Dangerous-Workflow"],   # untrusted PR context into agentic CLI = prompt injection
        "ADO-036":  ["Dangerous-Workflow"],   # unsafe pickle deser of fetched artifact = code exec
        "ADO-038":  ["Code-Review"],   # agentic CLI output lands without review
        "ADO-011":  ["Dangerous-Workflow"],
        "ADO-012":  ["Dangerous-Workflow"],
        "ADO-019":  ["Dangerous-Workflow"],
        "ADO-023":  ["Dangerous-Workflow"],
        "ADO-026":  ["Dangerous-Workflow"],                            # malicious activity
        "ADO-027":  ["Dangerous-Workflow"],
        "JF-002":   ["Dangerous-Workflow"],
        "JF-012":   ["Dangerous-Workflow"],
        "JF-013":   ["Dangerous-Workflow"],
        "JF-019":   ["Dangerous-Workflow"],
        "JF-023":   ["Dangerous-Workflow"],
        "JF-029":   ["Dangerous-Workflow"],                            # malicious activity
        "JF-030":   ["Dangerous-Workflow"],
        "CC-002":   ["Dangerous-Workflow"],
        "CC-012":   ["Dangerous-Workflow"],
        "CC-013":   ["Dangerous-Workflow"],                            # no branch filter on jobs
        "CC-023":   ["Dangerous-Workflow"],
        "CC-025":   ["Dangerous-Workflow"],
        "CC-026":   ["Dangerous-Workflow"],                            # malicious activity
        "CC-027":   ["Dangerous-Workflow"],
        "GCB-004":  ["Dangerous-Workflow"],
        "GCB-006":  ["Dangerous-Workflow"],
        # curl|bash is classic Dangerous-Workflow territory
        "GHA-016":  ["Dangerous-Workflow"],
        "GL-016":   ["Dangerous-Workflow"],
        "BB-012":   ["Dangerous-Workflow"],
        "ADO-016":  ["Dangerous-Workflow"],
        "JF-016":   ["Dangerous-Workflow"],
        "CC-016":   ["Dangerous-Workflow"],
        # Cross-step / cross-job taint flows = untrusted data reaches a
        # privileged sink, the canonical Dangerous-Workflow shape.
        "TAINT-001": ["Dangerous-Workflow"],                           # cross-step $GITHUB_OUTPUT
        "TAINT-002": ["Dangerous-Workflow"],                           # cross-job jobs.<id>.outputs
        "TAINT-003": ["Dangerous-Workflow"],                           # tainted with: into reusable
        "TAINT-004": ["Dangerous-Workflow"],                           # GitLab dotenv cross-job
        "TAINT-005": ["Dangerous-Workflow"],                           # Buildkite meta-data
        "TAINT-006": ["Dangerous-Workflow"],                           # Tekton results
        "TAINT-007": ["Dangerous-Workflow"],                           # Argo outputs.parameters
        "TAINT-008": ["Dangerous-Workflow"],                           # GitLab extends-chain
        # GHA worm-mitigation / advanced-PPE pack
        "GHA-030":  ["Dangerous-Workflow", "Token-Permissions"],       # OIDC w/o env-protected job
        "GHA-031":  ["Dangerous-Workflow"],                            # retired set-output / save-state
        "GHA-032":  ["Dangerous-Workflow"],                            # local script on untrusted trigger
        "GHA-033":  ["Token-Permissions"],                             # secret echoed in run:
        "GHA-034":  ["Token-Permissions"],                             # secrets: inherit (broad cred surface)
        "GHA-116":  ["Token-Permissions"],                             # bulk secrets serialization
        "GHA-035":  ["Dangerous-Workflow"],                            # github-script untrusted context
        "GHA-036":  ["Dangerous-Workflow"],                            # runs-on untrusted context
        "GHA-041":  ["Dangerous-Workflow"],                            # single-maintainer action (reputation)
        "GHA-042":  ["Dangerous-Workflow"],                            # very-young action repo
        "GHA-043":  ["Dangerous-Workflow", "Token-Permissions"],       # low-star + sensitive perms
        "GHA-044":  ["Dangerous-Workflow"],                            # build-tool PPE on untrusted trigger
        "GHA-045":  ["Dangerous-Workflow"],                            # caller-ref input drives checkout
        "GHA-046":  ["Dangerous-Workflow"],                            # manual PR-head fetch
        "GHA-047":  ["Dangerous-Workflow"],                            # fresh-ref cooldown
        "GHA-048":  ["Dangerous-Workflow"],                            # workflow self-mutation
        "GHA-049":  ["Dangerous-Workflow", "Token-Permissions"],       # cross-repo push from CI
        "GHA-050":  ["Token-Permissions"],                             # long-lived registry publish token
        "GHA-052":  ["Dangerous-Workflow"],                            # cache key untrusted-input poisoning
        "GHA-053":  ["Dangerous-Workflow"],                            # if: predicate untrusted-context
        "GHA-054":  ["Token-Permissions"],                             # checkout ssh-key persists
        "GHA-055":  ["Token-Permissions"],                             # reusable outputs leak secret
        "GHA-056":  ["Dangerous-Workflow"],                            # supply-chain worm IOC strings
        "GHA-057":  ["Dangerous-Workflow", "Token-Permissions"],       # secret-scanner output → egress
        "GHA-058":  ["Dangerous-Workflow"],                            # agentic CLI permission-bypass
        "GHA-059":  ["Signed-Releases", "Pinned-Dependencies"],        # npm install without audit signatures
        "GHA-060":  ["Pinned-Dependencies"],                           # pip install without --require-hashes
        "GHA-061":  ["Token-Permissions"],                             # App token minted without permissions filter
        "GHA-106":  ["Token-Permissions"],                             # AI agent with write-scoped token
        "GHA-111":  ["Dangerous-Workflow"],  # AI agent edits IaC applied in the same job
        "GHA-112":  ["Code-Review"],  # self-hosted deploy with no environment gate
        "GHA-113":  ["Dangerous-Workflow", "Token-Permissions"],  # OIDC trusted-publish w/o env gate
        "GHA-114":  ["Dangerous-Workflow", "Token-Permissions"],  # publish workflow on an unrestricted push trigger
        "GHA-062":  ["Token-Permissions"],                             # OIDC trust subject in sibling IaC overly broad
        # Cross-pipeline / cross-project artifact ingestion = same
        # source-poisoning shape as the GHA workflow_run rule
        "ADO-010":  ["Dangerous-Workflow"],                            # cross-pipeline download
        "ADO-017":  ["Dangerous-Workflow"],                            # docker run privileged/host
        "ADO-029":  ["Code-Review"],                                   # service-conn no env gate
        "ADO-030":  ["Dangerous-Workflow"],                            # pool interpolates untrusted
        "BB-005":   ["Dangerous-Workflow"],                            # docker privileged
        "BB-010":   ["Dangerous-Workflow"],                            # deploy step PR artifact unverified
        "BB-013":   ["Dangerous-Workflow"],                            # docker run privileged/host
        "BB-028":   ["Code-Review"],                                   # OIDC step w/o env gate
        "CB-002":   ["Dangerous-Workflow"],                            # CodeBuild privileged mode
        "CB-007":   ["Dangerous-Workflow"],                            # CodeBuild webhook no filter
        "CC-004":   ["Token-Permissions"],                             # secret in env
        "CC-010":   ["Dangerous-Workflow"],                            # docker privileged
        "CC-014":   ["Token-Permissions"],                             # unrestricted token equivalent
        "CC-015":   ["Dangerous-Workflow"],                            # docker privileged
        "CC-017":   ["Dangerous-Workflow"],                            # docker privileged
        "CC-031":   ["Code-Review", "Token-Permissions"],              # OIDC role w/o branch filter
        "DR-004":   ["Token-Permissions"],                             # literal credential
        "GL-010":   ["Dangerous-Workflow"],                            # multi-project artifact unverified
        "GL-017":   ["Dangerous-Workflow"],                            # docker run privileged
        "GL-039":   ["Dangerous-Workflow"],                            # dind daemon TLS disabled / exposed on 2375
        "GL-031":   ["Token-Permissions"],                             # id_tokens missing audience
        "GL-040":   ["Token-Permissions"],                             # CI_JOB_TOKEN used for cross-project access
        "GL-041":   ["Dangerous-Workflow"],                            # IaC apply on an untrusted MR trigger
        "GL-032":   ["Dangerous-Workflow"],                            # tags interpolates untrusted
        "JF-017":   ["Dangerous-Workflow"],                            # docker run privileged/host
        "JF-025":   ["Dangerous-Workflow"],                            # K8s agent privileged / hostPath
        "JF-032":   ["Dangerous-Workflow"],                            # agent label interpolates untrusted
        "JF-033":   ["Token-Permissions"],                             # withCredentials leaked via Groovy ${}
        "JF-034":   ["Token-Permissions"],                             # password() build parameter
        "JF-035":   ["Dangerous-Workflow", "Pinned-Dependencies"],     # httpRequest SSL off
        "TKN-013":  ["Dangerous-Workflow"],                            # sidecar privileged / root
        "TKN-015":  ["Dangerous-Workflow"],                            # workspace subPath param injection
        "ARGO-013": ["Token-Permissions"],                             # SA token automount default
        "ARGO-015": ["Pinned-Dependencies"],                           # insecure (non-HTTPS) artifact URL
        # ── Argo CD (GitOps deployment) ──
        "ARGOCD-010": ["Pinned-Dependencies"],                         # mutable targetRevision
        "ARGOCD-017": ["Pinned-Dependencies"],  # in-cluster mutable source
        "ARGOCD-016": ["Pinned-Dependencies"],  # Helm valueFiles from a remote URL
        "ARGOCD-018": ["Pinned-Dependencies"],  # custom resource health / action Lua
        "ARGOCD-011": ["Token-Permissions"],                           # cluster-resource wildcard
        # ── Helm extended pack ──
        "HELM-011": ["Token-Permissions"],                             # dependency URL embedded creds
        "HELM-014": ["Pinned-Dependencies"],                           # known-compromised dep
        "HELM-015": ["Pinned-Dependencies"],  # oci:// dependency not digest-pinned
        "HELM-016": ["Token-Permissions"],  # default secret in values.yaml
        "HELM-017": ["Pinned-Dependencies"],  # tpl of an untrusted .Values value
        "BK-013":   ["Code-Review"],                                   # deploy step no branches filter
        # Cloud Build tainted-substitution / shell pack
        "GCB-012":  ["Token-Permissions"],                             # credential-shaped literal
        "GCB-016":  ["Dangerous-Workflow"],                            # dir path escape
        "GCB-018":  ["Token-Permissions"],                             # legacy KMS secrets block
        "GCB-019":  ["Dangerous-Workflow"],                            # shell entrypoint + user substitution
        "GCB-020":  ["Token-Permissions"],                             # default Cloud Build SA
        "GCB-022":  ["Dangerous-Workflow"],                            # ALLOW_LOOSE substitution
        "GCB-023":  ["Dangerous-Workflow"],                            # undeclared user substitution
        # Dockerfile env-bypass + privileged shape
        "DF-008":   ["Dangerous-Workflow"],                            # docker --privileged
        "DF-012":   ["Dangerous-Workflow"],                            # sudo in RUN
        "DF-023":   ["Dangerous-Workflow"],                            # LD_PRELOAD / LD_LIBRARY_PATH
        "DF-025":   ["Token-Permissions"],                             # registry token in image layer
        "DF-030":   ["Dangerous-Workflow"],                            # NODE_OPTIONS --require / --inspect
        # NPM install-time lifecycle scripts = untrusted code path
        "NPM-004":  ["Dangerous-Workflow"],                            # install-time lifecycle script
        "NPM-007":  ["Dangerous-Workflow"],                            # .npmrc ignore-scripts enforcement
        "NPM-011":  ["Token-Permissions"],                             # secret-shaped paths in files field
        "NPM-013":  ["Token-Permissions"],                             # broad files-field publishes everything

        # ── Token-Permissions ────────────────────────────────────────
        # Scorecard's check targets GITHUB_TOKEN scope, but applies in
        # spirit to any overbroad CI identity.
        "GHA-004":  ["Token-Permissions"],
        "GHA-005":  ["Token-Permissions"],
        "GHA-008":  ["Token-Permissions"],
        "GHA-019":  ["Token-Permissions"],
        "GHA-037":  ["Token-Permissions"],          # actions/checkout persist-credentials
        "GHA-039":  ["Token-Permissions"],          # services / container creds literal
        "GL-003":   ["Token-Permissions"],
        "GL-008":   ["Token-Permissions"],
        "DEV-008":   ["Token-Permissions"],   # literal secret in a devenv config
        "GL-013":   ["Token-Permissions"],
        "GL-020":   ["Token-Permissions"],
        "BB-003":   ["Token-Permissions"],
        "BB-008":   ["Token-Permissions"],
        "BB-011":   ["Token-Permissions"],
        "BB-017":   ["Token-Permissions"],
        "BB-019":   ["Token-Permissions"],
        "ADO-003":  ["Token-Permissions"],
        "ADO-008":  ["Token-Permissions"],
        "ADO-014":  ["Token-Permissions"],
        "JF-004":   ["Token-Permissions"],
        "JF-008":   ["Token-Permissions"],
        "JF-010":   ["Token-Permissions"],
        "CC-005":   ["Token-Permissions"],
        "CC-008":   ["Token-Permissions"],
        "CC-019":   ["Token-Permissions"],
        "CC-030":   ["Token-Permissions"],
        "GCB-002":  ["Token-Permissions"],
        "GCB-003":  ["Token-Permissions"],
        "GCB-007":  ["Token-Permissions"],
        "CB-001":   ["Token-Permissions"],
        "CB-006":   ["Token-Permissions"],
        "CP-004":   ["Token-Permissions"],
        "CCM-003":  ["Token-Permissions"],                             # CodeCommit cross-account trigger
        "CA-004":   ["Token-Permissions"],                             # CodeArtifact wildcard Resource
        "IAM-001":  ["Token-Permissions"],
        "IAM-002":  ["Token-Permissions"],
        "IAM-003":  ["Token-Permissions"],                             # no permission boundary
        "IAM-004":  ["Token-Permissions"],
        "IAM-005":  ["Token-Permissions"],                             # relaxed external-trust
        "IAM-006":  ["Token-Permissions"],
        "IAM-007":  ["Token-Permissions"],
        "IAM-008":  ["Token-Permissions"],                             # OIDC audience not pinned
        "IAM-009":  ["Token-Permissions"],                             # Azure WIF broad subject
        "IAM-010":  ["Token-Permissions"],                             # GCP WIF no repo condition
        "KMS-001":  ["Token-Permissions"],                             # CMK rotation disabled
        "KMS-002":  ["Token-Permissions"],                             # KMS policy wildcard
        "LMB-002":  ["Token-Permissions"],                             # public Lambda function URL
        "LMB-003":  ["Token-Permissions"],                             # plaintext secrets in Lambda env
        "LMB-004":  ["Token-Permissions"],                             # public Lambda resource policy
        "SM-001":   ["Token-Permissions"],
        "SM-002":   ["Token-Permissions"],                             # Secrets Manager public policy
        "SSM-001":  ["Token-Permissions"],
        "SSM-002":  ["Token-Permissions"],                             # SSM SecureString default key
        "JF-003":   ["Token-Permissions"],                             # agent any (no executor isolation)
        "CA-003":   ["Token-Permissions"],                             # CodeArtifact domain cross-account wildcard
        "PBAC-002": ["Token-Permissions"],                             # shared service role across stages
        "PBAC-005": ["Token-Permissions"],                             # stage action roles mirror pipeline role

        # ── Signed-Releases ──────────────────────────────────────────
        "SIGN-001": ["Signed-Releases"],
        "SIGN-002": ["Signed-Releases"],
        "CP-002":   ["Signed-Releases"],
        "ECR-005":  ["Signed-Releases"],
        "CA-001":   ["Signed-Releases"],                               # CodeArtifact KMS (artifact integrity)
        "LMB-001":  ["Signed-Releases"],                               # Lambda code-signing config
        "GHA-006":  ["Signed-Releases"],
        "GHA-024":  ["Signed-Releases"],
        "GL-006":   ["Signed-Releases"],
        "GL-024":   ["Signed-Releases"],
        "BB-006":   ["Signed-Releases"],
        "BB-024":   ["Signed-Releases"],
        "ADO-006":  ["Signed-Releases"],
        "ADO-024":  ["Signed-Releases"],
        "JF-006":   ["Signed-Releases"],
        "JF-028":   ["Signed-Releases"],
        "CC-006":   ["Signed-Releases"],
        "CC-024":   ["Signed-Releases"],
        "GCB-009":  ["Signed-Releases"],
        "GCB-017":  ["Signed-Releases", "SBOM"],                       # image build without SLSA provenance
        "GCB-024":  ["Signed-Releases"],                               # images: missing for docker push
        # in-toto / SLSA attestation content rules: each flags the
        # provenance document itself (untrusted builder, source
        # claim, subject digest, buildType).
        "ATTEST-001": ["Signed-Releases"],                             # untrusted SLSA builder identity
        "ATTEST-002": ["Signed-Releases"],                             # source-repo claim unverifiable
        "ATTEST-005": ["Signed-Releases", "Pinned-Dependencies"],      # in-toto subject digest unpinned
        "ATTEST-006": ["Signed-Releases"],                             # buildType missing / placeholder

        # ── SBOM ─────────────────────────────────────────────────────
        "GHA-007":  ["SBOM"],
        "GL-007":   ["SBOM"],
        "BB-007":   ["SBOM"],
        "ADO-007":  ["SBOM"],
        "JF-007":   ["SBOM"],
        "CC-007":   ["SBOM"],
        "GCB-015":  ["SBOM"],                                          # no CycloneDX / syft / Trivy-SBOM step
        # SBOM-content failures (the SBOM exists but under-specifies
        # what it should track).
        "ATTEST-003": ["SBOM", "Pinned-Dependencies"],                 # SBOM floating versions
        "ATTEST-004": ["SBOM"],                                        # provenance lacks resolved materials
        "ATTEST-007": ["SBOM"],                                        # SBOM missing supplier attribution
        # OCI image provenance annotations are the per-image SBOM
        # surface (image.created / image.licenses).
        "OCI-003":   ["SBOM"],                                         # missing image.created
        "OCI-005":   ["SBOM"],                                         # missing image.licenses
        # Jenkins archiveArtifacts fingerprint = artifact-tracking
        "JF-027":    ["SBOM"],                                         # no fingerprint = no artifact trace

        # ── Vulnerabilities / SAST ───────────────────────────────────
        "ECR-001":  ["Vulnerabilities", "SAST"],
        "ECR-007":  ["Vulnerabilities", "SAST"],                       # Inspector v2 enhanced scanning
        "GHA-020":  ["Vulnerabilities", "SAST"],
        "GL-019":   ["Vulnerabilities", "SAST"],
        "BB-015":   ["Vulnerabilities", "SAST"],
        "ADO-020":  ["Vulnerabilities", "SAST"],
        "JF-020":   ["Vulnerabilities", "SAST"],
        "CC-020":   ["Vulnerabilities", "SAST"],
        "GCB-008":  ["Vulnerabilities", "SAST"],

        # ── Dependency-Update-Tool ───────────────────────────────────
        "GHA-022":  ["Dependency-Update-Tool"],
        "GL-022":   ["Dependency-Update-Tool"],
        "BB-022":   ["Dependency-Update-Tool"],
        "ADO-022":  ["Dependency-Update-Tool"],
        "JF-022":   ["Dependency-Update-Tool"],
        "CC-022":   ["Dependency-Update-Tool"],

        # ── Code-Review (loose: pipeline approval gates) ─────────────
        "CP-001":   ["Code-Review"],
        "CP-005":   ["Code-Review"],
        "CD-002":   ["Code-Review"],
        "CCM-001":  ["Code-Review"],                                   # CodeCommit approval rule template
        "GHA-014":  ["Code-Review"],
        "GHA-123":  ["Code-Review"],# agentic CLI output lands without review
        "GL-004":   ["Code-Review"],
        "GL-029":   ["Code-Review"],
        "BB-004":   ["Code-Review"],
        "ADO-004":  ["Code-Review"],
        "JF-005":   ["Code-Review"],
        "JF-024":   ["Code-Review"],
        "JF-026":   ["Code-Review"],                                   # build job unchecked
        "CC-009":   ["Code-Review"],
        "CB-008":   ["Code-Review"],
        # ── Buildkite ────────────────────────────────────────────────
        "BK-001":   ["Pinned-Dependencies"],                           # plugin not pinned
        "BK-002":   ["Token-Permissions"],                             # leaked creds in env
        "BK-003":   ["Dangerous-Workflow"],                            # untrusted variable injection
        "BK-015":   ["Dangerous-Workflow"],                            # agents map runner targeting via tainted vars
        "BK-004":   ["Dangerous-Workflow", "Pinned-Dependencies"],     # curl | bash
        "BK-005":   ["Dangerous-Workflow"],                            # Docker privileged
        "BK-007":   ["Code-Review"],                                   # deploy not gated
        "BK-008":   ["Pinned-Dependencies"],                           # TLS bypass
        "BK-009":   ["Signed-Releases"],                               # artifact signing
        "BK-010":   ["SBOM"],                                          # SBOM
        "BK-011":   ["Signed-Releases", "SBOM"],                       # SLSA provenance
        "BK-012":   ["Vulnerabilities", "SAST"],                       # vuln scanning
        # ── Tekton ───────────────────────────────────────────────────
        "TKN-001":  ["Pinned-Dependencies"],                           # step image not digest-pinned
        "TKN-016": ["Pinned-Dependencies"],  # remote resolver / bundle task body not pinned
        "TKN-002":  ["Dangerous-Workflow"],                            # step privileged
        "TKN-003":  ["Dangerous-Workflow"],                            # param injection
        "TKN-004":  ["Dangerous-Workflow"],                            # hostPath / namespaces
        "TKN-005":  ["Token-Permissions"],                             # leaked creds
        "TKN-007":  ["Token-Permissions"],                             # default SA
        "TKN-008":  ["Dangerous-Workflow", "Pinned-Dependencies"],     # remote install / TLS
        "TKN-009":  ["Signed-Releases"],                               # artifact signing
        "TKN-010":  ["SBOM"],                                          # SBOM
        "TKN-011":  ["Signed-Releases", "SBOM"],                       # SLSA provenance
        "TKN-012":  ["Vulnerabilities", "SAST"],                       # vuln scanning
        # ── Argo Workflows ───────────────────────────────────────────
        "ARGO-001": ["Pinned-Dependencies"],                           # template image not pinned
        "ARGO-002": ["Dangerous-Workflow"],                            # template privileged
        "ARGO-003": ["Token-Permissions"],                             # default SA
        "ARGO-016": ["Token-Permissions"],                             # cluster-admin / over-privileged ServiceAccount
        "ARGO-004": ["Dangerous-Workflow"],                            # hostPath / namespaces
        "ARGO-005": ["Dangerous-Workflow"],                            # parameter injection
        "ARGO-017": ["Dangerous-Workflow"],                            # resource template manifest injection
        "ARGO-006": ["Token-Permissions"],                             # leaked creds
        "ARGO-008": ["Dangerous-Workflow", "Pinned-Dependencies"],     # remote install / TLS
        "ARGO-009": ["Signed-Releases"],                               # artifact signing
        "ARGO-010": ["SBOM"],                                          # SBOM
        "ARGO-011": ["Signed-Releases", "SBOM"],                       # SLSA provenance
        "ARGO-012": ["Vulnerabilities", "SAST"],                       # vuln scanning
        # ── Drone CI ─────────────────────────────────────────────────
        "DR-001":   ["Pinned-Dependencies"],                           # step image not digest-pinned
        "DR-002":   ["Dangerous-Workflow"],                            # privileged step
        "DR-003":   ["Dangerous-Workflow"],                            # ${DRONE_*} parameter injection
        "DR-005":   ["Pinned-Dependencies"],                           # plugin floating tag
        "DR-006":   ["Dangerous-Workflow", "Pinned-Dependencies"],     # TLS bypass in commands
        "DR-007":   ["Dangerous-Workflow"],                            # sensitive host-path mount
        "DR-008":   ["Pinned-Dependencies"],                           # ``pull: never`` skips registry verify
        "DR-009":   ["Dangerous-Workflow"],                            # tainted cache key
        "DR-011":   ["Dangerous-Workflow"],                            # node map runner targeting
        # ── Drone extended pack ──
        "DR-012":   ["Pinned-Dependencies"],                           # service image not pinned
        "DR-014":   ["Pinned-Dependencies"],                           # pipe-to-shell
        "DR-015":   ["Dangerous-Workflow"],                            # clone recursive
        "DR-016":   ["Dangerous-Workflow"],                            # image field interpolation
        # ── OCI image manifest ───────────────────────────────────────
        "OCI-001":  ["SBOM"],                                          # provenance annotations
        "OCI-002":  ["Signed-Releases", "SBOM"],                       # build attestation manifest
        "OCI-004":  ["Pinned-Dependencies"],                           # foreign-URL layer = no content pin
        "OCI-007":  ["Pinned-Dependencies"],                           # legacy schemaVersion 1
        "OCI-008":  ["Pinned-Dependencies"],                           # non-sha256 digest
        "OCI-009":  ["SBOM"],                                          # missing base-image annotations
        # ── Helm chart-supply-chain ──────────────────────────────────
        # Chart deps ARE pinned dependencies in the Scorecard sense —
        # an unlocked Chart.lock is a Pinned-Dependencies failure.
        # HELM-005 (maintainers) and HELM-006 (kubeVersion) sit
        # outside Scorecard's check set; left unmapped on purpose.
        "HELM-001": ["Pinned-Dependencies"],                           # legacy v1 (no in-tree lock)
        "HELM-002": ["Pinned-Dependencies"],                           # missing Chart.lock digests
        "HELM-003": ["Pinned-Dependencies"],                           # non-HTTPS dep repo
        "HELM-004": ["Pinned-Dependencies"],                           # version range
        # ── Dockerfile (image base / build deps = pinned deps) ────
        # Scorecard's Pinned-Dependencies covers actions, images,
        # includes, and packages. ``FROM image:tag`` without a
        # digest is the canonical image-not-pinned failure.
        "DF-001": ["Pinned-Dependencies"],                              # FROM not digest-pinned
        "MODEL-001": ["Pinned-Dependencies"],                           # unpinned base model
        "MODEL-002": ["Pinned-Dependencies"],                           # third-party hub base model
        "MODEL-003": ["Pinned-Dependencies"],                           # local unverified weights blob
        "MODEL-004": ["Pinned-Dependencies"],                           # remote LoRA adapter
        "MODEL-005": ["Pinned-Dependencies"],                           # config auto_map = custom loader code
        "DF-031": ["Pinned-Dependencies"],                              # COPY --from external image not digest-pinned
        "DF-003": ["Pinned-Dependencies"],                              # ADD remote no integrity
        "DF-004": ["Pinned-Dependencies", "Dangerous-Workflow"],        # curl-pipe
        "DF-005": ["Dangerous-Workflow"],                               # shell-eval
        "DF-006": ["Token-Permissions"],                                # ENV credential literal
        "DF-010": ["Pinned-Dependencies"],                              # apt upgrade unpinned
        "DF-016": ["SBOM"],                                             # missing OCI provenance
        "DF-019": ["Token-Permissions"],                                # COPY credential file
        "DF-020": ["Token-Permissions"],                                # credential ARG
        # ── SCM posture (governance via the GitHub REST API) ────────
        # The SCM provider is the first surface that can evidence the
        # platform-side controls Scorecard built its model on.
        "SCM-001": ["Branch-Protection"],
        "SCM-002": ["Branch-Protection", "Code-Review"],
        "SCM-003": ["SAST"],
        "SCM-005": ["Dependency-Update-Tool", "Vulnerabilities"],
        "SCM-006": ["Branch-Protection"],
        "SCM-007": ["Branch-Protection"],
        "SCM-008": ["Branch-Protection"],
        "SCM-009": ["Branch-Protection"],
        "SCM-010": ["Branch-Protection"],
        "SCM-011": ["Code-Review"],
        "SCM-012": ["Code-Review"],
        "SCM-013": ["Code-Review"],
        "SCM-014": ["Code-Review"],
        # SCM-015 (push protection) and SCM-016 (private vuln reporting)
        # don't have direct Scorecard analogs.
        "SCM-017": ["Code-Review"],
        # SCM-018 (bypass list) and SCM-019 (push-restriction allowlist)
        # describe weaknesses in a configured protection rule rather
        # than the binary "protection present" Scorecard model; left
        # off the explicit mapping to keep the Scorecard surface
        # interpretable.
        # ── Actions governance + environment protection ─────────────
        "SCM-020": ["Token-Permissions"],          # workflow_token default write
        "SCM-021": ["Code-Review"],                # Actions can approve PRs
        "SCM-022": ["Pinned-Dependencies"],        # allowed_actions unrestricted
        "SCM-023": ["Code-Review"],                # env missing reviewers (review on deploys)
        "SCM-024": ["Branch-Protection"],          # env branch policy missing
        "SCM-025": ["Token-Permissions"],          # deploy keys write-enabled (long-lived push credential)
        # SCM-026 (webhook insecure) and SCM-028 (private repo
        # forking) cover surfaces Scorecard doesn't model; left
        # off the explicit mapping.
        "SCM-027": ["Code-Review"],                # outside collaborator elevated (review trust boundary)
        # ── Ruleset enforcement (modern variant of branch protection) ──
        "SCM-029": ["Branch-Protection"],          # ruleset not enforced
        "SCM-030": ["Branch-Protection"],          # ruleset always-bypass
        "SCM-031": ["Code-Review"],                # auto-merge enabled
        "SCM-032": ["Branch-Protection", "Code-Review"],  # ruleset lacks PR review
        "SCM-033": ["Branch-Protection"],          # ruleset lacks status_checks
        "SCM-034": ["Branch-Protection"],          # ruleset allows force_push
        "SCM-035": ["Branch-Protection"],          # ruleset allows deletion
        "SCM-036": ["Branch-Protection"],          # ruleset lacks signed_commits
        "SCM-037": ["Code-Review"],                # ruleset stale-review dismissal
        "SCM-038": ["Branch-Protection"],          # ruleset lacks linear_history
        "SCM-039": ["Branch-Protection"],          # ruleset lacks required_workflows
        "SCM-040": ["Branch-Protection", "SAST"],  # ruleset lacks code_scanning gate
        "SCM-041": ["Branch-Protection"],          # ruleset lacks deployment-env gate
        "SCM-042": ["Branch-Protection"],          # ruleset lacks merge queue
        # Signed-commit + code-scanning posture (SCM-043..047)
        "SCM-043": ["Branch-Protection"],          # tag-ruleset lacks signed_commits
        "SCM-044": ["Branch-Protection"],          # required_signatures admin bypass
        "SCM-045": ["SAST"],                       # default code scanning limited query suite
        "SCM-046": ["SAST"],                       # default code scanning configured but paused
        "SCM-047": ["SAST"],                       # repo language not covered by default scanning
        # ── Terraform / CloudFormation (IaC-native) ──────────────────
        # Long-lived IAM access keys declared as code and hard-coded
        # credentials surface a Token-Permissions failure — the same
        # shape as DF-006 / DF-019 / DF-020 above (cred-as-code).
        "TF-001":  ["Token-Permissions"],          # aws_iam_access_key declared as code
        "TF-002":  ["Token-Permissions"],          # hard-coded secret in resource attr
        "CF-001":  ["Token-Permissions"],          # AWS::IAM::AccessKey declared as code
        "CF-002":  ["Token-Permissions"],          # hard-coded secret in resource property
        # ── Azure Cloud (Entra ID / Storage / Key Vault / ACR / Monitor) ──
        "ENTRA-001": ["Token-Permissions"],                # SP assigned Global Administrator
        "ENTRA-002": ["Token-Permissions"],                # app credential beyond 180 days
        "ENTRA-003": ["Token-Permissions"],                # SP uses password credential
        "AZST-001":  ["Token-Permissions"],                # public blob access
        "AZST-002":  ["Pinned-Dependencies"],              # non-HTTPS traffic
        "AZST-003":  ["Token-Permissions"],                # no CMK encryption
        "AKV-001":   ["Token-Permissions"],                # soft delete not enabled
        "AKV-002":   ["Token-Permissions"],                # purge protection not enabled
        "AKV-003":   ["Token-Permissions"],                # network ACLs allow all
        "ACR-001":   ["Token-Permissions"],                # admin user enabled
        "ACR-002":   ["Token-Permissions"],                # public network access
        "ACR-003":   ["Signed-Releases"],                  # content trust not enabled
        "AZMON-001": ["Branch-Protection"],                # no diagnostic setting
        "AZMON-002": ["Branch-Protection"],                # log retention < 365 days
        "AZMON-003": ["Branch-Protection"],                # no alert rule
        # ── GCP (IAM / GCS / KMS / Artifact Registry / Cloud Logging) ────
        "GCIAM-001": ["Token-Permissions"],                # SA has Owner/Editor role
        "GCIAM-002": ["Token-Permissions"],                # user-managed SA key
        "GCIAM-003": ["Token-Permissions"],                # token creator without condition
        "GCS-001":   ["Token-Permissions"],                # public bucket
        "GCS-002":   ["Token-Permissions"],                # no uniform access
        "GCS-003":   ["Token-Permissions"],                # versioning not enabled
        "GCKMS-001": ["Token-Permissions"],                # key rotation > 365 days
        "GCKMS-002": ["Token-Permissions"],                # public KMS key access
        "GCKMS-003": ["Token-Permissions"],                # no HSM protection
        "GAR-001":   ["Vulnerabilities", "SAST"],          # no vulnerability scanning
        "GAR-002":   ["Token-Permissions"],                # publicly readable repo
        "GAR-003":   ["Pinned-Dependencies"],              # no cleanup policy
        "GCLOG-001": ["Branch-Protection"],                # audit logs not enabled
        "GCLOG-002": ["Branch-Protection"],                # no log sink
        "GCLOG-003": ["Branch-Protection"],                # log retention < 365 days
        # ── Azure Cloud phase-2 ──────────────────────────────────────
        "ENTRA-004": ["Token-Permissions"],                # cond access MFA
        "ENTRA-005": ["Token-Permissions"],                # ext user restrict
        "ENTRA-006": ["Branch-Protection"],                # risky signin
        "AZST-004":  ["Pinned-Dependencies"],              # min TLS
        "AZST-005":  ["Pinned-Dependencies"],              # lifecycle
        "AZST-006":  ["Token-Permissions"],                # key rotation
        "AKV-004":   ["Token-Permissions"],                # key expiry
        "AKV-005":   ["Token-Permissions"],                # secret expiry
        "AKV-006":   ["Token-Permissions"],                # RBAC
        "ACR-004":   ["Vulnerabilities", "SAST"],          # defender scan
        "ACR-005":   ["Signed-Releases"],                  # tag immutability
        "AZMON-004": ["Branch-Protection"],                # KV diagnostics
        "AZMON-005": ["Branch-Protection"],                # NSG flow retention
        "AZMON-006": ["Branch-Protection"],                # LAW retention
        "AZMON-007": ["Branch-Protection"],                # svc health alert
        "AZNW-001":  ["Dangerous-Workflow"],               # SSH/RDP internet (CRITICAL)
        "AZNW-002":  ["Branch-Protection"],                # flow logs
        "AZNW-003":  ["Dangerous-Workflow"],               # WAF
        "AZNW-004":  ["Dangerous-Workflow"],               # deny-all
        "AZNW-005":  ["Dangerous-Workflow"],               # public IP VM
        "AZAPP-001": ["Pinned-Dependencies"],              # HTTPS
        "AZAPP-002": ["Pinned-Dependencies"],              # TLS
        "AZAPP-003": ["Token-Permissions"],                # managed identity
        "AZAPP-004": ["Dangerous-Workflow"],               # remote debug
        "AZAPP-005": ["Dangerous-Workflow"],               # FTP
        "AZSQL-001": ["Token-Permissions"],                # TDE CMK
        "AZSQL-002": ["Branch-Protection"],                # auditing
        "AZSQL-003": ["Dangerous-Workflow"],               # public access
        "AZSQL-004": ["Token-Permissions"],                # AAD admin
        "AZSQL-005": ["Vulnerabilities"],                  # threat detect
        "AZVM-001":  ["Token-Permissions"],                # disk encrypt
        "AZVM-002":  ["Dangerous-Workflow"],               # public IP
        "AZVM-003":  ["Dangerous-Workflow"],               # JIT
        "AZVM-004":  ["Vulnerabilities"],                  # OS patch
        "AZVM-005":  ["Token-Permissions"],                # managed identity
        # ── GCP phase-2 ──────────────────────────────────────────────
        "GCIAM-004": ["Token-Permissions"],                # default SA
        "GCIAM-005": ["Token-Permissions"],                # domain restrict
        "GCIAM-006": ["Token-Permissions"],                # SA key age
        "GCS-004":   ["Token-Permissions"],                # CMEK
        "GCS-005":   ["Branch-Protection"],                # access logging
        "GCLOG-004": ["Branch-Protection"],                # VPC flow logs
        "GCLOG-005": ["Branch-Protection"],                # firewall logging
        "GCLOG-006": ["Branch-Protection"],                # data access
        "GCLOG-007": ["Branch-Protection"],                # metric filter IAM
        "GCLOG-008": ["Branch-Protection"],                # metric filter firewall
        "GCLOG-009": ["Branch-Protection"],                # metric filter route
        "GCLOG-010": ["Branch-Protection"],                # metric filter SQL
        "GCLOG-011": ["Branch-Protection"],                # metric filter custom role
        "GCNET-001": ["Dangerous-Workflow"],               # default network
        "GCNET-002": ["Dangerous-Workflow"],               # deny-all
        "GCNET-003": ["Dangerous-Workflow"],               # SSH/RDP (CRITICAL)
        "GCNET-004": ["Dangerous-Workflow"],               # private access
        "GCNET-005": ["Dangerous-Workflow"],               # Cloud NAT
        "GCCE-001":  ["Dangerous-Workflow"],               # shielded VM
        "GCCE-002":  ["Token-Permissions"],                # OS Login
        "GCCE-003":  ["Dangerous-Workflow"],               # serial port
        "GCCE-004":  ["Dangerous-Workflow"],               # public IP
        "GCCE-005":  ["Dangerous-Workflow"],               # project SSH keys
        "GCSQL-001": ["Dangerous-Workflow"],               # public IP
        "GCSQL-002": ["Pinned-Dependencies"],              # backups
        "GCSQL-003": ["Pinned-Dependencies"],              # SSL
        "GCSQL-004": ["Token-Permissions"],                # IAM auth
        "GCSQL-005": ["Pinned-Dependencies"],              # PITR
        "GCRUN-001": ["Dangerous-Workflow"],               # unauth
        "GCRUN-002": ["Token-Permissions"],                # custom SA
        "GCRUN-003": ["Pinned-Dependencies"],              # min instances
        "GCRUN-004": ["Dangerous-Workflow"],               # VPC connector
        "GCKMS-004": ["Token-Permissions"],                # keyring IAM
        "GCKMS-005": ["Token-Permissions"],                # destroy sched
        "GCKMS-006": ["Token-Permissions"],                # imported key
    },
)
