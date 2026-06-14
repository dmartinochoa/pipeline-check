"""NIST SP 800-190. Application Container Security Guide (2017).

Purpose-built for container-based workloads. Section 4 enumerates
*risks* across images, registries, orchestrators, containers, and the
host OS. Section 5 enumerates *countermeasures*. This scanner's
container-adjacent rules (image pinning, privileged-mode, TLS bypass,
vulnerability scanning, embedded secrets) give direct evidence of
the Section 4 risk set.

Control IDs here use the SP 800-190 section numbering (e.g. "4.1.5"
for "Use of untrusted images"). The guide is not a formal control
list, but the numbered subsections are how compliance teams cite it.

Out of scope: orchestrator risks (4.3) and host OS risks (4.5) require
runtime-environment visibility the scanner does not have. Risks 4.3.1
(unbounded admin access to orchestrator) and 4.3.3 (workload sensitivity
mixing) are architectural concerns outside pipeline config.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="nist_800_190",
    title="NIST SP 800-190 Application Container Security",
    version="1.0 (Sep 2017)",
    url="https://doi.org/10.6028/NIST.SP.800-190",
    controls={
        # ── 4.1. Image risks ───────────────────────────────────────
        "4.1.1": "Image vulnerabilities, unpatched CVEs baked into images",
        "4.1.2": "Image configuration defects, privileged flags, insecure runtime settings",
        "4.1.3": "Embedded malware in images",
        "4.1.4": "Embedded clear-text secrets in images",
        "4.1.5": "Use of untrusted images, unpinned tags, unknown provenance",
        # ── 4.2. Registry risks ────────────────────────────────────
        "4.2.1": "Insecure connections to registries (no TLS / cert validation bypassed)",
        "4.2.2": "Stale images in registries, drift and unpatched images",
        "4.2.3": "Insufficient authentication and authorization restrictions on registries",
        # ── 4.4. Container risks ───────────────────────────────────
        "4.4.3": "Unbounded network access from containers, egress not restricted",
        "4.4.4": "Insecure container runtime configurations, privileged flag, host namespace sharing",
        "4.4.5": "App vulnerabilities, untrusted code paths reached at runtime",
        "4.4.6": "Rogue containers, unvetted images executed inside pipeline",
    },
    mappings={
        # ── 4.1.1. Image vulnerabilities ───────────────────────────
        # CB-005 / ECR-002 / GCB-007 also evidence 4.2.2 (stale/drift).
        "CB-005":   ["4.1.1", "4.2.2"],
        "ECR-001":  ["4.1.1"],
        "ECR-007":  ["4.1.1"],
        "GHA-020":  ["4.1.1"],
        "GL-019":   ["4.1.1"],
        "BB-015":   ["4.1.1"],
        "ADO-020":  ["4.1.1"],
        "JF-020":   ["4.1.1"],
        "CC-020":   ["4.1.1"],
        "GCB-008":  ["4.1.1"],

        # ── 4.1.2. Image configuration defects ─────────────────────
        "CB-002":   ["4.1.2", "4.4.4"],
        "GHA-017":  ["4.1.2", "4.4.4"],
        "GHA-026":  ["4.1.2", "4.4.3"],
        "GHA-107":  ["4.4.3"],            # harden-runner in audit mode (egress not blocked)
        "GHA-108":  ["4.4.3"],            # no runtime egress control on OIDC/deploy workflow
        "GHA-109":  ["4.4.3"],            # harden-runner not the first step
        "GL-017":   ["4.1.2", "4.4.4"],
        "GL-039":   ["4.1.2", "4.4.4"],# dind daemon TLS disabled / exposed on 2375
        "GL-041":   ["4.1.3"],# IaC apply on an untrusted MR trigger
        "BB-013":   ["4.1.2", "4.4.4"],
        "ADO-017":  ["4.1.2", "4.4.4"],
        "JF-017":   ["4.1.2", "4.4.4"],
        "JF-025":   ["4.1.2", "4.4.4"],
        "CC-017":   ["4.1.2", "4.4.4"],

        # ── 4.1.3. Embedded malware ────────────────────────────────
        "CB-011":   ["4.1.3"],
        "GHA-003":  ["4.1.3"],
        "GHA-119":  ["4.1.3"],# untrusted context into an agentic AI CLI
        "GHA-120":  ["4.1.3"],# trust_remote_code model load = code exec
        "GHA-122":  ["4.1.3"],# unsafe pickle deser of fetched artifact = code exec
        "GHA-117":  ["4.1.3"],# IaC apply on untrusted PR trigger
        "GHA-118":  ["4.1.3"],# untrusted content into $GITHUB_ENV / $GITHUB_PATH
        "GHA-016":  ["4.1.3"],
        "GHA-027":  ["4.1.3"],
        "GHA-028":  ["4.1.3"],
        "GL-002":   ["4.1.3"],
        "GL-045":   ["4.1.3"],# trust_remote_code model load = code exec
        "GL-047":   ["4.1.3"],# unsafe pickle deser of fetched artifact = code exec
        "GL-048":   ["4.1.3"],# untrusted MR context into agentic CLI = prompt injection
        "GL-016":   ["4.1.3"],
        "GL-025":   ["4.1.3"],
        "GL-026":   ["4.1.3"],
        "BB-002":   ["4.1.3"],
        "BB-035":   ["4.1.3"],   # trust_remote_code model load = code exec
        "CC-034":   ["4.1.3"],   # trust_remote_code model load = code exec (CircleCI)
        "CC-036":   ["4.1.3"],   # unsafe pickle deser of fetched artifact = code exec (CircleCI)
        "CC-037":   ["4.1.3"],   # agentic CLI ingests untrusted context (prompt injection) (CircleCI)
        "BB-036":   ["4.1.3"],   # untrusted PR context into agentic CLI = prompt injection
        "BB-037":   ["4.1.3"],   # unsafe pickle deser of fetched artifact = code exec
        "BB-012":   ["4.1.3"],
        "BB-025":   ["4.1.3"],
        "BB-026":   ["4.1.3"],
        "ADO-002":  ["4.1.3"],
        "ADO-034":  ["4.1.3"],   # trust_remote_code model load = code exec
        "ADO-035":  ["4.1.3"],   # untrusted PR context into agentic CLI = prompt injection
        "ADO-036":  ["4.1.3"],   # unsafe pickle deser of fetched artifact = code exec
        "ADO-016":  ["4.1.3"],
        "ADO-026":  ["4.1.3"],
        "ADO-027":  ["4.1.3"],
        "JF-002":   ["4.1.3"],
        "JF-037":   ["4.1.3"],   # agentic CLI ingests untrusted context (prompt injection)
        "JF-039":   ["4.1.3"],   # trust_remote_code model load = code exec
        "JF-041":   ["4.1.3"],   # unsafe pickle deser of fetched artifact = code exec
        "JF-016":   ["4.1.3"],
        "JF-029":   ["4.1.3"],
        "JF-030":   ["4.1.3"],
        "CC-002":   ["4.1.3"],
        "CC-016":   ["4.1.3"],
        "CC-026":   ["4.1.3"],
        "CC-027":   ["4.1.3"],
        "GCB-004":  ["4.1.3"],
        "GCB-006":  ["4.1.3"],

        # ── 4.1.4. Embedded clear-text secrets ─────────────────────
        "CB-001":   ["4.1.4"],
        "GHA-005":  ["4.1.4"],
        "GHA-008":  ["4.1.4"],
        "GL-003":   ["4.1.4"],
        "GL-008":   ["4.1.4"],
        "DEV-008":   ["4.1.4"],   # literal secret in a devenv config
        "GL-013":   ["4.1.4"],
        "BB-003":   ["4.1.4"],
        "BB-008":   ["4.1.4"],
        "BB-011":   ["4.1.4"],
        "BB-019":   ["4.1.4"],
        "ADO-003":  ["4.1.4"],
        "ADO-008":  ["4.1.4"],
        "ADO-014":  ["4.1.4"],
        "JF-008":   ["4.1.4"],
        "JF-010":   ["4.1.4"],
        "CC-005":   ["4.1.4"],
        "CC-008":   ["4.1.4"],
        "GCB-003":  ["4.1.4"],
        "LMB-003":  ["4.1.4"],

        # ── 4.1.5. Use of untrusted images (pinning + provenance) ──
        "CB-009":   ["4.1.5"],
        "ECR-002":  ["4.1.5", "4.2.2"],
        "ECR-006":  ["4.1.5"],
        "CA-002":   ["4.1.5"],
        "GHA-001":  ["4.1.5"],
        "GHA-018":  ["4.1.5"],
        "GHA-021":  ["4.1.5"],
        "GHA-025":  ["4.1.5"],
        "GHA-029":  ["4.1.5"],
        "GL-001":   ["4.1.5"],
        "GL-005":   ["4.1.5"],
        "GL-042":   ["4.1.5"],    # include: component unpinned
        "GL-009":   ["4.1.5"],
        "GL-018":   ["4.1.5"],
        "GL-021":   ["4.1.5"],
        "GL-027":   ["4.1.5"],
        "GL-028":   ["4.1.5"],
        "GL-030":   ["4.1.5"],
        "BB-001":   ["4.1.5"],
        "BB-009":   ["4.1.5"],
        "BB-014":   ["4.1.5"],
        "BB-021":   ["4.1.5"],
        "BB-027":   ["4.1.5"],
        "ADO-001":  ["4.1.5"],
        "ADO-005":  ["4.1.5"],
        "ADO-009":  ["4.1.5"],
        "ADO-018":  ["4.1.5"],
        "ADO-021":  ["4.1.5"],
        "ADO-025":  ["4.1.5"],
        "ADO-028":  ["4.1.5"],
        "JF-001":   ["4.1.5"],
        "JF-009":   ["4.1.5"],
        "JF-018":   ["4.1.5"],
        "JF-021":   ["4.1.5"],
        "JF-031":   ["4.1.5"],
        "CC-001":   ["4.1.5"],
        "CC-003":   ["4.1.5"],
        "CC-018":   ["4.1.5"],
        "CC-021":   ["4.1.5"],
        "CC-028":   ["4.1.5"],
        "CC-029":   ["4.1.5"],
        "GCB-001":  ["4.1.5"],
        "GCB-007":  ["4.1.5", "4.2.2"],
        # Helm chart-supply-chain, chart provenance is the chart-
        # equivalent of the image-pinning / untrusted-image story.
        # HELM-001 (legacy v1 schema) and HELM-004 (range version)
        # both leave the chart's dependency surface unverified at
        # render time; HELM-002 (no Chart.lock digests) is the
        # direct analog of an unpinned image tag.
        "HELM-001": ["4.1.5"],
        "HELM-002": ["4.1.5"],
        "HELM-004": ["4.1.5"],

        # ── 4.2.1. Insecure connections to registries ──────────────
        "GHA-023":  ["4.2.1"],
        "GL-023":   ["4.2.1"],
        "BB-023":   ["4.2.1"],
        "ADO-023":  ["4.2.1"],
        "JF-023":   ["4.2.1"],
        "CC-023":   ["4.2.1"],
        "S3-005":   ["4.2.1"],
        # HELM-003. Helm chart repos are the registry analog for
        # chart distribution; a non-HTTPS dep repository is the
        # exact pattern 4.2.1 calls out.
        "HELM-003": ["4.2.1"],

        # ── 4.2.2. Stale images / drift ────────────────────────────
        # CB-005 / ECR-002 / GCB-007 co-map up in 4.1.1 / 4.1.5 to
        # preserve a single dict-key per check_id.
        "ECR-004":  ["4.2.2"],

        # ── 4.2.3. Registry auth/authz restrictions ────────────────
        "ECR-003":  ["4.2.3"],
        "CA-004":   ["4.2.3"],
        "ECR-005":  ["4.2.3"],             # KMS-encrypted = authz to decrypt

        # ── 4.4.3. Unbounded container network access ──────────────
        "PBAC-001": ["4.4.3"],
        "PBAC-003": ["4.4.3"],
        "GHA-012":  ["4.4.3"],             # self-hosted runner = uncontrolled net
        "GHA-105":  ["4.4.3"],             # self-hosted runner on PR trigger
        "GL-014":   ["4.4.3"],
        "BB-016":   ["4.4.3"],
        "ADO-013":  ["4.4.3"],
        "JF-014":   ["4.4.3"],
        "CC-010":   ["4.4.3"],

        # ── 4.4.5. App vulnerabilities reached at runtime ──────────
        # Untrusted trigger paths that run untrusted code against
        # pipeline identity, poisoned pipeline execution.
        "CB-010":   ["4.4.5"],
        "GHA-002":  ["4.4.5"],
        "GHA-009":  ["4.4.5"],
        "GHA-010":  ["4.4.5"],
        "GHA-013":  ["4.4.5"],
        "GL-010":   ["4.4.5"],
        "GL-011":   ["4.4.5"],
        "BB-010":   ["4.4.5"],
        "ADO-010":  ["4.4.5"],
        "ADO-011":  ["4.4.5"],
        "ADO-019":  ["4.4.5"],
        "JF-012":   ["4.4.5"],
        "JF-013":   ["4.4.5"],
        "JF-019":   ["4.4.5"],
        "CC-012":   ["4.4.5"],

        # ── 4.4.6. Rogue / unvetted containers ─────────────────────
        "CP-003":   ["4.4.6"],             # polling source = rogue-commit window
        "CP-007":   ["4.4.6"],
        "GHA-011":  ["4.4.6"],             # poisoned cache
        "GL-012":   ["4.4.6"],
        "BB-018":   ["4.4.6"],
        "ADO-012":  ["4.4.6"],
        "CC-025":   ["4.4.6"],
        "CC-013":   ["4.4.6"],             # no branch filter = rogue input

        # ── Kubernetes manifests ────────────────────────────────────
        # K8s rules are doubly-mapped because most controls evidence
        # both an image-config defect (4.1.2) AND an insecure runtime
        # configuration (4.4.4, privileged, host-namespace sharing).
        # Orchestrator risks (4.3) are out of scope per the file
        # docstring, so K8S-019..021 (RBAC, namespace) intentionally
        # have no mapping here. They live in OWASP CICD-SEC-2/5.
        "K8S-001":  ["4.1.5"],
        "K8S-002":  ["4.4.4"],
        "K8S-003":  ["4.4.4"],
        "K8S-004":  ["4.4.4"],
        "K8S-005":  ["4.1.2", "4.4.4"],
        "K8S-006":  ["4.1.2", "4.4.4"],
        "K8S-007":  ["4.1.2", "4.4.4"],
        "K8S-008":  ["4.1.2", "4.4.4"],
        "K8S-009":  ["4.1.2", "4.4.4"],
        "K8S-010":  ["4.1.2", "4.4.4"],
        "K8S-011":  ["4.1.2"],
        "K8S-012":  ["4.1.2"],
        "K8S-013":  ["4.4.4"],
        "K8S-014":  ["4.4.4"],
        "K8S-015":  ["4.4.4"],
        "K8S-016":  ["4.4.4"],
        "K8S-017":  ["4.1.4"],
        "K8S-018":  ["4.1.4"],
        "K8S-022":  ["4.4.4"],
        "K8S-036":  ["4.1.5"],                           # SA imagePullSecret missing
        "K8S-037":  ["4.1.4"],                           # ConfigMap credential literal
        "K8S-039":  ["4.1.2", "4.4.4"],                  # shareProcessNamespace
        "K8S-040":  ["4.1.2", "4.4.4"],                  # procMount: Unmasked
        # Tekton. Tekton runs as Kubernetes-native pipeline kinds, so
        # the same runtime-hardening controls apply. Supply-chain
        # rules (TKN-009..012 signing/SBOM/provenance/vuln-scan) live
        # outside 800-190's scope and aren't mapped here.
        "TKN-001":  ["4.1.5"],
        "TKN-016": ["4.1.5"],  # remote resolver / bundle task body not pinned
        "TKN-002":  ["4.1.2", "4.4.4"],
        "TKN-004":  ["4.4.4"],
        "TKN-005":  ["4.1.4"],
        "TKN-013":  ["4.1.2", "4.4.4"],
        # Argo Workflows, same K8s-native runtime concerns. Supply-
        # chain rules (ARGO-009..012) are out of 800-190's scope.
        "ARGO-001": ["4.1.5"],
        "ARGO-002": ["4.1.2", "4.4.4"],
        "ARGO-004": ["4.4.4"],
        "ARGO-006": ["4.1.4"],
        "ARGO-013": ["4.1.2"],
        # ── Dockerfile (image build = container risk surface) ─────
        # Section 4.1 maps almost line-for-line to a Dockerfile's
        # threat model: 4.1.1 vulns baked into images, 4.1.2 config
        # defects (privileged, root, sensitive ports), 4.1.4
        # cleartext secrets in images, 4.1.5 untrusted images
        # (unpinned).
        "DF-001": ["4.1.5"],                       # FROM not digest-pinned
        "MODEL-001": ["4.1.5"],                    # unpinned base model
        "MODEL-002": ["4.1.5"],                    # third-party hub base model
        "MODEL-003": ["4.1.5"],                    # local unverified weights blob
        "MODEL-004": ["4.1.5"],                    # remote LoRA adapter
        "MODEL-005": ["4.1.5"],                    # config auto_map = custom loader code
        "DF-031": ["4.1.5"],                       # COPY --from external image not digest-pinned
        "DF-002": ["4.1.2", "4.4.4"],              # runs as root
        "DF-003": ["4.1.5", "4.2.1"],              # ADD remote, no integrity
        "DF-004": ["4.2.1"],                       # curl-pipe
        "DF-005": ["4.4.5"],                       # shell-eval
        "DF-006": ["4.1.4"],                       # ENV credential literal
        "DF-008": ["4.1.2", "4.4.4"],              # docker --privileged
        "DF-010": ["4.2.2"],                       # apt upgrade (drift)
        "DF-012": ["4.1.2", "4.4.4"],              # RUN sudo
        "DF-013": ["4.1.2", "4.4.3"],              # sensitive EXPOSE
        "DF-014": ["4.1.2"],                       # WORKDIR /etc
        "DF-015": ["4.1.2"],                       # chmod 777
        "DF-016": ["4.1.5"],                       # missing OCI provenance
        "DF-017": ["4.1.2"],                       # PATH world-writable
        "DF-018": ["4.1.2"],                       # chown system path
        "DF-019": ["4.1.4"],                       # COPY credential file
        "DF-020": ["4.1.4"],                       # credential ARG
        "DF-007": ["4.1.2"],                       # no HEALTHCHECK (image config defect)
        "DF-009": ["4.1.5"],                       # ADD where COPY suffices
        "DF-011": ["4.1.2"],                       # apt cache not cleaned
        # Env-bypass pack: TLS-disabling env vars break the trusted-
        # registry connection during in-image package installs
        # (4.2.1); runtime-affecting envs (LD_PRELOAD, NODE_OPTIONS)
        # are image-config defects (4.1.2) that reach untrusted code
        # paths at runtime (4.4.5).
        "DF-021": ["4.2.1"],                       # pip TLS bypass / http index
        "DF-022": ["4.1.5"],                       # npm install (not npm ci)
        "DF-023": ["4.1.2", "4.4.5"],              # LD_PRELOAD / LD_LIBRARY_PATH
        "DF-024": ["4.4.5"],                       # npm install runs lifecycle scripts
        "DF-025": ["4.1.4"],                       # registry token in image layer
        "DF-026": ["4.2.1"],                       # NODE_TLS_REJECT_UNAUTHORIZED=0
        "DF-027": ["4.2.1"],                       # PYTHONHTTPSVERIFY=0
        "DF-028": ["4.2.1"],                       # GIT_SSL_NO_VERIFY=1
        "DF-029": ["4.2.1"],                       # REQUESTS_CA_BUNDLE neutered
        "DF-030": ["4.1.2", "4.4.5"],              # NODE_OPTIONS --require / --inspect
        # ── NPM / PyPI / Maven dep supply-chain ──────────────────
        # Non-registry sources / HTTP / wildcard mirrors map to
        # 4.2.1 (insecure registry connection); floating / mutable
        # / missing-integrity rules map to 4.1.5 (untrusted images
        # analog for packages). Compromised packages = malware
        # (4.1.3). Install-time lifecycle scripts reach untrusted
        # code at runtime (4.4.5). Secrets in file globs are
        # cleartext-secret-in-image equivalents (4.1.4).
        "NPM-001":  ["4.1.5"],                     # floating range
        "NPM-002":  ["4.1.5"],                     # lock entry missing integrity
        "NPM-003":  ["4.2.1"],                     # non-registry source
        "NPM-004":  ["4.4.5"],                     # install-time lifecycle script
        "NPM-005":  ["4.1.5"],                     # git dep mutable ref
        "NPM-006":  ["4.1.3"],                     # compromised npm version
        "NPM-007":  ["4.4.5"],                     # .npmrc ignore-scripts
        "NPM-011":  ["4.1.4"],                     # secret-shaped paths in files field
        "NPM-013":  ["4.1.4"],                     # broad files-field publishes everything
        "PYPI-001": ["4.1.5"],                     # missing ==pin
        "PYPI-002": ["4.1.5"],                     # hash pinning missing
        "PYPI-003": ["4.2.1"],                     # http index / --trusted-host
        "PYPI-018": ["4.2.1"],  # --no-binary forces sdist build
        "PYPI-004": ["4.1.5"],                     # VCS dep without commit SHA
        "PYPI-015": ["4.1.5"],  # direct artifact URL
        "PYPI-005": ["4.2.1"],                     # --extra-index-url (dep confusion)
        "PYPI-017": ["4.2.1"],  # remote --find-links
        "PYPI-016": ["4.2.1"],  # primary index repointed
        "PYPI-006": ["4.1.3"],                     # compromised PyPI version
        "MVN-001":  ["4.1.5"],                     # floating Maven range
        "MVN-002":  ["4.1.5"],                     # mutable SNAPSHOT dep
        "MVN-003":  ["4.2.1"],                     # plaintext-HTTP repository
        "MVN-004":  ["4.1.5"],                     # missing <version>
        "MVN-005":  ["4.1.5"],                     # lax checksumPolicy
        "MVN-006":  ["4.1.3"],                     # compromised Maven version
        "MVN-007":  ["4.2.1"],                     # settings.xml wildcard mirror
        "MVN-008":  ["4.1.3"],                     # cooldown gate (--resolve-remote)
        "MVN-009":  ["4.1.3"],                     # OSV advisory (--resolve-remote)
        # ── Maven extended pack ──
        "MVN-010":  ["4.1.4"],                     # plaintext server password
        "MVN-011":  ["4.1.4"],                     # repo URL credentials
        "MVN-012":  ["4.1.3"],                     # build plugin floating
        "MVN-013":  ["4.1.3"],                     # build extension floating
        "MVN-014":  ["4.1.3"],                     # wrapper sha256 missing
        "MVN-015": ["4.1.3"],  # build-time plugin exec bound to lifecycle
        "MVN-016": ["4.1.3"],  # gradle allowInsecureProtocol
        "MVN-017": ["4.1.4"],  # settings.xml privateKey + plaintext passphrase
        "MVN-018": ["4.1.3"],  # distributionManagement release accepts snapshots
        "NPM-008":  ["4.1.3"],                     # cooldown gate (--resolve-remote)
        "NPM-009":  ["4.1.5"],                     # new-transitive-dep diff gate
        "NPM-010":  ["4.1.3"],                     # OSV advisory (--resolve-remote)
        "PYPI-008": ["4.1.3"],                     # cooldown gate (--resolve-remote)
        "PYPI-009": ["4.1.3"],                     # OSV advisory (--resolve-remote)
        # ── nuget (dep supply-chain) ─────────────────────────────
        "NUGET-001": ["4.1.5"],                    # floating NuGet version range
        "NUGET-002": ["4.1.5"],                    # wildcard prerelease version
        "NUGET-003": ["4.1.5"],                    # missing explicit version
        "NUGET-004": ["4.2.1"],                    # HTTP-only package source
        "NUGET-005": ["4.1.3"],                    # known-compromised package version
        "NUGET-006": ["4.1.5"],                    # no lock file for reproducible restores
        "NUGET-007": ["4.2.1"],                    # multiple sources without packageSourceMapping
        "NUGET-008": ["4.1.3"],                    # cooldown gate (--resolve-remote)
        "NUGET-009": ["4.1.3"],                    # OSV advisory (--resolve-remote)
        "NUGET-010": ["4.4.5"],                    # NuGet.config cleartext feed credential
        # ── NuGet extended pack ──
        "NUGET-011": ["4.1.3"],
        "NUGET-012": ["4.1.3"],
        "NUGET-013": ["4.1.3"],
        "NUGET-014": ["4.1.4"],
        "NUGET-015": ["4.1.3"],
        "NUGET-016": ["4.2.1"],  # missing <clear/> inherits public gallery
        "NUGET-017": ["4.2.1"],  # public gallery active alongside private feed, not disabled
        "NUGET-018": ["4.1.3"],  # build-time MSBuild execution
        "NUGET-019": ["4.1.3"],  # require mode, no trusted signers
        # ── Composer / PHP ──
        "COMPOSER-001": ["4.1.3"],
        "COMPOSER-002": ["4.1.3"],
        "COMPOSER-003": ["4.2.1"],
        "COMPOSER-012": ["4.2.1"],  # disables Packagist / marks custom repo canonical
        "COMPOSER-011": ["4.2.1"],  # external VCS repository re-points a package
        "COMPOSER-004": ["4.4.5"],
        "COMPOSER-005": ["4.1.3"],
        "COMPOSER-014": ["4.1.3"],  # minimum-stability without prefer-stable
        "COMPOSER-006": ["4.1.3"],
        "COMPOSER-007": ["4.1.3"],
        "COMPOSER-008": ["4.1.3"],
        "COMPOSER-009": ["4.4.5"],
        "COMPOSER-010": ["4.2.1"],
        "COMPOSER-013": ["4.2.1"],  # config.disable-tls
        # ── RubyGems / Bundler ──
        "GEM-001": ["4.1.3"],
        "GEM-002": ["4.1.3"],
        "GEM-003": ["4.2.1"],
        "GEM-004": ["4.4.5"],
        "GEM-005": ["4.1.3"],
        "GEM-006": ["4.1.3"],
        "GEM-007": ["4.1.3"],
        "GEM-008": ["4.1.3"],
        "GEM-009": ["4.4.5"],
        "GEM-010": ["4.1.3"],
        "GEM-011": ["4.1.3"],  # Bundler plugin install-time exec
        "GEM-012": ["4.1.3"],  # per-gem :source override
        "GEM-013": ["4.1.3"],  # insecure git transport
        # ── OCI image manifest gaps ──────────────────────────────
        # OCI-001..003/005 are image-provenance metadata gaps —
        # untrusted-image surface (4.1.5). OCI-004 foreign-layer
        # URL is insecure registry connection (4.2.1). OCI-006/007/
        # 008 are image-integrity failures (4.1.5).
        "OCI-001":  ["4.1.5"],                     # provenance annotations missing
        "OCI-002":  ["4.1.5"],                     # build attestation missing
        "OCI-003":  ["4.1.5"],                     # missing image.created
        "OCI-004":  ["4.2.1"],                     # foreign-layer URL reference
        "OCI-005":  ["4.1.5"],                     # missing image.licenses
        "OCI-006":  ["4.1.2"],                     # excessive layer count (image config)
        "OCI-007":  ["4.1.5"],                     # legacy schemaVersion 1
        "OCI-008":  ["4.1.5"],                     # weak digest algorithm
        "OCI-009":  ["4.1.5"],                     # missing base-image annotations
        # ── Helm chart provenance metadata ───────────────────────
        # The same chart-provenance surface that HELM-001..004
        # already map to 4.1.5 / 4.2.1 — these are the per-field
        # gaps in the chart's chain-of-custody / staleness story.
        "HELM-005": ["4.1.5"],                     # missing maintainers
        "HELM-006": ["4.1.5"],                     # kubeVersion compat range
        "HELM-007": ["4.1.5"],                     # missing description
        "HELM-008": ["4.2.2"],                     # stale Chart.lock > 90 days
        "HELM-009": ["4.2.1"],                     # non-HTTPS home / sources URL
        "HELM-010": ["4.1.5"],                     # missing appVersion
        # ── Helm extended pack ──
        "HELM-011": ["4.2.1"],                     # dependency URL embedded creds
        "HELM-012": ["4.1.5"],                     # deprecated without successor
        "HELM-013": ["4.1.5"],                     # invalid chart type
        "HELM-014": ["4.1.5"],                     # known-compromised dep
        "HELM-015": ["4.1.3"],  # oci:// dependency not digest-pinned
        "HELM-016": ["4.1.4"],  # default secret in values.yaml
        "HELM-017": ["4.1.3"],  # tpl of an untrusted .Values value
        # ── Buildkite (CI runner runs builds inside containers) ───
        # Mostly 4.1.2 / 4.4.4 (runtime config defects), 4.1.5
        # (untrusted images), 4.1.4 (secrets baked into env), and
        # 4.4.6 (rogue images executed inside the pipeline).
        "BK-001": ["4.1.5", "4.4.6"],              # plugin not pinned
        "BK-002": ["4.1.4"],                       # literal secret in env
        "BK-003": ["4.4.5"],                       # untrusted variable injection
        "BK-004": ["4.2.1", "4.4.6"],              # curl-pipe
        "BK-005": ["4.1.2", "4.4.4"],              # privileged container
        "BK-008": ["4.2.1"],                       # TLS bypass
        "BK-012": ["4.1.1"],                       # no vuln scan
        "BK-006": ["4.4.5"],                       # no timeout = unbounded build exec
        "BK-014": ["4.1.5"],                       # unpinned package install
        "BK-015": ["4.4.5"],                       # agents map untrusted interpolation
        # ── Per-CI provider container-relevant gaps ──────────────
        # Many CI rules don't fit 800-190 (governance, signing,
        # SBOM, audit, IAM, KMS are out of scope per the docstring).
        # Below are the rules that genuinely touch the image /
        # registry / container risk surface: unbounded exec
        # (4.4.5), unpinned image-shaped refs (4.1.5), TLS bypass
        # (4.2.1), credential leakage into the container env (4.1.4),
        # untrusted-trigger code paths reaching the runner (4.4.5),
        # and dangerous shell idioms that get evaluated against an
        # image's contents (4.1.3 malware shape, 4.4.5 untrusted code).
        # ── CodeBuild ─────────────────────────────────────────────
        "CB-004":   ["4.4.5"],                     # no timeout (unbounded build)
        "CB-006":   ["4.1.4"],                     # long-lived source token = pipeline cred
        "CB-007":   ["4.4.6"],                     # webhook no filter = rogue build trigger
        "CB-008":   ["4.4.6"],                     # inline buildspec = rogue input
        # ── CodePipeline ──────────────────────────────────────────
        "CP-004":   ["4.1.4"],                     # OAuth-token source = pipeline cred
        # ── CodeArtifact / PBAC ──────────────────────────────────
        "CA-003":   ["4.2.3"],                     # CodeArtifact cross-account wildcard
        "PBAC-002": ["4.4.3"],                     # shared service role
        # ── GitHub Actions container-touching extras ─────────────
        "GHA-015":  ["4.4.5"],                     # no timeout
        "GHA-019":  ["4.1.5"],                     # install without lockfile
        "GHA-022":  ["4.2.1"],                     # TLS / cert verification bypass
        "GHA-031":  ["4.4.5"],                     # retired set-output / save-state
        "GHA-032":  ["4.4.5"],                     # local script on untrusted trigger
        "GHA-033":  ["4.1.4"],                     # secret echoed
        "GHA-034":  ["4.1.4"],                     # secrets: inherit
        "GHA-116":  ["4.1.4"],                     # bulk secrets serialization
        "GHA-035":  ["4.4.5"],                     # github-script untrusted context
        "GHA-036":  ["4.4.5"],                     # runs-on untrusted context
        "GHA-037":  ["4.1.4"],                     # checkout persists GITHUB_TOKEN
        "GHA-038":  ["4.4.5"],                     # ACTIONS_ALLOW_UNSECURE_COMMANDS
        "GHA-039":  ["4.1.4"],                     # services / container creds literal
        "GHA-040":  ["4.1.5", "4.1.3"],            # known-compromised action ref
        "GHA-041":  ["4.1.5"],                     # single-maintainer action
        "GHA-042":  ["4.1.5"],                     # very-young action repo
        "GHA-043":  ["4.1.5"],                     # low-star + sensitive perms
        "GHA-044":  ["4.4.5"],                     # build-tool PPE
        "GHA-045":  ["4.4.5"],                     # caller-ref input drives checkout
        "GHA-046":  ["4.4.5"],                     # manual PR-head fetch
        "GHA-047":  ["4.1.5"],                     # fresh-ref cooldown
        "GHA-051":  ["4.1.5"],                     # services / container image unpinned
        "GHA-052":  ["4.4.6"],                     # cache key poisoning
        "GHA-053":  ["4.4.5"],                     # if: predicate untrusted-context
        "GHA-054":  ["4.1.4"],                     # checkout ssh-key persists
        "GHA-055":  ["4.1.4"],                     # reusable outputs leak secret
        "GHA-056":  ["4.1.3"],                     # supply-chain worm IOC strings
        "GHA-057":  ["4.4.3"],                     # secret-scanner output → egress
        "GHA-058":  ["4.4.5"],                     # agentic CLI permission-bypass
        "GHA-059":  ["4.1.5"],                     # npm install without audit signatures
        "GHA-060":  ["4.1.5"],                     # pip install without --require-hashes
        "GHA-092":  ["4.4.5"],                     # TOCTOU PR head SHA force-push race
        # ── GitLab CI container-touching extras ──────────────────
        "GL-015":  ["4.4.5"],                      # no timeout
        "GL-020":  ["4.1.4"],                      # CI_JOB_TOKEN persisted
        "GL-022":  ["4.1.5"],                      # dep-update bypasses lockfile pins
        "GL-032":  ["4.4.5"],                      # tags untrusted variable
        "GL-033":  ["4.4.5"],                      # global before_script taint
        "GL-034":  ["4.1.5"],                      # npm install without audit signatures
        "GL-035":  ["4.1.5"],                      # pip install without --require-hashes
        # ── Bitbucket Pipelines container-touching extras ────────
        "BB-005":  ["4.1.2", "4.4.4"],             # privileged container (in pipe)
        "BB-017":  ["4.1.4"],                      # repo token persisted
        "BB-022":  ["4.1.5"],                      # dep-update bypasses lockfile pins
        "BB-029":  ["4.1.5"],                      # step+service image not pinned
        "BB-030":  ["4.1.5"],                      # npm install without audit signatures
        "BB-031":  ["4.1.5"],                      # pip install without --require-hashes
        # ── Azure DevOps Pipelines container-touching extras ─────
        "ADO-015": ["4.4.5"],                      # no timeoutInMinutes
        "ADO-022": ["4.1.5"],                      # dep-update bypasses lockfile pins
        "ADO-030": ["4.4.5"],                      # pool interpolates untrusted
        # ── Jenkins container-touching extras ────────────────────
        "JF-003":  ["4.4.6"],                      # agent any = rogue executor
        "JF-004":  ["4.1.4"],                      # long-lived AWS via withCredentials
        "JF-015":  ["4.4.5"],                      # no timeout
        "JF-022":  ["4.1.5"],                      # dep-update bypasses lockfile pins
        "JF-026":  ["4.4.6"],                      # build job: trigger ignores downstream failure
        "JF-032":  ["4.4.5"],                      # agent label interpolates untrusted
        "JF-033":  ["4.1.4"],                      # withCredentials leaked via Groovy ${}
        "JF-034":  ["4.1.4"],                      # password() build parameter
        "JF-035":  ["4.2.1"],                      # httpRequest SSL off
        # ── CircleCI container-touching extras ───────────────────
        "CC-004":  ["4.1.4"],                      # unrestricted context
        "CC-014":  ["4.4.3"],                      # resource class isolation
        "CC-015":  ["4.4.5"],                      # no timeout
        "CC-019":  ["4.1.4"],                      # SSH key in config
        "CC-022":  ["4.1.5"],                      # dep-update bypasses lockfile pins
        # ── Drone CI ─────────────────────────────────────────────
        "DR-001":  ["4.1.5"],                      # step image not digest-pinned
        "HARNESS-001":   ["4.1.5"],  # Harness step image not digest-pinned
        "HARNESS-002":   ["4.4.5"],  # Harness expression injection in step command
        "HARNESS-003":   ["4.1.2", "4.4.4"],  # Harness privileged step
        "HARNESS-004":   ["4.1.4"],  # Harness literal credential in variable
        "HARNESS-005":   ["4.1.5", "4.4.5"],  # Harness pipe-to-shell
        "HARNESS-006":   ["4.2.1"],  # Harness TLS bypass in commands
        "HARNESS-007":   ["4.4.4"],  # Harness sensitive host-path mount
        "HARNESS-008":   ["4.1.3"],  # Harness agentic-CLI prompt injection
        "HARNESS-010":   ["4.1.3"],  # Harness model trust_remote_code (code exec)
        "HARNESS-011":   ["4.1.3"],  # Harness unsafe model deser (pickle RCE)
        "DR-002":  ["4.1.2", "4.4.4"],             # privileged step
        "DR-003":  ["4.4.5"],                      # Drone variable injection
        "DR-004":  ["4.1.4"],                      # literal credential
        "DR-005":  ["4.1.5"],                      # plugin floating tag
        "DR-006":  ["4.2.1"],                      # TLS bypass in commands
        "DR-007":  ["4.4.4"],                      # sensitive host-path mount
        "DR-008":  ["4.1.5"],                      # pull: never (skips registry verify)
        "DR-009":  ["4.4.6"],                      # cache key tainted = rogue input
        "DR-010":  ["4.1.5"],                      # unpinned package install
        "DR-011":  ["4.4.5"],                      # node map interpolates untrusted
        # ── Drone extended pack ──
        "DR-012":  ["4.1.5"],                      # service image not pinned
        "DR-013":  ["4.4.5"],                      # no trigger event filter
        "DR-014":  ["4.1.5", "4.4.5"],             # pipe-to-shell
        "DR-015":  ["4.4.5"],                      # clone recursive
        "DR-016":  ["4.4.5"],                      # image field interpolation
        # ── Tekton container-touching extras ─────────────────────
        "TKN-003": ["4.4.5"],                      # param injection in script
        "TKN-006": ["4.4.5"],                      # no timeout
        "TKN-008": ["4.2.1"],                      # remote install / TLS
        "TKN-014": ["4.1.5"],                      # unpinned package install
        "TKN-015": ["4.4.5"],                      # workspace subPath param injection
        # ── Argo Workflows container-touching extras ─────────────
        "ARGO-005": ["4.4.5"],                     # parameter injection in script
        "ARGO-017": ["4.4.5"],                     # resource template manifest injection
        "ARGO-007": ["4.4.5"],                     # missing activeDeadlineSeconds
        "ARGO-008": ["4.2.1"],                     # remote install / TLS bypass
        "ARGO-014": ["4.1.5"],                     # unpinned package install
        "ARGO-015": ["4.2.1"],                     # insecure (non-HTTPS) artifact URL
        # ── Cloud Build container-touching extras ────────────────
        "GCB-005": ["4.4.5"],                      # no timeout
        "GCB-010": ["4.2.1"],                      # remote script piped to shell
        "GCB-011": ["4.2.1"],                      # TLS bypass
        "GCB-012": ["4.1.4"],                      # literal secret in pipeline body
        "GCB-013": ["4.1.5"],                      # pkg install bypasses registry integrity
        "GCB-016": ["4.4.5"],                      # dir path escape
        "GCB-018": ["4.1.4"],                      # legacy KMS secrets block
        "GCB-019": ["4.4.5"],                      # shell entrypoint + user substitution
        "GCB-021": ["4.4.3"],                      # no private worker pool
        "GCB-022": ["4.4.5"],                      # ALLOW_LOOSE substitution
        "GCB-023": ["4.4.5"],                      # undeclared user substitution
        # ── Cross-cutting dataflow / taint engine ────────────────
        # Cross-step / cross-job untrusted-data flow into privileged
        # build sinks is the canonical 4.4.5 shape — an app
        # vulnerability path where untrusted input reaches code
        # executed in the build container.
        "TAINT-001": ["4.4.5"],
        "TAINT-002": ["4.4.5"],
        "TAINT-003": ["4.4.5"],
        "TAINT-004": ["4.4.5"],
        "TAINT-005": ["4.4.5"],
        "TAINT-006": ["4.4.5"],
        "TAINT-007": ["4.4.5"],
        "TAINT-008": ["4.4.5"],
        # ── SCM-022 (untrusted actions allowed) ──────────────────
        # The one SCM rule that genuinely touches 800-190's surface
        # — unrestricted ``allowed_actions`` lets any 3rd-party
        # action run in the build (analog of an untrusted image
        # being pulled into the pipeline). Other SCM rules cover
        # source-side governance, not container risk.
        "SCM-022": ["4.1.5"],
        # ── Azure Cloud (container-adjacent rules) ────────────────────
        "AZST-001":  ["4.2.3"],                    # public blob access (registry auth/authz)
        "AZST-002":  ["4.2.1"],                    # non-HTTPS traffic (insecure registry conn)
        "AZST-003":  ["4.2.3"],                    # no CMK encryption
        "AKV-001":   ["4.1.4"],                    # soft delete off (secret recoverability)
        "AKV-002":   ["4.1.4"],                    # purge protection off
        "AKV-003":   ["4.2.3"],                    # network ACLs allow all
        "ACR-001":   ["4.2.3"],                    # admin user enabled
        "ACR-002":   ["4.2.3"],                    # public network access
        "ACR-003":   ["4.1.5"],                    # content trust not enabled
        # ── GCP (container-adjacent rules) ────────────────────────────
        "GCS-001":   ["4.2.3"],                    # public bucket
        "GCS-002":   ["4.2.3"],                    # no uniform access
        "GCKMS-002": ["4.2.3"],                    # public KMS key access
        "GAR-001":   ["4.1.1"],                    # no vulnerability scanning
        "GAR-002":   ["4.2.3"],                    # publicly readable repo
        "GAR-003":   ["4.2.2"],                    # no cleanup policy (stale images)
        # ── Azure Cloud phase-2 (container-adjacent rules) ───────────
        "AZST-004":  ["4.2.1"],                    # min TLS (insecure registry conn)
        "ACR-004":   ["4.1.1"],                    # defender scan (image vulns)
        "ACR-005":   ["4.1.5"],                    # tag immutability (untrusted images)
        "AZNW-001":  ["4.4.3"],                    # SSH/RDP internet (unbounded net)
        "AZNW-002":  ["4.4.3"],                    # flow logs
        "AZNW-004":  ["4.4.3"],                    # deny-all
        "AZNW-005":  ["4.4.3"],                    # public IP VM
        "AZAPP-001": ["4.2.1"],                    # HTTPS (insecure conn)
        "AZAPP-002": ["4.2.1"],                    # TLS
        "AZSQL-003": ["4.4.3"],                    # public access
        "AZVM-001":  ["4.1.4"],                    # disk encrypt (secret at rest)
        "AZVM-002":  ["4.4.3"],                    # public IP
        "AZVM-004":  ["4.1.1"],                    # OS patch (image vulns)
        # ── GCP phase-2 (container-adjacent rules) ───────────────────
        "GCNET-001": ["4.4.3"],                    # default network
        "GCNET-002": ["4.4.3"],                    # deny-all
        "GCNET-003": ["4.4.3"],                    # SSH/RDP (CRITICAL)
        "GCNET-004": ["4.4.3"],                    # private access
        "GCNET-005": ["4.4.3"],                    # Cloud NAT
        "GCCE-001":  ["4.1.2"],                    # shielded VM (config defect)
        "GCCE-002":  ["4.1.2"],                    # OS Login
        "GCCE-003":  ["4.4.4"],                    # serial port (runtime config)
        "GCCE-004":  ["4.4.3"],                    # public IP
        "GCCE-005":  ["4.1.2"],                    # project SSH keys
        "GCSQL-001": ["4.4.3"],                    # public IP
        "GCSQL-003": ["4.2.1"],                    # SSL (insecure conn)
        "GCRUN-001": ["4.2.3"],                    # unauth (registry auth)
        "GCRUN-002": ["4.1.2"],                    # custom SA
        "GCRUN-004": ["4.4.3"],                    # VPC connector
    },
)
