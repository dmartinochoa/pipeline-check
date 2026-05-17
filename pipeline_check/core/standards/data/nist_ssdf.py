"""NIST Secure Software Development Framework (SP 800-218 v1.1).

Subset covering the practices and tasks this scanner can evidence from
CI/CD state. The SSDF is grouped into four practice areas:

- PO. Prepare the Organization
- PS. Protect the Software
- PW. Produce Well-Secured Software
- RV. Respond to Vulnerabilities

Only the tasks for which at least one check produces evidence are
included. A single task may be evidenced by multiple checks, and a
single check may evidence multiple tasks across different practices.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="nist_ssdf",
    title="NIST Secure Software Development Framework",
    version="SP 800-218 v1.1",
    url="https://csrc.nist.gov/pubs/sp/800/218/final",
    controls={
        # Prepare the Organization
        "PO.3.2": "Implement and maintain supporting toolchains with security controls",
        "PO.3.3": "Configure the toolchain to generate an audit trail of SDLC activities",
        "PO.5.1": "Separate and protect each environment involved in software development",
        "PO.5.2": "Secure and harden endpoints used for software development",
        # Protect the Software
        "PS.1.1": "Store all forms of code based on least-privilege and tamper-resistance",
        "PS.2.1": "Make software integrity verification information available to acquirers",
        "PS.3.1": "Securely archive the necessary files and data for each software release",
        "PS.3.2": "Collect, safeguard, maintain, and share provenance data for releases",
        # Produce Well-Secured Software
        "PW.4.1": "Acquire and maintain well-secured 3rd-party software components",
        "PW.4.4": "Verify that acquired components are what is expected and behave as expected",
        "PW.6.1": "Use compiler, interpreter, and build tool features to improve security",
        "PW.9.1": "Configure software to have secure settings by default",
        # Respond to Vulnerabilities
        "RV.1.1": "Gather information about potential vulnerabilities in released software",
    },
    mappings={
        # CodeBuild
        "CB-001":   ["PS.1.1"],                        # plaintext secrets
        "CB-002":   ["PO.5.1", "PW.9.1"],              # privileged mode
        "CB-003":   ["PO.3.3"],                        # build logging disabled
        "CB-004":   ["PO.5.2", "PW.9.1"],              # no build timeout
        "CB-005":   ["PW.4.1", "PW.4.4", "RV.1.1"],    # outdated managed image
        "CB-006":   ["PS.1.1"],                        # long-lived source token
        "CB-007":   ["PO.5.1", "PW.9.1"],              # webhook no filter group
        # CodePipeline
        "CP-001":   ["PO.5.1"],                        # no manual approval
        "CP-002":   ["PS.1.1", "PS.3.1"],              # artifact store not CMK-encrypted
        "CP-003":   ["PO.3.2"],                        # polling source
        "CP-004":   ["PS.1.1"],                        # OAuth-token source
        # CodeDeploy
        "CD-001":   ["PO.3.2"],                        # no auto rollback
        "CD-002":   ["PO.5.1"],                        # AllAtOnce deployment
        "CD-003":   ["PO.3.3", "RV.1.1"],              # no CloudWatch alarm
        # ECR
        "ECR-001":  ["PW.4.4", "RV.1.1"],              # no image scan on push
        "ECR-002":  ["PS.3.1", "PS.3.2"],              # mutable tags
        "ECR-003":  ["PO.5.1", "PS.1.1"],              # public repo policy
        "ECR-004":  ["PO.3.2"],                        # no lifecycle policy
        "ECR-005":  ["PS.1.1"],                        # AES256 not CMK
        # IAM
        "IAM-001":  ["PO.5.1"],
        "IAM-002":  ["PO.5.1"],
        "IAM-003":  ["PO.5.1"],
        "IAM-004":  ["PO.5.1"],
        "IAM-005":  ["PO.5.1"],
        "IAM-006":  ["PO.5.1"],
        # PBAC
        "PBAC-001": ["PO.5.1", "PO.3.2"],              # no VPC for CodeBuild
        "PBAC-002": ["PO.5.1", "PO.3.2"],              # shared service role
        # S3 artifact store
        "S3-001":   ["PS.1.1"],                        # public access block
        "S3-002":   ["PS.1.1", "PS.3.1"],              # server-side encryption
        "S3-003":   ["PS.3.1", "PS.3.2"],              # versioning (provenance history)
        "S3-004":   ["PO.3.3"],                        # access logging
        "S3-005":   ["PS.1.1"],                        # SecureTransport deny
        # GitHub Actions
        "GHA-001":  ["PW.4.1", "PW.4.4"],              # action not pinned to SHA
        "GHA-002":  ["PO.5.1", "PW.9.1"],              # pull_request_target with PR head
        "GHA-003":  ["PW.6.1", "PW.9.1"],              # script injection
        "GHA-004":  ["PO.5.1"],                        # no explicit permissions
        "GHA-005":  ["PS.1.1"],                        # long-lived AWS keys
        # GitLab CI
        "GL-001":   ["PW.4.1", "PW.4.4"],
        "GL-002":   ["PW.6.1", "PW.9.1"],
        "GL-003":   ["PS.1.1"],
        "GL-004":   ["PO.5.1"],
        "GL-005":   ["PW.4.1", "PW.4.4"],
        # Bitbucket Pipelines
        "BB-001":   ["PW.4.1", "PW.4.4"],
        "BB-002":   ["PW.6.1", "PW.9.1"],
        "BB-003":   ["PS.1.1"],
        "BB-004":   ["PO.5.1"],
        "BB-005":   ["PO.5.2", "PW.9.1"],
        # Azure DevOps Pipelines
        "ADO-001":  ["PW.4.1", "PW.4.4"],
        "ADO-002":  ["PW.6.1", "PW.9.1"],
        "ADO-003":  ["PS.1.1"],
        "ADO-004":  ["PO.5.1"],
        "ADO-005":  ["PW.4.1", "PW.4.4"],
        # CircleCI
        "CC-001":   ["PW.4.1", "PW.4.4"],              # orb not pinned to SHA
        "CC-002":   ["PW.6.1", "PW.9.1"],              # script injection
        "CC-003":   ["PW.4.1", "PW.4.4"],              # image not pinned to digest
        "CC-004":   ["PS.1.1"],                        # unrestricted context
        "CC-005":   ["PS.1.1"],                        # long-lived AWS keys
        "CC-006":   ["PS.2.1", "PS.3.2"],              # unsigned artifacts
        "CC-007":   ["PS.3.2"],                        # no SBOM / provenance
        "CC-008":   ["PS.1.1"],                        # literal secrets in config
        "CC-009":   ["PO.5.1"],                        # no deployment approval
        "CC-010":   ["PO.5.2", "PW.9.1"],              # self-hosted runner
        "CC-011":   ["PO.3.3"],                        # no build retention
        "CC-012":   ["PW.6.1", "PW.9.1"],              # setup / dynamic config
        "CC-013":   ["PO.5.1"],                        # no branch filter
        "CC-014":   ["PO.5.1", "PO.5.2"],              # resource class isolation
        "CC-015":   ["PO.5.2", "PW.9.1"],              # no timeout
        "CC-016":   ["PW.4.1", "PW.4.4"],              # curl | bash
        "CC-017":   ["PO.5.2", "PW.9.1"],              # insecure Docker config
        "CC-018":   ["PW.4.1", "PW.4.4"],              # insecure package source
        "CC-019":   ["PS.1.1"],                        # SSH key in config
        "CC-020":   ["RV.1.1"],                        # no vulnerability scanning
        "CC-021":   ["PW.4.4"],                        # no lockfile
        "CC-022":   ["PW.4.1"],                        # no dependency updates
        "CC-023":   ["PW.4.4"],                        # TLS verification bypass
        # Buildkite — same shape as the other CI providers, mapped to
        # the corresponding tasks. Plugin / curl-pipe / TLS-bypass land
        # under PW.4.* (acquire / verify components); secret / signing
        # land under PS.* (protect software, integrity, provenance).
        "BK-001":   ["PW.4.1", "PW.4.4"],              # plugin not pinned
        "BK-002":   ["PS.1.1"],                        # literal secret
        "BK-003":   ["PW.6.1", "PW.9.1"],              # untrusted variable interp
        "BK-004":   ["PW.4.1", "PW.4.4"],              # curl-pipe
        "BK-005":   ["PO.5.1", "PW.9.1"],              # privileged container
        "BK-006":   ["PO.5.2", "PW.9.1"],              # no timeout
        "BK-007":   ["PO.5.1"],                        # no manual deploy gate
        "BK-008":   ["PW.4.4"],                        # TLS bypass
        "BK-009":   ["PS.2.1", "PS.3.2"],              # no signing
        "BK-010":   ["PS.3.2"],                        # no SBOM
        "BK-011":   ["PS.3.2"],                        # no SLSA provenance
        "BK-012":   ["RV.1.1"],                        # no vuln scan
        "BK-013":   ["PO.5.1"],                        # no branches filter
        # Dockerfile — image-build supply chain. Pinning / verification
        # rules tie to PW.4.* (acquire and verify 3rd-party components);
        # privileged / root / sensitive-path rules tie to PO.5.1 +
        # PW.9.1 (env separation, secure defaults); credential-shape
        # rules tie to PS.1.1 (least-privilege code storage).
        "DF-001":   ["PW.4.1", "PW.4.4"],              # FROM not digest-pinned
        "DF-002":   ["PO.5.1", "PW.9.1"],              # runs as root
        "DF-003":   ["PW.4.4", "PS.2.1"],              # ADD remote, no integrity
        "DF-004":   ["PW.4.1", "PW.4.4"],              # curl-pipe in RUN
        "DF-005":   ["PW.6.1", "PW.9.1"],              # shell-eval
        "DF-006":   ["PS.1.1"],                        # ENV credential literal
        "DF-007":   ["PO.3.3", "RV.1.1"],              # no HEALTHCHECK
        "DF-008":   ["PO.5.1", "PW.9.1"],              # docker --privileged
        "DF-009":   ["PW.6.1"],                        # ADD where COPY suffices
        "DF-010":   ["PW.4.1"],                        # apt dist-upgrade
        "DF-011":   ["PW.4.1"],                        # no cache cleanup
        "DF-012":   ["PO.5.1", "PW.9.1"],              # RUN sudo
        "DF-013":   ["PO.5.1", "PW.9.1"],              # sensitive EXPOSE
        "DF-014":   ["PW.9.1"],                        # WORKDIR /etc
        "DF-015":   ["PW.9.1"],                        # chmod 777
        "DF-016":   ["PS.3.2"],                        # no OCI provenance labels
        "DF-017":   ["PW.9.1"],                        # PATH world-writable
        "DF-018":   ["PW.9.1"],                        # chown system path
        "DF-019":   ["PS.1.1"],                        # COPY credential file
        "DF-020":   ["PS.1.1"],                        # credential-named ARG
        # Helm chart-supply-chain — every HELM-* rule scores a chart's
        # own posture (lockfile drift, transport, plaintext metadata),
        # so they ride mostly on PW.4.* (acquire / verify components)
        # and PS.3.* (provenance / archive). Hygiene fields (description,
        # maintainers, appVersion) tie to PO.3.3 audit trail.
        "HELM-001": ["PW.6.1"],                        # legacy apiVersion
        "HELM-002": ["PW.4.4", "PS.3.2"],              # no lockfile digests
        "HELM-003": ["PW.4.4", "PS.2.1"],              # non-HTTPS dep repo
        "HELM-004": ["PW.4.1", "PW.4.4"],              # dep version range
        "HELM-005": ["PO.3.3"],                        # missing maintainers
        "HELM-006": ["PO.5.1"],                        # missing kubeVersion
        "HELM-007": ["PO.3.3"],                        # missing description
        "HELM-008": ["PW.4.1"],                        # stale Chart.lock
        "HELM-009": ["PW.4.4"],                        # non-HTTPS home/sources
        "HELM-010": ["PO.3.3", "PS.3.2"],              # missing appVersion
        # ── Cloud Build (GCB) ────────────────────────────────────
        "GCB-001": ["PW.4.1", "PW.4.4"],               # step image not pinned
        "GCB-002": ["PS.1.1"],                         # plaintext env secret
        "GCB-003": ["PS.1.1"],                         # plain script secret
        "GCB-004": ["PW.4.1", "PW.4.4"],               # community step not SHA-pinned
        "GCB-005": ["PS.1.1"],                         # secret-shaped substitution
        "GCB-006": ["PO.3.3"],                         # build logging disabled
        "GCB-007": ["PW.4.1"],                         # latest secret version
        "GCB-008": ["PS.2.1", "PS.3.2"],               # no signing
        "GCB-009": ["PS.3.2"],                         # no SBOM
        "GCB-010": ["PO.5.1"],                         # default network egress
        "GCB-011": ["PW.4.4"],                         # TLS bypass
        "GCB-012": ["RV.1.1"],                         # no vuln scan
        "GCB-013": ["PS.1.1"],                         # default service account
        "GCB-014": ["PW.6.1", "PW.9.1"],               # untrusted substitution
        "GCB-015": ["PS.3.2"],                         # no provenance
        "GCB-016": ["PO.5.2", "PW.9.1"],               # no timeout
        "GCB-017": ["PO.3.3"],                         # default logs
        "GCB-018": ["PW.4.1"],                         # legacy gcr.io
        "GCB-019": ["PO.5.1", "PW.9.1"],               # privileged step
        "GCB-020": ["PS.1.1"],                         # default SA email
        "GCB-021": ["PO.5.1"],                         # no private worker pool
        "GCB-022": ["PW.6.1", "PW.9.1"],               # ALLOW_LOOSE substitution
        "GCB-023": ["PS.2.1", "PS.3.2"],               # build artifacts not signed
        "GCB-024": ["PS.3.2"],                         # missing provenance labels
        "GCB-025": ["PW.4.1"],                         # outdated runner image
        "GCB-026": ["PS.1.1"],                         # public storage bucket
        # ── SCM posture (governance via the platform REST API) ──────
        # The PS.1 family ("Protect all forms of code from
        # unauthorized access and tampering") is purpose-built for
        # SCM governance: branch protection, review gates, and
        # ruleset enforcement all evidence "store all forms of code
        # based on least-privilege and tamper-resistance". PS.2.1
        # carries integrity-verification surfaces (signed commits).
        # PW.4.x carries third-party action governance. PO.5.1
        # carries environment separation. RV.1.1 carries
        # vulnerability gathering.
        "SCM-001":  ["PS.1.1"],                        # default branch unprotected
        "SCM-002":  ["PS.1.1"],                        # required reviews missing
        "SCM-003":  ["RV.1.1"],                        # default code scanning disabled
        "SCM-004":  ["PS.1.1"],                        # secret scanning disabled
        "SCM-005":  ["PW.4.4", "RV.1.1"],              # Dependabot security updates off
        "SCM-006":  ["PS.2.1"],                        # signed commits not required
        "SCM-007":  ["PS.1.1"],                        # force-push allowed
        "SCM-008":  ["PS.1.1"],                        # required status checks missing
        "SCM-009":  ["PS.1.1"],                        # branch deletions allowed
        "SCM-010":  ["PS.1.1"],                        # admin bypass allowed
        "SCM-011":  ["PS.1.1"],                        # CODEOWNERS reviews not required
        "SCM-012":  ["PS.1.1"],                        # stale reviews not dismissed
        "SCM-013":  ["PS.1.1"],                        # conversation resolution not required
        "SCM-014":  ["PS.1.1"],                        # last-push approval not required
        "SCM-015":  ["PS.1.1"],                        # secret scanning push protection off
        "SCM-016":  ["RV.1.1"],                        # private vulnerability reporting off
        "SCM-017":  ["PS.1.1"],                        # CODEOWNERS file missing
        "SCM-018":  ["PS.1.1"],                        # PR review bypass allowed
        "SCM-019":  ["PS.1.1"],                        # push-restriction allowlist names users
        # Actions governance + environments + deploy keys
        "SCM-020":  ["PO.5.1", "PS.1.1"],              # workflow_token default write
        "SCM-021":  ["PS.1.1"],                        # Actions can approve PRs
        "SCM-022":  ["PW.4.1", "PW.4.4"],              # allowed_actions unrestricted
        "SCM-023":  ["PO.5.1"],                        # env missing reviewers
        "SCM-024":  ["PO.5.1"],                        # env branch policy missing
        "SCM-025":  ["PS.1.1"],                        # deploy keys write-enabled
        "SCM-026":  ["PO.3.2"],                        # webhook insecure / no HMAC
        "SCM-027":  ["PS.1.1"],                        # outside collaborator elevated
        "SCM-028":  ["PS.1.1"],                        # private repo allows forking
        # Ruleset enforcement
        "SCM-029":  ["PS.1.1"],                        # ruleset not enforced
        "SCM-030":  ["PS.1.1"],                        # ruleset always-bypass
        "SCM-031":  ["PS.1.1"],                        # auto-merge enabled
        "SCM-032":  ["PS.1.1"],                        # ruleset lacks PR review
        "SCM-033":  ["PS.1.1"],                        # ruleset lacks status_checks
        "SCM-034":  ["PS.1.1"],                        # ruleset allows force_push
        "SCM-035":  ["PS.1.1"],                        # ruleset allows deletion
        "SCM-036":  ["PS.2.1"],                        # ruleset lacks signed_commits
        "SCM-037":  ["PS.1.1"],                        # ruleset stale-review dismissal
        "SCM-038":  ["PS.1.1"],                        # ruleset lacks linear_history
        "SCM-039":  ["PS.1.1", "PW.6.1"],              # ruleset lacks required_workflows
        "SCM-040":  ["RV.1.1", "PS.1.1"],              # ruleset lacks code_scanning gate
    },
)
