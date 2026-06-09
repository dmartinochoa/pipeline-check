"""SOC 2. Trust Services Criteria (AICPA).

SOC 2 organizes its Trust Services Criteria into five categories:
Security (required), Availability, Processing Integrity,
Confidentiality, and Privacy. The Security category is expressed via
the Common Criteria (CC1–CC9), which apply across all trust services.

This scanner evidences the CC-series criteria that have a concrete
CI/CD pipeline footprint, primarily CC6 (logical access), CC7
(system operations / anomaly detection), and CC8 (change management).
CC1 (control environment), CC2 (communication), CC3 (risk
assessment), CC4 (monitoring), CC5 (control activities), and CC9
(risk mitigation) are organizational/process criteria that don't
reduce to pipeline config and are intentionally unmapped.

The mappings are intentionally *indicative*, not *sufficient*. SOC 2
attestation requires auditor-reviewed evidence of control operation
over time, not just a point-in-time config scan. Findings here
identify *gaps* in the config substrate that typical SOC 2 controls
sit on top of; passing all mapped checks does not by itself demonstrate
compliance.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="soc2",
    title="SOC 2 Trust Services Criteria",
    version="2017 (revised 2022)",
    url="https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022",
    controls={
        # ── CC6. Logical and Physical Access ───────────────────────
        "CC6.1": "Logical access controls restrict entities to authorized system resources",
        "CC6.2": "New internal and external users are registered, authorized, and provisioned",
        "CC6.3": "Access modifications (including revocation) are tracked and timely",
        "CC6.6": "Boundary-protection measures restrict access from outside the system boundary",
        "CC6.7": "Data in transit is protected from unauthorized disclosure",
        "CC6.8": "Controls prevent or detect the introduction of malicious software",
        # ── CC7. System Operations ─────────────────────────────────
        "CC7.1": "Detection procedures identify configuration changes that introduce vulnerabilities",
        "CC7.2": "System components are monitored for anomalies indicative of malicious acts or failures",
        "CC7.3": "Security events are evaluated to determine if they require response",
        "CC7.4": "Identified security incidents trigger a response process",
        # ── CC8. Change Management ─────────────────────────────────
        "CC8.1": (
            "Changes to infrastructure, data, software, and procedures are "
            "authorized, designed, tested, approved, and implemented"
        ),
    },
    mappings={
        # ── CC6.1. Logical access controls ─────────────────────────
        "IAM-001":  ["CC6.1"],
        "IAM-002":  ["CC6.1"],
        "IAM-003":  ["CC6.1"],
        "IAM-004":  ["CC6.1"],
        "IAM-006":  ["CC6.1"],
        "KMS-002":  ["CC6.1"],
        "GHA-004":  ["CC6.1"],
        "GHA-019":  ["CC6.1"],
        "GL-020":   ["CC6.1"],
        "BB-017":   ["CC6.1"],
        "CC-030":   ["CC6.1"],
        "GCB-002":  ["CC6.1"],
        "CCM-003":  ["CC6.1"],
        "CA-004":   ["CC6.1"],
        "PBAC-001": ["CC6.1"],
        "PBAC-002": ["CC6.1"],
        "PBAC-003": ["CC6.1"],
        "PBAC-005": ["CC6.1"],

        # ── CC6.2 / CC6.3. User provisioning & trust relationships ─
        "IAM-005":  ["CC6.2", "CC6.3"],    # relaxed external trust = weak provisioning
        "IAM-007":  ["CC6.3"],             # stale access keys = untimely revocation
        "IAM-008":  ["CC6.2"],             # OIDC audience pin = federated authz
        "IAM-009":  ["CC6.2"],             # Azure WIF broad subject
        "IAM-010":  ["CC6.2"],             # GCP WIF no repo condition
        "CB-006":   ["CC6.3"],             # long-lived source token
        "CP-004":   ["CC6.3"],             # legacy OAuth = non-revocable token
        "GHA-005":  ["CC6.2", "CC6.3"],
        "GHA-008":  ["CC6.2"],
        "GL-003":   ["CC6.2"],
        "GL-008":   ["CC6.2"],
        "DEV-008":   ["CC6.2"],   # literal secret in a devenv config
        "GL-013":   ["CC6.2", "CC6.3"],
        "BB-003":   ["CC6.2"],
        "BB-008":   ["CC6.2"],
        "BB-011":   ["CC6.2", "CC6.3"],
        "ADO-003":  ["CC6.2"],
        "ADO-008":  ["CC6.2"],
        "ADO-014":  ["CC6.2", "CC6.3"],
        "JF-004":   ["CC6.2", "CC6.3"],
        "JF-008":   ["CC6.2"],
        "JF-010":   ["CC6.2"],
        "JF-033":   ["CC6.1", "CC6.2"],   # withCredentials leaked via Groovy ${}
        "JF-034":   ["CC6.1"],             # password() build parameter
        "CC-005":   ["CC6.2", "CC6.3"],
        "CC-008":   ["CC6.2"],
        "CC-019":   ["CC6.3"],
        "CB-001":   ["CC6.2"],
        "GCB-003":  ["CC6.2"],
        # GCB-007 co-maps: secret-alias (CC6.3) + drift-hide (CC7.1).
        "GCB-007":  ["CC6.3", "CC7.1"],

        # ── CC6.6. Boundary protection ─────────────────────────────
        "CB-002":   ["CC6.6"],             # privileged mode breaks sandbox boundary
        "GHA-017":  ["CC6.6"],
        "GL-017":   ["CC6.6"],
        "GL-039":   ["CC6.6"],# dind daemon TLS disabled / exposed on 2375
        "BB-013":   ["CC6.6"],
        "ADO-017":  ["CC6.6"],
        "JF-017":   ["CC6.6"],
        "CC-017":   ["CC6.6"],
        "JF-025":   ["CC6.6"],             # k8s privileged
        "GHA-026":  ["CC6.6"],             # container egress
        "GHA-107":  ["CC6.6"],             # harden-runner in audit mode (egress not blocked)
        "GHA-108":  ["CC6.6"],             # no runtime egress control on OIDC/deploy workflow
        "GHA-109":  ["CC6.6"],             # harden-runner not the first step
        "GHA-012":  ["CC6.6"],             # self-hosted runner
        "GHA-105":  ["CC6.6"],             # self-hosted runner on PR trigger
        "GL-014":   ["CC6.6"],
        "BB-016":   ["CC6.6"],
        "ADO-013":  ["CC6.6"],
        "JF-003":   ["CC6.6"],
        "JF-014":   ["CC6.6"],
        "CC-010":   ["CC6.6"],
        "ECR-003":  ["CC6.6"],             # public repo
        "S3-001":   ["CC6.6"],             # public artifact bucket
        "S3-002":   ["CC6.1"],             # bucket not encrypted at rest
        "LMB-002":  ["CC6.6"],             # public Lambda URL
        "LMB-004":  ["CC6.6"],             # public Lambda policy
        "SM-002":   ["CC6.6"],             # Secrets Manager public
        "CP-003":   ["CC6.6"],             # polling source leaks cred to SCM
        "CP-007":   ["CC6.6"],

        # ── CC6.7. Data in transit ─────────────────────────────────
        # S3-005 covers both boundary (6.6) and transit (6.7): the
        # bucket policy deny of non-TLS requests is a boundary control
        # whose effect is transit protection.
        "S3-005":   ["CC6.6", "CC6.7"],
        "GHA-023":  ["CC6.7"],
        "GL-023":   ["CC6.7"],
        "BB-023":   ["CC6.7"],
        "ADO-023":  ["CC6.7"],
        "JF-023":   ["CC6.7"],
        "JF-035":   ["CC6.7"],             # httpRequest ignoreSslErrors
        "CC-023":   ["CC6.7"],

        # ── CC6.8. Malicious software prevention / detection ───────
        "CB-011":   ["CC6.8"],
        "GHA-003":  ["CC6.8"],             # script injection = malware vector
        "GHA-119":  ["CC6.8"],             # untrusted context into an agentic AI CLI
        "GHA-120":  ["CC6.8"],             # trust_remote_code model load = code exec
        "GHA-122":  ["CC6.8"],             # unsafe pickle deser of fetched artifact = code exec
        "GHA-117":  ["CC6.8"],             # IaC apply on untrusted PR trigger
        "GHA-118":  ["CC6.8"],             # untrusted content into $GITHUB_ENV / $GITHUB_PATH
        "GHA-016":  ["CC6.8"],             # curl|bash = malware vector
        "GHA-020":  ["CC6.8"],             # vuln scanning
        "GHA-027":  ["CC6.8"],             # malicious activity
        "GHA-028":  ["CC6.8"],             # shell eval
        "GL-002":   ["CC6.8"],
        "GL-045":   ["CC6.8"],   # trust_remote_code model load = code exec
        "GL-047":   ["CC6.8"],   # unsafe pickle deser of fetched artifact = code exec
        "GL-048":   ["CC6.8"],   # untrusted MR context into agentic CLI = prompt injection
        "GL-049":   ["CC8.1"],   # agentic CLI output lands without review
        "GL-016":   ["CC6.8"],
        "GL-019":   ["CC6.8"],
        "GL-043":   ["CC6.8"],
        "GL-025":   ["CC6.8"],
        "GL-026":   ["CC6.8"],
        "BB-002":   ["CC6.8"],
        "BB-035":   ["CC6.8"],   # trust_remote_code model load = code exec
        "BB-012":   ["CC6.8"],
        "BB-015":   ["CC6.8"],
        "BB-025":   ["CC6.8"],
        "BB-026":   ["CC6.8"],
        "ADO-002":  ["CC6.8"],
        "ADO-016":  ["CC6.8"],
        "ADO-020":  ["CC6.8"],
        "ADO-026":  ["CC6.8"],
        "ADO-027":  ["CC6.8"],
        "JF-002":   ["CC6.8"],
        "JF-016":   ["CC6.8"],
        "JF-020":   ["CC6.8"],
        "JF-029":   ["CC6.8"],
        "JF-030":   ["CC6.8"],
        "CC-002":   ["CC6.8"],
        "CC-016":   ["CC6.8"],
        "CC-020":   ["CC6.8"],
        "CC-026":   ["CC6.8"],
        "CC-027":   ["CC6.8"],
        "GCB-006":  ["CC6.8"],
        "GCB-008":  ["CC6.8"],
        "ECR-001":  ["CC6.8"],
        "ECR-007":  ["CC6.8"],

        # ── CC7.1. Change-introduced vulnerability detection ──────
        "CB-005":   ["CC7.1"],             # outdated build image = unpatched vuln
        "ECR-002":  ["CC7.1"],             # mutable tags hide drift
        # GCB-007 co-mapped up under CC6.3.

        # ── CC7.2. Monitoring for anomalies ───────────────────────
        "CB-003":   ["CC7.2"],             # build logs disabled
        # CloudTrail / CloudWatch / EventBridge co-map: the same
        # signal source feeds CC7.2 (monitoring), CC7.3 (event
        # evaluation), and CC7.4 (response trigger).
        "CT-001":   ["CC7.2", "CC7.3"],
        "CT-002":   ["CC7.2", "CC7.3"],
        "CT-003":   ["CC7.2", "CC7.3"],
        "CWL-001":  ["CC7.2"],
        "CWL-002":  ["CC7.2"],
        "EB-001":   ["CC7.2", "CC7.3", "CC7.4"],
        "CW-001":   ["CC7.2", "CC7.3", "CC7.4"],
        "S3-003":   ["CC7.2"],             # versioning = tamper detection
        "S3-004":   ["CC7.2"],             # access logging
        "JF-011":   ["CC7.2"],             # build retention
        "CC-011":   ["CC7.2"],             # build retention

        # ── CC7.3 / CC7.4. Event evaluation & response ────────────
        "CD-001":   ["CC7.4"],             # auto-rollback = response
        "CD-003":   ["CC7.3", "CC7.4"],    # CW alarm on deploy group

        # ── CC8.1. Change management ──────────────────────────────
        # Approval gates
        "CP-001":   ["CC8.1"],
        "CP-005":   ["CC8.1"],
        "CD-002":   ["CC8.1"],
        "CCM-001":  ["CC8.1"],
        "CB-008":   ["CC8.1"],
        "GHA-014":  ["CC8.1"],
        "GHA-123":  ["CC8.1"],
        "GL-004":   ["CC8.1"],
        "GL-044":   ["CC8.1"],
        "GL-029":   ["CC8.1"],
        "BB-004":   ["CC8.1"],
        "BB-034":   ["CC8.1"],
        "ADO-004":  ["CC8.1"],
        "JF-005":   ["CC8.1"],
        "JF-024":   ["CC8.1"],
        "JF-026":   ["CC8.1"],
        "CC-009":   ["CC8.1"],
        "CC-013":   ["CC8.1"],
        # Pinning (changes require explicit review, not silent drift)
        "GHA-001":  ["CC8.1"],
        "GHA-110": ["CC8.1"],  # CI env disables Go module verification
        "GHA-025":  ["CC8.1"],
        "GL-001":   ["CC8.1"],
        "GL-037": ["CC8.1"],  # CI env disables Go module verification
        "GL-005":   ["CC8.1"],
        "GL-042":   ["CC8.1"],
        "BB-001":   ["CC8.1"],
        "ADO-001":  ["CC8.1"],
        "ADO-025":  ["CC8.1"],
        "JF-001":   ["CC8.1"],
        "CC-001":   ["CC8.1"],
        "CC-033": ["CC8.1"],  # CI env disables Go module verification
        "GCB-001":  ["CC8.1"],
        # Integrity / attestation (change record)
        "SIGN-001": ["CC8.1"],
        "SIGN-002": ["CC8.1"],
        "GHA-024":  ["CC8.1"],
        "GL-024":   ["CC8.1"],
        "BB-024":   ["CC8.1"],
        "ADO-024":  ["CC8.1"],
        "JF-028":   ["CC8.1"],
        "CC-024":   ["CC8.1"],
        "GCB-009":  ["CC8.1"],

        # ── Kubernetes, runtime / network / RBAC / change posture ──
        # CC6.1 covers RBAC and SA-token surfaces; CC6.6 covers
        # network boundary; CC6.7 covers data-in-transit; CC6.8
        # covers malicious-software prevention (image-pinning, hostPath
        # escapes, runtime hardening); CC7.1/CC7.2 cover monitoring
        # and configuration-drift detection; CC8.1 covers change-
        # management (image pin = explicit change record).
        "K8S-001":  ["CC8.1"],            # image not pinned to digest
        "K8S-002":  ["CC6.6"],            # hostNetwork
        "K8S-003":  ["CC6.8"],            # hostPID
        "K8S-004":  ["CC6.8"],            # hostIPC
        "K8S-005":  ["CC6.8"],            # privileged container
        "K8S-006":  ["CC6.8"],            # allowPrivilegeEscalation
        "K8S-007":  ["CC6.8"],            # runAsNonRoot
        "K8S-008":  ["CC6.8"],            # readOnlyRootFilesystem
        "K8S-009":  ["CC6.8"],            # capabilities
        "K8S-010":  ["CC6.8"],            # seccompProfile
        "K8S-011":  ["CC6.1"],            # default ServiceAccount
        "K8S-012":  ["CC6.1"],            # automountServiceAccountToken
        "K8S-013":  ["CC6.8"],            # hostPath volume
        "K8S-014":  ["CC6.8"],            # sensitive hostPath
        "K8S-017":  ["CC6.1"],            # env credential
        "K8S-018":  ["CC6.1"],            # Secret data credential
        "K8S-019":  ["CC6.1"],            # default namespace
        "K8S-020":  ["CC6.1"],            # cluster-admin RoleBinding
        "K8S-021":  ["CC6.1"],            # wildcard verbs
        "K8S-022":  ["CC6.6"],            # SSH service exposed
        "K8S-023":  ["CC7.1"],            # PSA enforce missing
        "K8S-044":  ["CC7.1"],            # admission webhook fail-open / unscoped mutating
        "K8S-024":  ["CC7.2"],            # readiness/liveness probes
        "K8S-015":  ["CC6.6"],            # no memory limit (availability boundary)
        "K8S-016":  ["CC6.6"],            # no CPU limit (availability boundary)
        "K8S-025":  ["CC6.1"],            # system priority class
        "K8S-030":  ["CC6.1", "CC6.6"],   # control-plane scheduling
        "K8S-026":  ["CC6.6"],            # LB without source ranges
        "K8S-027":  ["CC6.7"],            # Ingress without TLS
        "K8S-028":  ["CC6.6"],            # host port
        "K8S-029":  ["CC6.1"],            # default-SA RoleBinding
        "K8S-031":  ["CC7.1"],            # PSA warn label missing
        "K8S-032":  ["CC6.6"],            # NetworkPolicy default-deny
        "K8S-033":  ["CC7.2"],            # ResourceQuota / LimitRange
        "K8S-034":  ["CC6.1"],            # SA automount default
        "K8S-035":  ["CC6.8"],            # runAsUser: 0
        "K8S-036":  ["CC8.1"],            # SA imagePullSecret missing
        "K8S-037":  ["CC6.1"],            # ConfigMap credential
        "K8S-038":  ["CC6.6"],            # NetworkPolicy allow-all
        "K8S-039":  ["CC6.8"],            # shareProcessNamespace
        "K8S-040":  ["CC6.8"],            # procMount: Unmasked
        "K8S-041":  ["CC6.6"],            # Service externalIPs (CVE-2020-8554)
        "K8S-042":  ["CC6.1", "CC6.3"],   # anonymous RoleBinding
        "K8S-043":  ["CC6.6"],            # Ingress wildcard host

        # ── Helm, chart-supply-chain hygiene maps to CC8.1 ─────────
        # (changes flow through chart upgrades) plus CC6.7 for non-
        # HTTPS dep repos.
        "HELM-001": ["CC8.1"],            # legacy v1 schema
        "HELM-002": ["CC8.1"],            # Chart.lock missing digests
        "HELM-003": ["CC6.7", "CC8.1"],   # non-HTTPS dep repo
        "HELM-004": ["CC8.1"],            # dep version not exact-pinned
        "HELM-008": ["CC8.1"],            # Chart.lock stale
        "HELM-009": ["CC6.7"],            # non-HTTPS sources
        # ── Dockerfile (image build = configuration change) ────────
        # CC6.1 / CC6.8 covers logical access + malicious-software
        # prevention (privileged / root / sensitive ports). CC6.7
        # covers data-in-transit (curl-pipe / TLS bypass). CC8.1
        # covers change management (pinning, version drift).
        "DF-001": ["CC8.1"],                # FROM not digest-pinned
        "MODEL-001": ["CC8.1"],             # unpinned base model
        "MODEL-002": ["CC8.1"],             # third-party hub base model
        "MODEL-003": ["CC8.1"],             # local unverified weights blob
        "MODEL-004": ["CC8.1"],             # remote LoRA adapter
        "MODEL-005": ["CC8.1"],             # config auto_map = custom loader code
        "DF-031": ["CC8.1"],                # COPY --from external image not digest-pinned
        "DF-002": ["CC6.1", "CC6.8"],       # runs as root
        "DF-003": ["CC6.7", "CC8.1"],       # ADD remote no integrity
        "DF-004": ["CC6.7", "CC8.1"],       # curl-pipe
        "DF-005": ["CC6.8"],                # shell-eval
        "DF-006": ["CC6.1"],                # ENV credential literal
        "DF-007": ["CC7.2"],                # no HEALTHCHECK
        "DF-008": ["CC6.1", "CC6.8"],       # docker --privileged
        "DF-010": ["CC8.1"],                # apt upgrade
        "DF-012": ["CC6.1"],                # RUN sudo
        "DF-013": ["CC6.6", "CC6.8"],       # sensitive EXPOSE
        "DF-014": ["CC6.8"],                # WORKDIR /etc
        "DF-015": ["CC6.8"],                # chmod 777
        "DF-016": ["CC8.1"],                # OCI provenance labels
        "DF-017": ["CC6.8"],                # PATH world-writable
        "DF-018": ["CC6.8"],                # chown system path
        "DF-019": ["CC6.1"],                # COPY credential file
        "DF-020": ["CC6.1"],                # credential ARG
        "DF-021": ["CC6.7"],                # pip install TLS bypass
        "DF-022": ["CC8.1"],                # npm install vs npm ci
        "DF-023": ["CC6.8"],                # ENV loader-hijack var
        # ── Buildkite (CI provider) ───────────────────────────────
        # Mirrors GHA / GitLab pack mappings: CC6.1 (logical access /
        # secrets), CC8.1 (change management), CC6.6 (network
        # boundary), CC6.7 (data in transit), CC7.1 / CC7.2
        # (vulnerability monitoring).
        "BK-001": ["CC8.1"],                # plugin not pinned
        "BK-002": ["CC6.1"],                # literal secret
        "BK-003": ["CC6.8"],                # untrusted variable
        "BK-004": ["CC6.7", "CC8.1"],       # curl-pipe
        "BK-005": ["CC6.1", "CC6.8"],       # privileged container
        "BK-006": ["CC6.1"],                # no timeout
        "BK-007": ["CC8.1"],                # no manual deploy gate
        "BK-008": ["CC6.7"],                # TLS bypass
        "BK-009": ["CC8.1"],                # no signing
        "BK-010": ["CC8.1"],                # no SBOM
        "BK-011": ["CC8.1"],                # no SLSA provenance
        "BK-012": ["CC7.1"],                # no vuln scan
        "BK-013": ["CC8.1"],                # no branches filter
        "BK-014": ["CC8.1"],                # unpinned package install
        "BK-015": ["CC6.8"],                # agents map untrusted interpolation
        # ── AWS extras ───────────────────────────────────────────
        "CB-004":  ["CC6.6"],               # no build timeout (unbounded build)
        "CB-007":  ["CC6.6", "CC8.1"],      # webhook no filter group
        "CB-009":  ["CC8.1"],               # build image not digest-pinned
        "CB-010":  ["CC6.6", "CC8.1"],      # fork-PR webhook unfiltered
        "CP-002":  ["CC6.1"],               # artifact store not CMK
        "CCM-002": ["CC6.1"],               # CodeCommit repo not CMK
        "CA-001":  ["CC6.1"],               # CodeArtifact domain not CMK
        "CA-002":  ["CC6.6"],               # CodeArtifact public external connection
        "CA-003":  ["CC6.1"],               # CodeArtifact cross-account wildcard
        "ECR-004": ["CC7.1"],               # ECR no lifecycle policy (drift)
        "ECR-005": ["CC6.1"],               # ECR AES256 (no CMK)
        "ECR-006": ["CC8.1"],               # ECR pull-through untrusted upstream
        "EB-002":  ["CC6.1"],               # EventBridge wildcard target
        "KMS-001": ["CC6.1"],               # KMS rotation disabled
        "SM-001":  ["CC6.3"],               # Secrets Manager no rotation
        "SSM-001": ["CC6.1"],               # SSM SecureString name not encrypted
        "SSM-002": ["CC6.1"],               # SSM SecureString default key
        "LMB-001": ["CC8.1"],               # Lambda code-signing config
        "LMB-003": ["CC6.1"],               # Lambda plaintext env secrets
        # ── Terraform / CloudFormation (IaC-native) ───────────────
        "TF-001":  ["CC6.1", "CC6.3"],      # aws_iam_access_key as code (long-lived)
        "TF-002":  ["CC6.1"],               # hard-coded secret in resource attr
        "TF-003":  ["CC6.6"],               # CodeBuild VPC shares public subnet
        "CF-001":  ["CC6.1", "CC6.3"],      # AWS::IAM::AccessKey as code
        "CF-002":  ["CC6.1"],               # hard-coded secret in resource property
        "CF-003":  ["CC6.6"],               # CodeBuild VPC shares public subnet
        # ── GitHub Actions ───────────────────────────────────────
        "GHA-002":  ["CC6.6", "CC6.8"],     # pull_request_target + PR head
        "RUN-001":  ["CC6.6", "CC6.8"],     # forensics: fork PR ran on privileged trigger
        "RUN-002":  ["CC6.6", "CC6.8"],     # forensics: privileged trigger fired
        "RUN-003":  ["CC6.6", "CC6.8"],     # forensics: secret leaked in run logs
        "GHA-006":  ["CC8.1"],              # unsigned artifacts
        "GHA-007":  ["CC8.1"],              # no SBOM
        "GHA-009":  ["CC6.6", "CC6.8"],     # workflow_run upstream artifact unverified
        "GHA-010":  ["CC6.6", "CC6.8"],     # local action on untrusted trigger
        "GHA-011":  ["CC6.6", "CC6.8"],     # cache key tainted
        "GHA-013":  ["CC6.6", "CC6.8"],     # issue_comment no author guard
        "GHA-015":  ["CC6.6"],              # no timeout-minutes
        "GHA-018":  ["CC6.1"],              # GITHUB_TOKEN persisted to storage
        "GHA-021":  ["CC8.1"],              # dep-update bypasses lockfile pins
        "GHA-022":  ["CC6.7"],              # TLS / cert verification bypass
        "GHA-029":  ["CC8.1"],              # package source bypasses lockfile
        "GHA-030":  ["CC6.1", "CC8.1"],     # OIDC w/o env-protected job
        "GHA-031":  ["CC6.8"],              # retired set-output / save-state
        "GHA-032":  ["CC6.8"],              # local script on untrusted trigger
        "GHA-033":  ["CC6.1"],              # secret echoed in run:
        "GHA-034":  ["CC6.1"],              # secrets: inherit
        "GHA-035":  ["CC6.8"],              # github-script untrusted context
        "GHA-036":  ["CC6.8"],              # runs-on untrusted context
        "GHA-037":  ["CC6.1"],              # checkout persists GITHUB_TOKEN
        "GHA-038":  ["CC6.8"],              # ACTIONS_ALLOW_UNSECURE_COMMANDS
        "GHA-039":  ["CC6.1"],              # services / container creds literal
        "GHA-040":  ["CC6.8", "CC8.1"],     # known-compromised action ref
        "GHA-041":  ["CC8.1"],              # single-maintainer action
        "GHA-042":  ["CC8.1"],              # very-young action repo
        "GHA-043":  ["CC8.1"],              # low-star + sensitive perms
        "GHA-044":  ["CC6.8"],              # build-tool PPE on untrusted trigger
        "GHA-045":  ["CC6.8"],              # caller-ref input drives checkout
        "GHA-046":  ["CC6.8"],              # manual PR-head fetch
        "GHA-047":  ["CC8.1"],              # fresh-ref cooldown
        "GHA-048":  ["CC8.1"],              # workflow self-mutation
        "GHA-049":  ["CC6.1"],              # cross-repo push from CI
        "GHA-050":  ["CC6.1", "CC6.3"],     # long-lived registry publish token
        "GHA-051":  ["CC8.1"],              # services / container image unpinned
        "GHA-052":  ["CC6.6"],              # cache key untrusted-input poisoning
        "GHA-053":  ["CC6.8"],              # if: predicate untrusted-context
        "GHA-054":  ["CC6.1"],              # checkout ssh-key persists
        "GHA-055":  ["CC6.1"],              # reusable outputs leak secret
        "GHA-056":  ["CC6.8"],              # worm IOC strings
        "GHA-057":  ["CC6.1", "CC6.6"],     # secret-scanner output → egress
        "GHA-058":  ["CC6.8"],              # agentic CLI permission-bypass
        "GHA-059":  ["CC8.1"],              # npm install without audit signatures
        "GHA-060":  ["CC8.1"],              # pip install without --require-hashes
        "GHA-061":  ["CC6.1", "CC6.3"],     # App token minted without permissions filter
        "GHA-106":  ["CC6.1", "CC6.3"],     # AI agent with write-scoped token
        "GHA-111":  ["CC6.1", "CC6.3"],  # AI agent edits IaC applied in the same job
        "GHA-112":  ["CC6.6", "CC8.1"],  # self-hosted deploy with no environment gate
        "GHA-113":  ["CC6.1", "CC8.1"],  # OIDC trusted-publish w/o env gate
        "GHA-114":  ["CC6.1", "CC8.1"],  # publish workflow on an unrestricted push trigger
        "GHA-115":  ["CC6.1"],              # id-token granted workflow-wide, not job-scoped
        "GHA-116":  ["CC6.1"],              # bulk secrets serialization
        "GHA-062":  ["CC6.1", "CC6.3"],     # OIDC trust subject in sibling IaC is overly broad
        "GHA-063":  ["CC6.1"],              # spoofable bot-actor if-predicate
        "GHA-064":  ["CC8.1"],              # unsound contains() with comma-string operand
        "GHA-065":  ["CC8.1"],              # zero-width / bidi unicode in workflow body
        "GHA-066":  ["CC6.1"],              # upload-artifact wildcard sweeps workspace
        "GHA-067":  ["CC6.1"],              # cache step publishes credential-shaped paths
        "GHA-068":  ["CC8.1"],              # runs-on targets a deprecated hosted runner
        "GHA-069":  ["CC6.1"],              # orphan id-token: write scope
        "GHA-070":  ["CC6.1"],              # ssh-keyscan / host-key check TOFU
        "GHA-071":  ["CC8.1"],              # powershell on Linux / macOS step
        "GHA-072":  ["CC6.1"],              # secret env: at wider scope than consumer
        "GHA-073":  ["CC6.1"],              # unused workflow_call.secrets declaration
        "GHA-086":  ["CC8.1"],              # wildcard branch trigger + environment binding
        "GHA-087":  ["CC6.1"],              # derived-value of secret printed to log
        "GHA-088":  ["CC6.8", "CC8.1"],     # typosquat uses: near-edit of top action
        "GHA-089":  ["CC6.8", "CC8.1"],     # archived upstream repo
        "GHA-090":  ["CC6.8", "CC8.1"],     # impostor-commit: SHA absent from repo
        "GHA-091":  ["CC6.8", "CC8.1"],     # repojacking: action upstream missing
        "GHA-092":  ["CC6.8"],              # TOCTOU PR head SHA force-push race
        "GHA-093":  ["CC6.1"],              # LOTP indicators
        "GHA-094":  ["CC6.8", "CC8.1"],     # stale-action-refs
        "GHA-096":  ["CC6.8", "CC8.1"],     # known-vulnerable action ref (GHSA)
        # ── GitLab CI ─────────────────────────────────────────────
        "GL-006":   ["CC8.1"],              # unsigned artifacts
        "GL-007":   ["CC8.1"],              # no SBOM
        "GL-009":   ["CC8.1"],              # image not digest-pinned
        "GL-010":   ["CC6.6", "CC6.8"],     # multi-project artifact unverified
        "GL-011":   ["CC6.6", "CC6.8"],     # include: local on MR pipeline
        "GL-012":   ["CC6.6", "CC6.8"],     # cache key tainted
        "GL-015":   ["CC6.6"],              # no timeout
        "GL-018":   ["CC8.1"],              # package install insecure source
        "GL-021":   ["CC8.1"],              # install without lockfile
        "GL-022":   ["CC8.1"],              # dep-update bypasses lockfile pins
        "GL-027":   ["CC8.1"],              # install bypasses registry integrity
        "GL-028":   ["CC8.1"],              # services: image not pinned
        "GL-030":   ["CC8.1"],              # trigger: include w/o pinned ref
        "GL-031":   ["CC6.1", "CC8.1"],     # id_tokens missing audience pin
        "GL-040":   ["CC6.1", "CC8.1"],     # CI_JOB_TOKEN used for cross-project access
        "GL-041":   ["CC6.8"],              # IaC apply on an untrusted MR trigger
        "BB-033":   ["CC6.8"],              # IaC apply on a PR pipeline
        "ADO-033":  ["CC6.8"],              # IaC apply on a PR-validated pipeline
        "BK-016":   ["CC6.8"],              # dangerous shell idiom
        "JF-036":   ["CC6.8"],              # shell step interpolates params.*
        "GL-032":   ["CC6.8"],              # tags interpolates untrusted
        "GL-033":   ["CC6.8"],              # global before_script taint
        "GL-034":   ["CC8.1"],              # npm install without audit signatures
        "GL-035":   ["CC8.1"],              # pip install without --require-hashes
        # ── Bitbucket Pipelines ──────────────────────────────────
        "BB-005":   ["CC6.1", "CC6.8"],     # privileged container
        "BB-006":   ["CC8.1"],              # unsigned artifacts
        "BB-007":   ["CC8.1"],              # no SBOM
        "BB-009":   ["CC8.1"],              # pipe not digest-pinned
        "BB-010":   ["CC6.6", "CC6.8"],     # deploy step PR artifact unverified
        "BB-014":   ["CC8.1"],              # package install insecure source
        "BB-018":   ["CC6.6", "CC6.8"],     # cache key tainted
        "BB-019":   ["CC6.1"],              # after-script references secrets
        "BB-020":   ["CC6.1"],              # full clone depth exposes history
        "BB-021":   ["CC8.1"],              # install without lockfile
        "BB-022":   ["CC8.1"],              # dep-update bypasses lockfile pins
        "BB-027":   ["CC8.1"],              # install bypasses registry integrity
        "BB-028":   ["CC6.1", "CC8.1"],     # OIDC step w/o env gate
        "BB-029":   ["CC8.1"],              # step + service image not pinned
        "BB-030":   ["CC8.1"],              # npm install without audit signatures
        "BB-031":   ["CC8.1"],              # pip install without --require-hashes
        # ── Azure DevOps Pipelines ───────────────────────────────
        "ADO-005":  ["CC8.1"],              # unpinned container
        "ADO-006":  ["CC8.1"],              # unsigned artifacts
        "ADO-007":  ["CC8.1"],              # no SBOM
        "ADO-009":  ["CC8.1"],              # container image not digest-pinned
        "ADO-010":  ["CC6.6", "CC6.8"],     # cross-pipeline download unverified
        "ADO-011":  ["CC6.6", "CC6.8"],     # template: local on PR-validated
        "ADO-012":  ["CC6.6", "CC6.8"],     # Cache@2 PullRequest context
        "ADO-015":  ["CC6.6"],              # no timeoutInMinutes
        "ADO-018":  ["CC8.1"],              # package install insecure source
        "ADO-019":  ["CC6.6", "CC6.8"],     # extends template injection
        "ADO-021":  ["CC8.1"],              # install without lockfile
        "ADO-022":  ["CC8.1"],              # dep-update bypasses lockfile pins
        "ADO-028":  ["CC8.1"],              # install bypasses registry integrity
        "ADO-029":  ["CC8.1"],              # service-conn job w/o env gate
        "ADO-030":  ["CC6.8"],              # pool interpolates untrusted
        # ── CircleCI ──────────────────────────────────────────────
        "CC-003":   ["CC8.1"],              # image not pinned to digest
        "CC-004":   ["CC6.1"],              # unrestricted context
        "CC-006":   ["CC8.1"],              # unsigned artifacts
        "CC-007":   ["CC8.1"],              # no SBOM
        "CC-012":   ["CC6.6", "CC6.8"],     # dynamic config
        "CC-014":   ["CC6.6"],              # resource class isolation
        "CC-015":   ["CC6.6"],              # no timeout
        "CC-018":   ["CC8.1"],              # package install insecure source
        "CC-021":   ["CC8.1"],              # install without lockfile
        "CC-022":   ["CC8.1"],              # dep-update bypasses lockfile pins
        "CC-025":   ["CC6.6", "CC6.8"],     # cache key tainted
        "CC-028":   ["CC8.1"],              # install bypasses registry integrity
        "CC-029":   ["CC8.1"],              # machine executor image not pinned
        "CC-031":   ["CC6.1", "CC8.1"],     # OIDC role w/o branch filter
        # ── Jenkins ──────────────────────────────────────────────
        "JF-006":   ["CC8.1"],              # artifacts not signed
        "JF-007":   ["CC8.1"],              # SBOM not produced
        "JF-009":   ["CC8.1"],              # agent docker image not digest-pinned
        "JF-012":   ["CC8.1"],              # load step pulls Groovy w/o integrity pin
        "JF-013":   ["CC6.6", "CC6.8"],     # copyArtifacts ingests upstream unverified
        "JF-015":   ["CC6.6"],              # pipeline has no timeout wrapper
        "JF-018":   ["CC8.1"],              # package install insecure source
        "JF-019":   ["CC6.8"],              # Groovy sandbox escape pattern
        "JF-021":   ["CC8.1"],              # install without lockfile
        "JF-022":   ["CC8.1"],              # dep-update bypasses lockfile pins
        "JF-027":   ["CC8.1"],              # archiveArtifacts no fingerprint
        "JF-031":   ["CC8.1"],              # install bypasses registry integrity
        "JF-032":   ["CC6.8"],              # agent label interpolates untrusted
        # ── Drone CI ─────────────────────────────────────────────
        "DR-001":   ["CC8.1"],              # step image not digest-pinned
        "DR-002":   ["CC6.1", "CC6.8"],     # privileged step
        "DR-003":   ["CC6.8"],              # Drone variable injection
        "DR-004":   ["CC6.1"],              # literal credential
        "DR-005":   ["CC8.1"],              # plugin floating tag
        "DR-006":   ["CC6.7"],              # TLS bypass in commands
        "DR-007":   ["CC6.6", "CC6.8"],     # sensitive host-path mount
        "DR-008":   ["CC8.1"],              # pull: never
        "DR-009":   ["CC6.6", "CC6.8"],     # cache key tainted
        "DR-010":   ["CC8.1"],              # unpinned package install
        "DR-011":   ["CC6.8"],              # node map interpolates untrusted
        # ── Drone extended pack ──
        "DR-012":   ["CC8.1"],              # service image not pinned
        "DR-013":   ["CC8.1"],              # no trigger event filter
        "DR-014":   ["CC8.1"],              # pipe-to-shell
        "DR-015":   ["CC8.1"],              # clone recursive
        "DR-016":   ["CC8.1"],              # image field interpolation
        "DR-017":   ["CC6.8"],              # dangerous shell idiom
        # ── Tekton (K8s-native pipeline kinds) ────────────────────
        "TKN-001":  ["CC8.1"],              # step image not digest-pinned
        "TKN-016": ["CC8.1"],  # remote resolver / bundle task body not pinned
        "TKN-002":  ["CC6.1", "CC6.8"],     # step privileged / root
        "TKN-003":  ["CC6.8"],              # param injection in script
        "TKN-004":  ["CC6.6", "CC6.8"],     # hostPath / host namespaces
        "TKN-005":  ["CC6.1"],              # leaked creds
        "TKN-006":  ["CC6.6"],              # no explicit timeout
        "TKN-007":  ["CC6.1"],              # default ServiceAccount
        "TKN-008":  ["CC6.7", "CC8.1"],     # remote install / TLS bypass
        "TKN-009":  ["CC8.1"],              # artifacts not signed
        "TKN-010":  ["CC8.1"],              # SBOM not generated
        "TKN-011":  ["CC8.1"],              # SLSA provenance
        "TKN-012":  ["CC7.1"],              # no vulnerability scanning
        "TKN-013":  ["CC6.1", "CC6.8"],     # sidecar privileged / root
        "TKN-014":  ["CC8.1"],              # unpinned package install
        "TKN-015":  ["CC6.8"],              # workspace subPath param injection
        # ── Argo Workflows ───────────────────────────────────────
        "ARGO-001": ["CC8.1"],              # template image not digest-pinned
        "ARGO-002": ["CC6.1", "CC6.8"],     # template privileged / root
        "ARGO-003": ["CC6.1"],              # default ServiceAccount
        "ARGO-016": ["CC6.1"],              # cluster-admin / over-privileged ServiceAccount
        "ARGO-004": ["CC6.6", "CC6.8"],     # hostPath / host namespaces
        "ARGO-005": ["CC6.8"],              # parameter injection
        "ARGO-017": ["CC6.8"],              # resource template manifest injection
        "ARGO-006": ["CC6.1"],              # leaked creds
        "ARGO-007": ["CC6.6"],              # missing activeDeadlineSeconds
        "ARGO-008": ["CC6.7", "CC8.1"],     # remote install / TLS bypass
        "ARGO-009": ["CC8.1"],              # artifacts not signed
        "ARGO-010": ["CC8.1"],              # SBOM not generated
        "ARGO-011": ["CC8.1"],              # SLSA provenance
        "ARGO-012": ["CC7.1"],              # no vulnerability scanning
        "ARGO-013": ["CC6.1"],              # SA token automount default
        "ARGO-014": ["CC8.1"],              # unpinned package install
        "ARGO-015": ["CC6.7"],              # insecure (non-HTTPS) artifact URL
        # ── Argo CD (GitOps deployment) ──
        "ARGOCD-010": ["CC8.1"],            # mutable targetRevision
        "ARGOCD-017": ["CC8.1"],  # in-cluster mutable source
        "ARGOCD-019": ["CC8.1"],  # drift detection disabled on a sensitive field
        "ARGOCD-016": ["CC8.1"],  # Helm valueFiles from a remote URL
        "ARGOCD-018": ["CC8.1"],  # custom resource health / action Lua
        "ARGOCD-011": ["CC6.1"],            # cluster-resource wildcard
        "ARGOCD-012": ["CC8.1"],            # no sync windows
        "ARGOCD-013": ["CC8.1"],            # no revision history cap
        # ── Cloud Build extras ───────────────────────────────────
        "GCB-004": ["CC8.1"],               # community step not SHA-pinned
        "GCB-005": ["CC6.6"],               # build timeout unset
        "GCB-010": ["CC6.7", "CC8.1"],      # remote script piped to shell
        "GCB-011": ["CC6.7"],               # TLS bypass
        "GCB-012": ["CC6.1"],               # literal secret
        "GCB-013": ["CC8.1"],               # pkg install bypasses registry integrity
        "GCB-014": ["CC7.2"],               # build logging disabled
        "GCB-015": ["CC8.1"],               # no SBOM step
        "GCB-016": ["CC6.8"],               # dir path escape
        "GCB-017": ["CC8.1"],               # no SLSA provenance
        "GCB-018": ["CC6.1"],               # legacy KMS secrets block
        "GCB-019": ["CC6.8"],               # shell entrypoint + user substitution
        "GCB-020": ["CC6.1"],               # default Cloud Build SA
        "GCB-021": ["CC6.6"],               # no private worker pool
        "GCB-022": ["CC6.8"],               # ALLOW_LOOSE substitution
        "GCB-023": ["CC6.8"],               # undeclared user substitution
        "GCB-024": ["CC8.1"],               # images: missing for docker push
        "GCB-025": ["CC7.2"],               # tags: empty (audit/discoverability)
        "GCB-026": ["CC8.1"],               # waitFor unknown step id
        "GCB-027": ["CC6.8"],               # malicious-activity indicators
        # ── NPM / PyPI / Maven dep supply-chain ──────────────────
        # Dep-supply-chain rules land on CC8.1 (change management).
        # Compromised packages also evidence CC6.8 (malicious software)
        # and CC7.1 (vulnerability detection). HTTP / TLS bypass adds
        # CC6.7 (data in transit). Install-time lifecycle scripts +
        # ignore-scripts evidence CC6.8 (malicious software prevention).
        # Secret-shaped paths in files field add CC6.1.
        "NPM-001":  ["CC8.1"],
        "NPM-002":  ["CC8.1"],
        "NPM-003":  ["CC8.1"],
        "NPM-004":  ["CC6.8"],
        "NPM-005":  ["CC8.1"],
        "NPM-006":  ["CC6.8", "CC7.1", "CC8.1"],
        "NPM-007":  ["CC6.8"],
        "NPM-011":  ["CC6.1"],
        "NPM-013":  ["CC6.1"],
        "PYPI-001": ["CC8.1"],
        "PYPI-002": ["CC8.1"],
        "PYPI-003": ["CC6.7", "CC8.1"],
        "PYPI-018": ["CC6.7", "CC8.1"],  # --no-binary forces sdist build
        "PYPI-019": ["CC6.8", "CC7.1", "CC8.1"],  # missing PEP 740 build provenance
        "PYPI-020": ["CC6.8", "CC7.1", "CC8.1"],  # low OpenSSF Scorecard upstream
        "PYPI-021": ["CC6.8", "CC7.1", "CC8.1"],  # provenance built from a non-release ref
        "PYPI-004": ["CC8.1"],
        "PYPI-015": ["CC8.1"],  # direct artifact URL
        "PYPI-005": ["CC8.1"],
        "PYPI-017": ["CC8.1"],  # remote --find-links
        "PYPI-016": ["CC8.1"],  # primary index repointed
        "PYPI-006": ["CC6.8", "CC7.1", "CC8.1"],
        "MVN-001":  ["CC8.1"],
        "MVN-002":  ["CC8.1"],
        "MVN-003":  ["CC6.7", "CC8.1"],
        "MVN-004":  ["CC8.1"],
        "MVN-005":  ["CC8.1"],
        "MVN-006":  ["CC6.8", "CC7.1", "CC8.1"],
        "MVN-007":  ["CC8.1"],
        "MVN-008":  ["CC6.8", "CC7.1", "CC8.1"],
        "MVN-009":  ["CC6.8", "CC7.1", "CC8.1"],
        # ── Maven extended pack ──
        "MVN-010":  ["CC6.1"],
        "MVN-011":  ["CC6.1"],
        "MVN-012":  ["CC8.1"],
        "MVN-013":  ["CC8.1"],
        "MVN-014":  ["CC8.1"],
        "MVN-015": ["CC8.1"],  # build-time plugin exec bound to lifecycle
        "MVN-016": ["CC8.1"],  # gradle allowInsecureProtocol
        "MVN-017": ["CC6.1"],  # settings.xml privateKey + plaintext passphrase
        "MVN-018": ["CC8.1"],  # distributionManagement release accepts snapshots
        "NPM-008":  ["CC6.8", "CC7.1", "CC8.1"],
        "NPM-009":  ["CC8.1"],
        "NPM-010":  ["CC6.8", "CC7.1", "CC8.1"],
        "NPM-014":  ["CC6.8", "CC7.1", "CC8.1"],
        "NPM-015":  ["CC6.8", "CC7.1", "CC8.1"],
        "NPM-017":  ["CC6.8", "CC7.1", "CC8.1"],  # provenance built from a non-release ref
        "NPM-018":  ["CC6.8", "CC7.1", "CC8.1"],  # latest release from a new publisher
        "NPM-019":  ["CC6.8", "CC7.1", "CC8.1"],  # overrides / resolutions redirect
        "NPM-020":  ["CC6.8", "CC7.1", "CC8.1"],  # .npmrc registry repoint
        "NPM-016":  ["CC6.8", "CC7.1", "CC8.1"],
        "PYPI-008": ["CC6.8", "CC7.1", "CC8.1"],
        "PYPI-009": ["CC6.8", "CC7.1", "CC8.1"],
        # ── PyPI extended pack ──
        "PYPI-010": ["CC6.1"],                  # index URL embedded credentials
        "PYPI-011": ["CC6.1"],                  # --trusted-host disables TLS
        "PYPI-012": ["CC8.1"],                  # build-system requires floating
        "PYPI-013": ["CC8.1"],                  # pyproject dynamic dependencies
        "PYPI-014": ["CC6.1"],                  # custom source HTTP
        # ── nuget (dep supply-chain) ─────────────────────────────
        "NUGET-001": ["CC8.1"],
        "NUGET-002": ["CC8.1"],
        "NUGET-003": ["CC8.1"],
        "NUGET-004": ["CC6.7", "CC8.1"],
        "NUGET-005": ["CC6.8", "CC7.1", "CC8.1"],
        "NUGET-006": ["CC8.1"],
        "NUGET-007": ["CC8.1"],
        "NUGET-008": ["CC6.8", "CC7.1", "CC8.1"],
        "NUGET-009": ["CC6.8", "CC7.1", "CC8.1"],
        "NUGET-010": ["CC6.1"],
        # ── NuGet extended pack ──
        "NUGET-011": ["CC8.1"],
        "NUGET-012": ["CC8.1"],
        "NUGET-013": ["CC8.1"],
        "NUGET-014": ["CC6.1"],
        "NUGET-015": ["CC8.1"],
        "NUGET-016": ["CC8.1"],  # missing <clear/> inherits public gallery
        "NUGET-017": ["CC8.1"],  # public gallery active alongside private feed, not disabled
        "NUGET-018": ["CC8.1"],  # build-time MSBuild execution
        "NUGET-019": ["CC8.1"],  # require mode, no trusted signers
        # ── Go modules ──
        "GOMOD-001": ["CC8.1"],                 # go.sum integrity manifest missing
        "GOMOD-002": ["CC8.1"],                 # replace directive to local path
        "GOMOD-003": ["CC8.1"],                 # replace directive to different module
        "GOMOD-004": ["CC8.1"],                 # +incompatible direct require
        "GOMOD-005": ["CC8.1"],                 # missing go toolchain directive
        "GOMOD-006": ["CC8.1", "CC7.1"],        # known-compromised module version
        # ── Go modules extended pack ──
        "GOMOD-007": ["CC8.1"],
        "GOMOD-008": ["CC8.1"],
        "GOMOD-009": ["CC8.1"],
        "GOMOD-010": ["CC8.1"],
        "GOMOD-011": ["CC8.1"],  # tool directive build-time exec
        "GOMOD-012": ["CC8.1"],  # insecure / non-canonical module host
        # ── Cargo ──
        "CARGO-001": ["CC8.1"],                 # floating Cargo.toml version spec
        "CARGO-002": ["CC8.1"],                 # git dep with mutable ref (no rev)
        "CARGO-003": ["CC8.1"],                 # missing Cargo.lock
        "CARGO-004": ["CC8.1"],                 # local-path Cargo dependency
        "CARGO-005": ["CC8.1"],                 # alternate-registry Cargo dependency
        "CARGO-006": ["CC8.1", "CC7.1"],        # known-compromised crate version
        # ── Cargo extended pack ──
        "CARGO-007": ["CC8.1"],
        "CARGO-008": ["CC8.1"],
        "CARGO-009": ["CC8.1"],
        "CARGO-010": ["CC8.1"],
        "CARGO-011": ["CC8.1"],  # build.rs compile-time egress / exec
        "CARGO-012": ["CC8.1"],  # .cargo/config.toml source override / build flags
        "CARGO-013": ["CC8.1"],  # Cargo.lock off-crates.io source
        "CARGO-014": ["CC8.1"],  # no supply-chain audit-gate config
        # ── Composer / PHP ──
        "COMPOSER-001": ["CC8.1"],
        "COMPOSER-002": ["CC8.1"],
        "COMPOSER-003": ["CC8.1", "CC6.1"],
        "COMPOSER-012": ["CC8.1", "CC6.1"],  # disables Packagist / marks custom repo canonical
        "COMPOSER-011": ["CC8.1", "CC6.1"],  # external VCS repository re-points a package
        "COMPOSER-004": ["CC6.1"],
        "COMPOSER-005": ["CC8.1"],
        "COMPOSER-014": ["CC8.1"],  # minimum-stability without prefer-stable
        "COMPOSER-006": ["CC8.1"],
        "COMPOSER-007": ["CC8.1", "CC7.1"],
        "COMPOSER-008": ["CC8.1"],
        "COMPOSER-009": ["CC6.1"],
        "COMPOSER-010": ["CC8.1", "CC6.1"],
        "COMPOSER-013": ["CC8.1", "CC6.1"],  # config.disable-tls
        # ── RubyGems / Bundler ──
        "GEM-001": ["CC8.1"],
        "GEM-002": ["CC8.1"],
        "GEM-003": ["CC8.1", "CC6.1"],
        "GEM-004": ["CC6.1"],
        "GEM-005": ["CC8.1"],
        "GEM-006": ["CC8.1", "CC7.1"],
        "GEM-007": ["CC8.1"],
        "GEM-008": ["CC8.1"],
        "GEM-009": ["CC6.1"],
        "GEM-010": ["CC8.1"],
        "GEM-011": ["CC8.1"],  # Bundler plugin install-time exec
        "GEM-012": ["CC8.1"],  # per-gem :source override
        "GEM-013": ["CC8.1"],  # insecure git transport
        # ── Pulumi ──
        "PULUMI-001": ["CC6.1"],                # passphrase secretsprovider
        "PULUMI-002": ["CC6.1"],                # secret-shaped config plaintext
        "PULUMI-003": ["CC6.1"],                # hardcoded credentials in source
        "PULUMI-011": ["CC6.1"],  # plugin from custom download server
        "PULUMI-004": ["CC6.1", "CC8.1"],       # insecure state backend
        "PULUMI-005": ["CC6.1"],                # wildcard IAM policy in source
        "PULUMI-006": ["CC8.1"],                # StackReference unguarded
        # ── Pulumi extended pack ──
        "PULUMI-007": ["CC6.1"],                # public-access cloud resource
        "PULUMI-008": ["CC6.1"],                # shell-exec with non-constant input
        "PULUMI-013": ["CC6.1"],  # dynamic provider deploy-time code
        "PULUMI-014": ["CC6.1"],  # ESC environment imported without a qualifier
        "PULUMI-009": ["CC8.1"],                # runtime / source mismatch
        "PULUMI-012": ["CC8.1"],  # plugin version unpinned
        "PULUMI-010": ["CC6.1"],                # stack orphaned encryption salt
        # ── OCI image manifest gaps ──────────────────────────────
        "OCI-001":  ["CC8.1"],              # provenance annotations missing
        "OCI-002":  ["CC8.1"],              # build attestation missing
        "OCI-003":  ["CC8.1"],              # missing image.created
        "OCI-004":  ["CC8.1"],              # foreign-layer URL reference
        "OCI-005":  ["CC8.1"],              # missing image.licenses
        "OCI-006":  ["CC8.1"],              # excessive layer count (config drift)
        "OCI-007":  ["CC8.1"],              # legacy schemaVersion 1
        "OCI-009":  ["CC8.1"],              # missing base-image annotations
        "OCI-008":  ["CC8.1"],              # weak digest algorithm
        # ── SLSA / in-toto attestation content ───────────────────
        "ATTEST-001": ["CC8.1"],            # untrusted SLSA builder identity
        "ATTEST-002": ["CC8.1"],            # source-repo claim unverifiable
        "ATTEST-003": ["CC8.1"],            # SBOM floating versions
        "ATTEST-004": ["CC8.1"],            # provenance lacks materials
        "ATTEST-005": ["CC8.1"],            # in-toto subject digest unpinned
        "ATTEST-006": ["CC8.1"],            # buildType missing
        "ATTEST-007": ["CC8.1"],            # SBOM missing supplier
        # ── Cross-cutting dataflow / taint engine ────────────────
        # Cross-step / cross-job untrusted-data flow into privileged
        # sinks is both a boundary failure (CC6.6) and a malicious-
        # software-execution surface (CC6.8).
        "TAINT-001": ["CC6.6", "CC6.8"],
        "TAINT-002": ["CC6.6", "CC6.8"],
        "TAINT-003": ["CC6.6", "CC6.8"],
        "TAINT-004": ["CC6.6", "CC6.8"],
        "TAINT-005": ["CC6.6", "CC6.8"],
        "TAINT-006": ["CC6.6", "CC6.8"],
        "TAINT-007": ["CC6.6", "CC6.8"],
        "TAINT-008": ["CC6.6", "CC6.8"],
        "TAINT-009": ["CC6.1"],                  # env-protected secret flows to unprotected job
        # ── Dockerfile extras ───────────────────────────────────
        "DF-009":   ["CC8.1"],              # ADD where COPY suffices
        "DF-011":   ["CC8.1"],              # apt cache not cleaned (drift)
        "DF-024":   ["CC6.8"],              # npm install runs lifecycle scripts
        "DF-025":   ["CC6.1"],              # registry token in image layer
        "DF-026":   ["CC6.7"],              # NODE_TLS_REJECT_UNAUTHORIZED=0
        "DF-027":   ["CC6.7"],              # PYTHONHTTPSVERIFY=0
        "DF-028":   ["CC6.7"],              # GIT_SSL_NO_VERIFY=1
        "DF-029":   ["CC6.7"],              # REQUESTS_CA_BUNDLE neutered
        "DF-030":   ["CC6.8"],              # NODE_OPTIONS --require / --inspect
        # ── Helm chart provenance metadata extras ────────────────
        "HELM-005": ["CC8.1"],              # missing maintainers
        "HELM-006": ["CC8.1"],              # missing kubeVersion
        "HELM-007": ["CC8.1"],              # missing description
        "HELM-010": ["CC8.1"],              # missing appVersion
        # ── Helm extended pack ──
        "HELM-011": ["CC6.1"],              # dependency URL embedded creds
        "HELM-012": ["CC8.1"],              # deprecated without successor
        "HELM-013": ["CC8.1"],              # invalid chart type
        "HELM-014": ["CC8.1", "CC7.1"],     # known-compromised dep
        "HELM-015": ["CC8.1"],  # oci:// dependency not digest-pinned
        "HELM-016": ["CC6.1"],  # default secret in values.yaml
        "HELM-017": ["CC8.1"],  # tpl of an untrusted .Values value
        # ── Degraded-mode findings (API access failures) ─────────
        # Visibility gap = monitoring-for-anomalies failure (CC7.2)
        # plus a logical-access trail evidence gap on the security-
        # event surfaces; mirrors the cross-standard precedent.
        "CB-000":   ["CC7.2"],
        "CP-000":   ["CC7.2"],
        "CD-000":   ["CC7.2"],
        "ECR-000":  ["CC7.2"],
        "IAM-000":  ["CC7.2"],
        "PBAC-000": ["CC7.2"],
        "CT-000":   ["CC7.2"],
        "CWL-000":  ["CC7.2"],
        "EB-000":   ["CC7.2"],
        "CA-000":   ["CC7.2"],
        "CCM-000":  ["CC7.2"],
        "LMB-000":  ["CC7.2"],
        "KMS-000":  ["CC7.2"],
        "SM-000":   ["CC7.2"],
        "SSM-000":  ["CC7.2"],
        "S3-000":   ["CC7.2"],
        # supply-chain posture pack
        "GHA-097":  ["CC8.1"],                   # recursive PR auto-merge loop
        "GHA-098":  ["CC8.1", "CC6.8"],          # deploy without security scan gate
        "GHA-099":  ["CC6.1"],                   # deploy env plaintext secret
        "GHA-100":  ["CC8.1"],                   # cosign verify no identity binding
        "GHA-102":  ["CC6.8"],                   # submodule checkout on PR trigger
        "GHA-103":  ["CC6.8"],              # AI review bot on untrusted trigger
        "GHA-104":  ["CC6.8"],              # AI agent auto-push without PR review
        "GL-036":   ["CC6.1"],              # secret echoed to GitLab CI log
        "GL-038":   ["CC6.1"],              # CI_DEBUG_TRACE dumps secrets to GitLab CI log
        "BB-032":   ["CC6.1"],              # secret echoed to Bitbucket log
        "ADO-031":  ["CC6.1"],              # secret echoed to Azure DevOps log
        "ADO-032":  ["CC6.1"],              # checkout persistCredentials leaks token to .git/config
        "CC-032":   ["CC6.1"],              # secret echoed to CircleCI log
        "SCM-048":  ["CC6.1"],                   # org codespace secrets scoped to all repos
        "SCM-049":  ["CC6.1", "CC6.3"],          # classic PAT used where fine-grained suffices
        "NPM-012":  ["CC6.1", "CC8.1"],          # publish token missing restrictions
        # ── SCM posture (governance via the platform REST API) ──────
        # Branch protection / review controls map to CC8.1 (Change
        # Management) since the SOC 2 framing of source-code review
        # is essentially "changes are authorized before deployment".
        # Logical-access surfaces (workflow tokens, deploy keys,
        # outside collaborators) map to CC6.1 / CC6.2 / CC6.3.
        "SCM-001": ["CC8.1"],               # default branch unprotected
        "SCM-002": ["CC8.1"],               # required reviews missing
        "SCM-003": ["CC8.1", "CC7.1"],      # default code scanning disabled
        "SCM-004": ["CC6.1"],               # secret scanning disabled
        "SCM-005": ["CC7.1"],               # Dependabot security updates off
        "SCM-006": ["CC6.1", "CC8.1"],      # signed commits not required
        "SCM-007": ["CC8.1"],               # force-push allowed
        "SCM-008": ["CC8.1"],               # required status checks missing
        "SCM-009": ["CC8.1"],               # branch deletions allowed
        "SCM-010": ["CC8.1"],               # admin bypass allowed
        "SCM-011": ["CC8.1"],               # CODEOWNERS reviews not required
        "SCM-012": ["CC8.1"],               # stale reviews not dismissed
        "SCM-013": ["CC8.1"],               # conversation resolution not required
        "SCM-014": ["CC8.1"],               # last-push approval not required
        "SCM-015": ["CC6.1"],               # secret scanning push protection off
        "SCM-016": ["CC7.3", "CC7.4"],      # private vulnerability reporting off
        "SCM-017": ["CC8.1"],               # CODEOWNERS file missing
        "SCM-018": ["CC8.1"],               # PR review bypass allowed
        "SCM-019": ["CC6.1"],               # push-restriction allowlist names users
        # Actions governance + environments + deploy keys
        "SCM-020": ["CC6.1"],               # workflow_token default write
        "SCM-021": ["CC8.1"],               # Actions can approve PRs
        "SCM-022": ["CC6.8"],               # allowed_actions unrestricted
        "SCM-023": ["CC8.1"],               # env missing reviewers
        "SCM-024": ["CC8.1"],               # env branch policy missing
        "SCM-025": ["CC6.1", "CC6.3"],      # deploy keys write-enabled
        "SCM-026": ["CC6.7", "CC6.1"],      # webhook insecure transport / no HMAC
        "SCM-027": ["CC6.1", "CC6.2"],      # outside collaborator elevated
        "SCM-028": ["CC6.1"],               # private repo allows forking
        # Ruleset enforcement
        "SCM-029": ["CC8.1"],               # ruleset not enforced
        "SCM-030": ["CC8.1"],               # ruleset always-bypass
        "SCM-031": ["CC8.1"],               # auto-merge enabled
        "SCM-032": ["CC8.1"],               # ruleset lacks PR review
        "SCM-033": ["CC8.1"],               # ruleset lacks status_checks
        "SCM-034": ["CC8.1"],               # ruleset allows force_push
        "SCM-035": ["CC8.1"],               # ruleset allows deletion
        "SCM-036": ["CC6.1", "CC8.1"],      # ruleset lacks signed_commits
        "SCM-037": ["CC8.1"],               # ruleset stale-review dismissal
        "SCM-038": ["CC8.1"],               # ruleset lacks linear_history
        "SCM-039": ["CC8.1", "CC7.1"],      # ruleset lacks required_workflows
        "SCM-040": ["CC8.1", "CC7.1"],      # ruleset lacks code_scanning gate
        "SCM-041": ["CC8.1"],               # ruleset lacks deployment-env gate
        "SCM-042": ["CC8.1", "CC7.1"],      # ruleset lacks merge queue
        "SCM-043": ["CC6.1", "CC8.1"],      # tag-ruleset lacks signed_commits
        "SCM-044": ["CC6.1", "CC8.1"],      # required_signatures bypassed for admins
        "SCM-045": ["CC7.1"],               # default code scanning limited query suite
        "SCM-046": ["CC7.1"],               # default code scanning configured but paused
        "SCM-047": ["CC7.1"],               # repo language not covered
        # ── Azure Cloud (Entra ID / Storage / Key Vault / ACR / Monitor) ──
        "ENTRA-001": ["CC6.1"],                  # SP assigned Global Administrator
        "ENTRA-002": ["CC6.3"],                  # app credential beyond 180 days
        "ENTRA-003": ["CC6.1", "CC6.2"],         # SP uses password credential
        "AZST-001":  ["CC6.6"],                  # public blob access
        "AZST-002":  ["CC6.7"],                  # non-HTTPS traffic
        "AZST-003":  ["CC6.1"],                  # no CMK encryption
        "AKV-001":   ["CC6.1"],                  # soft delete not enabled
        "AKV-002":   ["CC6.1"],                  # purge protection not enabled
        "AKV-003":   ["CC6.6"],                  # network ACLs allow all
        "ACR-001":   ["CC6.1", "CC6.2"],         # admin user enabled
        "ACR-002":   ["CC6.6"],                  # public network access
        "ACR-003":   ["CC8.1"],                  # content trust not enabled
        "AZMON-001": ["CC7.2"],                  # no diagnostic setting
        "AZMON-002": ["CC7.2"],                  # log retention < 365 days
        "AZMON-003": ["CC7.2", "CC7.3", "CC7.4"],  # no alert rule
        # ── GCP (IAM / GCS / KMS / Artifact Registry / Cloud Logging) ────
        "GCIAM-001": ["CC6.1"],                  # SA has Owner/Editor role
        "GCIAM-002": ["CC6.1", "CC6.3"],         # user-managed SA key
        "GCIAM-003": ["CC6.1"],                  # token creator without condition
        "GCS-001":   ["CC6.6"],                  # public bucket
        "GCS-002":   ["CC6.1"],                  # no uniform access
        "GCS-003":   ["CC7.2"],                  # versioning not enabled
        "GCKMS-001": ["CC6.1"],                  # key rotation > 365 days
        "GCKMS-002": ["CC6.1", "CC6.6"],         # public KMS key access
        "GCKMS-003": ["CC6.1"],                  # no HSM protection
        "GAR-001":   ["CC6.8"],                  # no vulnerability scanning
        "GAR-002":   ["CC6.6"],                  # publicly readable repo
        "GAR-003":   ["CC7.1"],                  # no cleanup policy
        "GCLOG-001": ["CC7.2"],                  # audit logs not enabled
        "GCLOG-002": ["CC7.2"],                  # no log sink
        "GCLOG-003": ["CC7.2"],                  # log retention < 365 days
        # ── Azure Cloud phase-2 ──────────────────────────────────────
        "ENTRA-004": ["CC6.1"],                  # cond access MFA
        "ENTRA-005": ["CC6.1", "CC6.2"],         # ext user restrict
        "ENTRA-006": ["CC7.2", "CC7.3"],         # risky signin
        "AZST-004":  ["CC6.7"],                  # min TLS
        "AZST-005":  ["CC7.1"],                  # lifecycle
        "AZST-006":  ["CC6.3"],                  # key rotation
        "AKV-004":   ["CC6.3"],                  # key expiry
        "AKV-005":   ["CC6.3"],                  # secret expiry
        "AKV-006":   ["CC6.1"],                  # RBAC
        "ACR-004":   ["CC6.8"],                  # defender scan
        "ACR-005":   ["CC7.1"],                  # tag immutability
        "AZMON-004": ["CC7.2"],                  # KV diagnostics
        "AZMON-005": ["CC7.2"],                  # NSG flow retention
        "AZMON-006": ["CC7.2"],                  # LAW retention
        "AZMON-007": ["CC7.2", "CC7.3", "CC7.4"],  # svc health alert
        "AZNW-001":  ["CC6.6"],                  # SSH/RDP internet (CRITICAL)
        "AZNW-002":  ["CC7.2"],                  # flow logs
        "AZNW-003":  ["CC6.6"],                  # WAF
        "AZNW-004":  ["CC6.6"],                  # deny-all
        "AZNW-005":  ["CC6.6"],                  # public IP VM
        "AZAPP-001": ["CC6.7"],                  # HTTPS
        "AZAPP-002": ["CC6.7"],                  # TLS
        "AZAPP-003": ["CC6.1"],                  # managed identity
        "AZAPP-004": ["CC6.6"],                  # remote debug
        "AZAPP-005": ["CC6.6"],                  # FTP
        "AZSQL-001": ["CC6.1"],                  # TDE CMK
        "AZSQL-002": ["CC7.2"],                  # auditing
        "AZSQL-003": ["CC6.6"],                  # public access
        "AZSQL-004": ["CC6.1"],                  # AAD admin
        "AZSQL-005": ["CC7.2", "CC7.3"],         # threat detect
        "AZVM-001":  ["CC6.1"],                  # disk encrypt
        "AZVM-002":  ["CC6.6"],                  # public IP
        "AZVM-003":  ["CC6.6"],                  # JIT
        "AZVM-004":  ["CC7.1"],                  # OS patch
        "AZVM-005":  ["CC6.1"],                  # managed identity
        # ── GCP phase-2 ──────────────────────────────────────────────
        "GCIAM-004": ["CC6.1"],                  # default SA
        "GCIAM-005": ["CC6.1"],                  # domain restrict
        "GCIAM-006": ["CC6.3"],                  # SA key age
        "GCS-004":   ["CC6.1"],                  # CMEK
        "GCS-005":   ["CC7.2"],                  # access logging
        "GCLOG-004": ["CC7.2"],                  # VPC flow logs
        "GCLOG-005": ["CC7.2"],                  # firewall logging
        "GCLOG-006": ["CC7.2"],                  # data access
        "GCLOG-007": ["CC7.2", "CC7.3"],         # metric filter IAM
        "GCLOG-008": ["CC7.2", "CC7.3"],         # metric filter firewall
        "GCLOG-009": ["CC7.2", "CC7.3"],         # metric filter route
        "GCLOG-010": ["CC7.2", "CC7.3"],         # metric filter SQL
        "GCLOG-011": ["CC7.2", "CC7.3"],         # metric filter custom role
        "GCNET-001": ["CC6.6"],                  # default network
        "GCNET-002": ["CC6.6"],                  # deny-all
        "GCNET-003": ["CC6.6"],                  # SSH/RDP (CRITICAL)
        "GCNET-004": ["CC6.6"],                  # private access
        "GCNET-005": ["CC6.6"],                  # Cloud NAT
        "GCCE-001":  ["CC6.8"],                  # shielded VM
        "GCCE-002":  ["CC6.1"],                  # OS Login
        "GCCE-003":  ["CC6.6"],                  # serial port
        "GCCE-004":  ["CC6.6"],                  # public IP
        "GCCE-005":  ["CC6.6"],                  # project SSH keys
        "GCSQL-001": ["CC6.6"],                  # public IP
        "GCSQL-002": ["CC7.4"],                  # backups
        "GCSQL-003": ["CC6.7"],                  # SSL
        "GCSQL-004": ["CC6.1"],                  # IAM auth
        "GCSQL-005": ["CC7.4"],                  # PITR
        "GCRUN-001": ["CC6.6"],                  # unauth
        "GCRUN-002": ["CC6.1"],                  # custom SA
        "GCRUN-003": ["CC6.6"],                  # min instances
        "GCRUN-004": ["CC6.6"],                  # VPC connector
        "GCKMS-004": ["CC6.1"],                  # keyring IAM
        "GCKMS-005": ["CC6.1"],                  # destroy sched
        "GCKMS-006": ["CC6.1"],                  # imported key
        # Developer-environment auto-execution (malware / untrusted-code vector)
        "DEV-001":   ["CC6.8"],
        "DEV-006":   ["CC6.8"],
        "DEV-007":   ["CC6.8"],   # committed MCP config auto-launches a command server
        "DEV-002":   ["CC6.8"],
        "DEV-003":   ["CC6.8"],
        "DEV-004":   ["CC6.8"],
        "DEV-005":   ["CC6.8"],
    },
)
