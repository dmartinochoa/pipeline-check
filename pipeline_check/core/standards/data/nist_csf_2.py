"""NIST Cybersecurity Framework 2.0 (February 2024).

CSF 2.0 added the GV (Govern) function and restructured the PR
(Protect) function to include PR.PS (Platform Security), both of
which have direct CI/CD pipeline footprints.

CSF is a *framework*, not a control list. Subcategory text is
high-level; this scanner evidences the subcategories whose outcomes
are observable in pipeline configuration. Unmapped subcategories
(awareness/training, physical access, personnel activity, etc.) are
out of scope for a posture-from-YAML tool. Passing mapped checks is
necessary but not sufficient for CSF alignment; many subcategories
additionally require documented processes, training, and ongoing
review that live outside pipeline config.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="nist_csf_2",
    title="NIST Cybersecurity Framework 2.0",
    version="2.0",
    url="https://doi.org/10.6028/NIST.CSWP.29",
    controls={
        # ── GV (Govern), new function in CSF 2.0 ───────────────────
        "GV.SC-03": "Cybersecurity supply chain risk management is integrated into CS and ERM programs",
        "GV.SC-04": "Suppliers are known and prioritized by criticality",
        "GV.SC-05": (
            "Requirements to address cybersecurity risks in supply chains are "
            "established, prioritized, and integrated into contracts"
        ),
        "GV.SC-07": (
            "Risks posed by suppliers, their products and services, are "
            "understood, recorded, prioritized, assessed, responded to, and monitored"
        ),
        "GV.SC-08": (
            "Relevant suppliers and other third parties are included in "
            "incident planning, response, and recovery activities"
        ),
        # ── PR (Protect) ────────────────────────────────────────────
        "PR.AA-01": "Identities and credentials for authorized users, services, and hardware are managed",
        "PR.AA-03": "Users, services, and hardware are authenticated",
        "PR.AA-05": (
            "Access permissions, entitlements, and authorizations are "
            "defined in a policy, managed, enforced, and reviewed"
        ),
        "PR.DS-01": "The confidentiality, integrity, and availability of data-at-rest are protected",
        "PR.DS-02": "The confidentiality, integrity, and availability of data-in-transit are protected",
        "PR.PS-01": "Configuration management practices are established and applied",
        "PR.PS-02": "Software is maintained, replaced, and removed commensurate with risk",
        "PR.PS-04": "Log records are generated and made available for continuous monitoring",
        "PR.PS-05": "Installation and execution of unauthorized software are prevented",
        "PR.PS-06": (
            "Secure software development practices are integrated, and "
            "their performance is monitored throughout the SDLC"
        ),
        "PR.IR-01": "Networks and environments are protected from unauthorized logical access and usage",
        "PR.IR-03": "Mechanisms are implemented to achieve resilience requirements in normal and adverse situations",
        # ── DE (Detect) ─────────────────────────────────────────────
        "DE.CM-01": "Networks and network services are monitored to find potentially adverse events",
        "DE.CM-06": "External service provider activities and services are monitored",
        "DE.CM-09": "Computing hardware and software, runtime environments, and their data are monitored",
        "DE.AE-03": "Information is correlated from multiple sources",
        # ── RS (Respond) / RC (Recover) ─────────────────────────────
        "RS.MA-01": "The incident response plan is executed once an incident is declared",
        "RC.RP-01": "The recovery portion of the incident response plan is executed once initiated",
    },
    mappings={
        # GV.SC-08 (supplier incident-response participation) is
        # contractual / process; no manifest signal evidences it.
        # Left unmapped on purpose.
        # ── GV.SC. Supply-chain risk management ────────────────────
        "GHA-001":  ["GV.SC-05", "GV.SC-07"],
        "GHA-110": ["GV.SC-07"],  # CI env disables Go module verification
        "GHA-021":  ["GV.SC-05"],
        "GHA-025":  ["GV.SC-05"],
        "GHA-029":  ["GV.SC-05"],
        "GL-001":   ["GV.SC-05", "GV.SC-07"],
        "GL-037": ["GV.SC-07"],  # CI env disables Go module verification
        "GL-005":   ["GV.SC-05"],
        "GL-042":   ["GV.SC-05"],    # include: component unpinned
        "GL-009":   ["GV.SC-05"],
        "GL-021":   ["GV.SC-05"],
        "GL-027":   ["GV.SC-05"],
        "GL-028":   ["GV.SC-05"],
        "GL-030":   ["GV.SC-05"],
        "BB-001":   ["GV.SC-05", "GV.SC-07"],
        "BB-009":   ["GV.SC-05"],
        "BB-021":   ["GV.SC-05"],
        "BB-027":   ["GV.SC-05"],
        "ADO-001":  ["GV.SC-05", "GV.SC-07"],
        "ADO-005":  ["GV.SC-05"],
        "ADO-009":  ["GV.SC-05"],
        "ADO-021":  ["GV.SC-05"],
        "ADO-025":  ["GV.SC-05"],
        "ADO-028":  ["GV.SC-05"],
        "JF-001":   ["GV.SC-05", "GV.SC-07"],
        "JF-009":   ["GV.SC-05"],
        "JF-021":   ["GV.SC-05"],
        "JF-031":   ["GV.SC-05"],
        "CC-001":   ["GV.SC-05", "GV.SC-07"],
        "CC-033": ["GV.SC-07"],  # CI env disables Go module verification
        "CC-003":   ["GV.SC-05"],
        "CC-021":   ["GV.SC-05"],
        "CC-028":   ["GV.SC-05"],
        "CC-029":   ["GV.SC-05"],
        "GCB-001":  ["GV.SC-05"],
        "CB-009":   ["GV.SC-05"],
        "ECR-006":  ["GV.SC-04", "GV.SC-07", "DE.CM-06"],   # pull-through upstream = external provider
        "CA-002":   ["GV.SC-04", "GV.SC-07"],
        "GHA-018":  ["GV.SC-04"],
        "GL-018":   ["GV.SC-04"],
        "BB-014":   ["GV.SC-04"],
        "ADO-018":  ["GV.SC-04"],
        "JF-018":   ["GV.SC-04"],
        "CC-018":   ["GV.SC-04"],
        # Automated dependency-update tooling = ongoing third-party monitoring
        "GHA-022":  ["GV.SC-07"],
        "GL-022":   ["GV.SC-07"],
        "BB-022":   ["GV.SC-07"],
        "ADO-022":  ["GV.SC-07"],
        "JF-022":   ["GV.SC-07"],
        "CC-022":   ["GV.SC-07"],
        # SBOM = inventory of third-party components
        "GHA-007":  ["GV.SC-03", "GV.SC-04"],
        "GL-007":   ["GV.SC-03", "GV.SC-04"],
        "BB-007":   ["GV.SC-03", "GV.SC-04"],
        "ADO-007":  ["GV.SC-03", "GV.SC-04"],
        "JF-007":   ["GV.SC-03", "GV.SC-04"],
        "CC-007":   ["GV.SC-03", "GV.SC-04"],

        # ── PR.AA. Identity & access ───────────────────────────────
        "IAM-001":  ["PR.AA-05"],
        "IAM-002":  ["PR.AA-05"],
        "IAM-003":  ["PR.AA-05"],
        "IAM-004":  ["PR.AA-05"],
        "IAM-005":  ["PR.AA-01", "PR.AA-03"],
        "IAM-006":  ["PR.AA-05"],
        "IAM-007":  ["PR.AA-01"],
        "IAM-008":  ["PR.AA-03"],
        "IAM-009":  ["PR.AA-03"],
        "IAM-010":  ["PR.AA-03"],
        "KMS-002":  ["PR.AA-05"],
        "CB-001":   ["PR.AA-01"],
        "CB-006":   ["PR.AA-01"],
        "CP-004":   ["PR.AA-01"],
        "GHA-004":  ["PR.AA-05"],
        "GHA-005":  ["PR.AA-01"],
        "GHA-008":  ["PR.AA-01"],
        "GHA-019":  ["PR.AA-01"],
        "GL-003":   ["PR.AA-01"],
        "GL-008":   ["PR.AA-01"],
        "DEV-008":   ["PR.AA-01"],   # literal secret in a devenv config
        "GL-013":   ["PR.AA-01"],
        "GL-020":   ["PR.AA-01"],
        "BB-003":   ["PR.AA-01"],
        "BB-008":   ["PR.AA-01"],
        "BB-011":   ["PR.AA-01"],
        "BB-017":   ["PR.AA-01"],
        "BB-019":   ["PR.AA-01"],
        "ADO-003":  ["PR.AA-01"],
        "ADO-008":  ["PR.AA-01"],
        "ADO-014":  ["PR.AA-01"],
        "JF-004":   ["PR.AA-01"],
        "JF-008":   ["PR.AA-01"],
        "JF-010":   ["PR.AA-01"],
        "CC-005":   ["PR.AA-01"],
        "CC-008":   ["PR.AA-01"],
        "CC-019":   ["PR.AA-01"],
        "CC-030":   ["PR.AA-05"],
        "GCB-002":  ["PR.AA-03"],
        "GCB-003":  ["PR.AA-01"],
        "GCB-007":  ["PR.AA-01"],
        "CCM-003":  ["PR.AA-05", "DE.CM-06"],   # cross-account trigger = external sink
        "CA-004":   ["PR.AA-05"],
        "SM-001":   ["PR.AA-01"],
        "SM-002":   ["PR.AA-05"],
        "SSM-001":  ["PR.AA-01"],

        # ── PR.DS. Data protection ─────────────────────────────────
        "S3-002":   ["PR.DS-01"],
        "S3-003":   ["PR.DS-01", "PR.IR-03", "RC.RP-01"],
        "S3-005":   ["PR.DS-02"],
        "CP-002":   ["PR.DS-01"],
        "ECR-005":  ["PR.DS-01"],
        "CA-001":   ["PR.DS-01"],
        "KMS-001":  ["PR.DS-01"],
        "SSM-002":  ["PR.DS-01"],
        "LMB-003":  ["PR.DS-01"],
        "GHA-023":  ["PR.DS-02"],
        "GL-023":   ["PR.DS-02"],
        "BB-023":   ["PR.DS-02"],
        "ADO-023":  ["PR.DS-02"],
        "JF-023":   ["PR.DS-02"],
        "CC-023":   ["PR.DS-02"],

        # ── PR.PS. Platform security (NEW in CSF 2.0) ──────────────
        # PS-01: configuration management
        "CB-002":   ["PR.PS-01"],
        "CB-004":   ["PR.PS-01"],
        "GHA-012":  ["PR.PS-01"],
        "GHA-105":  ["PR.PS-01"],
        "GHA-015":  ["PR.PS-01"],
        "GHA-017":  ["PR.PS-01"],
        "GHA-026":  ["PR.PS-01"],
        "GHA-107":  ["PR.PS-01"],   # harden-runner in audit mode (egress not blocked)
        "GHA-108":  ["PR.PS-01"],   # no runtime egress control on OIDC/deploy workflow
        "GHA-109":  ["PR.PS-01"],   # harden-runner not the first step
        "GL-014":   ["PR.PS-01"],
        "GL-015":   ["PR.PS-01"],
        "GL-017":   ["PR.PS-01"],
        "GL-039":   ["PR.PS-01"],# dind daemon TLS disabled / exposed on 2375
        "BB-005":   ["PR.PS-01"],
        "BB-013":   ["PR.PS-01"],
        "BB-016":   ["PR.PS-01"],
        "BB-020":   ["PR.PS-01"],
        "ADO-013":  ["PR.PS-01"],
        "ADO-015":  ["PR.PS-01"],
        "ADO-017":  ["PR.PS-01"],
        "JF-003":   ["PR.PS-01"],
        "JF-014":   ["PR.PS-01"],
        "JF-015":   ["PR.PS-01"],
        "JF-017":   ["PR.PS-01"],
        "JF-025":   ["PR.PS-01"],
        "CC-010":   ["PR.PS-01"],
        "CC-014":   ["PR.PS-01"],
        "CC-015":   ["PR.PS-01"],
        "CC-017":   ["PR.PS-01"],
        "GCB-005":  ["PR.PS-01"],
        # PS-02: software maintained commensurate with risk
        # CB-005 co-maps: outdated image evidences both SC-risk monitoring
        # (GV.SC-07) and software-maintained-commensurate-with-risk (PS-02).
        "CB-005":   ["GV.SC-07", "PR.PS-02"],
        "ECR-002":  ["GV.SC-05", "PR.PS-02", "RC.RP-01"],   # mutable tags also break recovery-by-digest
        "GHA-020":  ["PR.PS-02"],
        "GL-019":   ["PR.PS-02"],
        "GL-043":   ["PR.PS-02"],               # native security scanner disabled
        "BB-015":   ["PR.PS-02"],
        "ADO-020":  ["PR.PS-02"],
        "JF-020":   ["PR.PS-02"],
        "CC-020":   ["PR.PS-02"],
        "GCB-008":  ["PR.PS-02"],
        "ECR-001":  ["PR.PS-02"],
        "ECR-007":  ["PR.PS-02"],
        # PS-04: log records (co-map with DE.CM-09 monitoring)
        "CB-003":   ["PR.PS-04", "DE.CM-09"],
        "CT-001":   ["PR.PS-04", "DE.CM-09", "DE.AE-03"],
        "CT-002":   ["PR.PS-04", "DE.CM-09", "DE.AE-03"],
        "CT-003":   ["PR.PS-04", "DE.CM-09", "DE.AE-03"],   # multi-region trail = cross-region correlation
        "CWL-001":  ["PR.PS-04", "DE.CM-09"],
        "CWL-002":  ["PR.PS-04", "DE.CM-09"],
        "S3-004":   ["PR.PS-04", "DE.CM-01", "DE.AE-03"],
        "JF-011":   ["PR.PS-04"],
        "CC-011":   ["PR.PS-04"],
        # PS-05: prevent unauthorized software execution
        "CB-011":   ["PR.PS-05"],
        "GHA-003":  ["PR.PS-05"],
        "GHA-119":  ["PR.PS-05"],# untrusted context into an agentic AI CLI
        "GHA-120":  ["PR.PS-05"],# trust_remote_code model load = code exec
        "GHA-122":  ["PR.PS-05"],# unsafe pickle deser of fetched artifact = code exec
        "GHA-117":  ["PR.PS-05"],# IaC apply on untrusted PR trigger
        "GHA-118":  ["PR.PS-05"],# untrusted content into $GITHUB_ENV / $GITHUB_PATH
        "GHA-016":  ["PR.PS-05"],
        "GHA-027":  ["PR.PS-05"],
        "GHA-028":  ["PR.PS-05"],
        "GL-002":   ["PR.PS-05"],
        "GL-045":   ["PR.PS-05"],   # trust_remote_code model load = code exec
        "GL-047":   ["PR.PS-05"],   # unsafe pickle deser of fetched artifact = code exec
        "GL-048":   ["PR.PS-05"],   # untrusted MR context into agentic CLI = prompt injection
        "GL-049":   ["PR.PS-06"],   # agentic CLI output lands without review
        "GL-016":   ["PR.PS-05"],
        "GL-025":   ["PR.PS-05"],
        "GL-026":   ["PR.PS-05"],
        "BB-002":   ["PR.PS-05"],
        "BB-035":   ["PR.PS-05"],   # trust_remote_code model load = code exec
        "BB-036":   ["PR.PS-05"],   # untrusted PR context into agentic CLI = prompt injection
        "BB-037":   ["PR.PS-05"],   # unsafe pickle deser of fetched artifact = code exec
        "BB-039":   ["PR.PS-06"],   # agentic CLI output lands without review
        "JF-038":   ["PR.PS-06"],   # agentic CLI output lands without review
        "JF-039":   ["PR.PS-05"],   # trust_remote_code model load = code exec
        "JF-040":   ["GV.SC-05"],   # model pulled without a pinned revision
        "JF-041":   ["PR.PS-05"],   # unsafe pickle deser of fetched artifact = code exec
        "JF-042":   ["PR.AA-01", "PR.DS-01"],   # secret echoed to Jenkins build log
        "BB-012":   ["PR.PS-05"],
        "BB-025":   ["PR.PS-05"],
        "BB-026":   ["PR.PS-05"],
        "ADO-002":  ["PR.PS-05"],
        "ADO-034":  ["PR.PS-05"],   # trust_remote_code model load = code exec
        "ADO-035":  ["PR.PS-05"],   # untrusted PR context into agentic CLI = prompt injection
        "ADO-036":  ["PR.PS-05"],   # unsafe pickle deser of fetched artifact = code exec
        "ADO-038":  ["PR.PS-06"],   # agentic CLI output lands without review
        "ADO-016":  ["PR.PS-05"],
        "ADO-026":  ["PR.PS-05"],
        "ADO-027":  ["PR.PS-05"],
        "JF-002":   ["PR.PS-05"],
        "JF-037":   ["PR.PS-05"],   # agentic CLI ingests untrusted context (prompt injection)
        "JF-012":   ["PR.PS-05"],
        "JF-016":   ["PR.PS-05"],
        "JF-019":   ["PR.PS-05"],
        "JF-029":   ["PR.PS-05"],
        "JF-030":   ["PR.PS-05"],
        "JF-033":   ["PR.AA-01", "PR.DS-01"],   # withCredentials leaked via ${} interpolation
        "JF-034":   ["PR.AA-01"],               # password() build parameter
        "JF-035":   ["GV.SC-05", "PR.DS-02"],   # httpRequest ignoreSslErrors
        "CC-002":   ["PR.PS-05"],
        "CC-016":   ["PR.PS-05"],
        "CC-026":   ["PR.PS-05"],
        "CC-027":   ["PR.PS-05"],
        "ARGO-019":  ["PR.PS-05"],  # Argo dangerous shell idiom
        "TKN-018":  ["PR.PS-05"],  # Tekton dangerous shell idiom
        "HARNESS-014":  ["PR.PS-05"],  # Harness dangerous shell idiom
        "GCB-004":  ["PR.PS-05"],
        "GCB-006":  ["PR.PS-05"],
        # PS-06: secure software development practices
        "SIGN-001": ["PR.PS-06"],
        "SIGN-002": ["PR.PS-06"],
        "LMB-001":  ["PR.PS-06"],
        "GHA-006":  ["PR.PS-06"],
        "GHA-024":  ["PR.PS-06"],
        "GL-006":   ["PR.PS-06"],
        "GL-024":   ["PR.PS-06"],
        "BB-006":   ["PR.PS-06"],
        "BB-024":   ["PR.PS-06"],
        "ADO-006":  ["PR.PS-06"],
        "ADO-024":  ["PR.PS-06"],
        "JF-006":   ["PR.PS-06"],
        "JF-028":   ["PR.PS-06"],
        "CC-006":   ["PR.PS-06"],
        "CC-024":   ["PR.PS-06"],
        "GCB-009":  ["PR.PS-06"],

        # ── PR.IR. Resilience & boundary protection ────────────────
        "PBAC-001": ["PR.IR-01"],
        "PBAC-002": ["PR.IR-01"],
        "PBAC-003": ["PR.IR-01"],
        "PBAC-005": ["PR.IR-01"],
        "ECR-003":  ["PR.IR-01"],
        "S3-001":   ["PR.IR-01"],
        "LMB-002":  ["PR.IR-01"],
        "LMB-004":  ["PR.IR-01"],
        "CP-003":   ["PR.IR-01"],
        "CP-007":   ["PR.IR-01"],
        "GHA-002":  ["PR.IR-01"],
        "RUN-001":  ["PR.IR-01"],
        "RUN-002":  ["PR.IR-01"],
        "GLRUN-001": ["PR.IR-01"],  # gitlab forensics: merge-request pipeline executed
        "GLRUN-002": ["PR.IR-01"],  # gitlab forensics: fork merge-request pipeline executed
        "GLRUN-003": ["PR.IR-01"],  # gitlab forensics: secret leaked in fork pipeline trace
        "GLRUN-004": ["PR.IR-01"],  # gitlab forensics: fork pipeline minted a cloud OIDC token
        "GLRUN-005": ["PR.IR-01"],  # gitlab forensics: fork pipeline ran on a self-managed runner
        "RUN-003":  ["PR.IR-01"],
        "RUN-004":  ["PR.IR-01"],
        "RUN-005":  ["PR.IR-01"],
        "RUN-006":  ["GV.SC-05", "GV.SC-07"],
        "RUN-007":  ["GV.SC-05", "GV.SC-07"],
        "GHA-009":  ["PR.IR-01"],
        "GHA-010":  ["PR.IR-01"],
        "GHA-011":  ["PR.IR-01"],
        "GHA-013":  ["PR.IR-01"],
        "GHA-044":  ["PR.IR-01"],
        "GHA-045":  ["PR.IR-01"],
        "GHA-046":  ["PR.IR-01"],
        "GL-010":   ["PR.IR-01"],
        "GL-011":   ["PR.IR-01"],
        "GL-012":   ["PR.IR-01"],
        "BB-010":   ["PR.IR-01"],
        "BB-018":   ["PR.IR-01"],
        "ADO-010":  ["PR.IR-01"],
        "ADO-011":  ["PR.IR-01"],
        "ADO-012":  ["PR.IR-01"],
        "ADO-019":  ["PR.IR-01"],
        "JF-013":   ["PR.IR-01"],
        "CC-012":   ["PR.IR-01"],
        "CC-013":   ["PR.IR-01"],
        "CC-025":   ["PR.IR-01"],
        # CD-001 / CD-003 co-map: resilience + recovery / incident-mgmt.
        "CD-001":   ["PR.IR-03", "RC.RP-01"],
        "CD-003":   ["PR.IR-03", "RS.MA-01"],
        # ECR-002 (mutable tags) already maps to GV.SC-05 + PR.PS-02
        # above; mutable tags also break recovery-by-digest, evidence
        # for RC.RP-01.

        # ── DE.CM / DE.AE. Monitoring (cross-domain inputs) ────────
        # CW-001 / EB-001 co-map: a missing alarm / event rule is
        # both a monitoring gap (DE.CM-09) and a missing incident-
        # response trigger (RS.MA-01).
        "EB-001":   ["DE.CM-09", "RS.MA-01"],
        "EB-002":   ["DE.CM-06"],
        "CW-001":   ["DE.CM-09", "RS.MA-01"],
        "CB-007":   ["DE.CM-06"],
        # CCM-003 / ECR-006 already map to GV.SC-* above; both are
        # also external-service-provider monitoring surfaces
        # (cross-account event sinks, pull-through cache upstreams).

        # ── Kubernetes, workload runtime + RBAC + network +
        # configuration management. The pack maps cleanly across
        # PR.PS (platform security), PR.AA (access), PR.IR (network),
        # PR.DS (data integrity), and DE.CM (runtime monitoring).
        "K8S-001":  ["GV.SC-05", "PR.PS-02"],   # image not pinned to digest
        "K8S-002":  ["PR.PS-01"],               # hostNetwork
        "K8S-003":  ["PR.PS-01"],               # hostPID
        "K8S-004":  ["PR.PS-01"],               # hostIPC
        "K8S-005":  ["PR.PS-01", "PR.PS-05"],   # privileged container
        "K8S-006":  ["PR.PS-01"],               # allowPrivilegeEscalation
        "K8S-007":  ["PR.PS-01"],               # runAsNonRoot
        "K8S-008":  ["PR.PS-01"],               # readOnlyRootFilesystem
        "K8S-009":  ["PR.PS-01"],               # capabilities
        "K8S-010":  ["PR.PS-01"],               # seccompProfile
        "K8S-011":  ["PR.AA-05"],               # default ServiceAccount
        "K8S-012":  ["PR.AA-01"],               # automountServiceAccountToken
        "K8S-013":  ["PR.PS-01"],               # hostPath volume
        "K8S-014":  ["PR.PS-01"],               # sensitive hostPath
        "K8S-015":  ["PR.IR-03"],               # memory limit
        "K8S-016":  ["PR.IR-03"],               # cpu limit
        "K8S-017":  ["PR.AA-01", "PR.DS-01"],   # env credential
        "K8S-018":  ["PR.AA-01", "PR.DS-01"],   # Secret data credential
        "K8S-019":  ["PR.PS-01"],               # default namespace
        "K8S-020":  ["PR.AA-05"],               # cluster-admin RoleBinding
        "K8S-021":  ["PR.AA-05"],               # wildcard verbs
        "K8S-022":  ["PR.IR-01"],               # SSH service exposed
        "K8S-023":  ["PR.PS-01"],               # PSA enforce missing
        "K8S-044":  ["PR.PS-01"],               # admission webhook fail-open / unscoped mutating
        "K8S-024":  ["DE.CM-09"],               # readiness/liveness probes
        "K8S-025":  ["PR.PS-01"],               # system priority class
        "K8S-026":  ["PR.IR-01"],               # LB without source ranges
        "K8S-027":  ["PR.DS-02"],               # Ingress without TLS
        "K8S-028":  ["PR.IR-01"],               # host port
        "K8S-029":  ["PR.AA-05"],               # default-SA RoleBinding
        "K8S-030":  ["PR.PS-01"],               # control-plane scheduling
        "K8S-031":  ["PR.PS-01"],               # PSA warn label missing
        "K8S-032":  ["PR.IR-01"],               # NetworkPolicy default-deny
        "K8S-033":  ["PR.IR-03"],               # ResourceQuota / LimitRange
        "K8S-034":  ["PR.AA-01"],               # SA automount default
        "K8S-035":  ["PR.PS-01"],               # runAsUser: 0
        "K8S-036":  ["GV.SC-05"],               # SA imagePullSecret missing
        "K8S-037":  ["PR.AA-01", "PR.DS-01"],   # ConfigMap credential
        "K8S-038":  ["PR.IR-01"],               # NetworkPolicy allow-all
        "K8S-039":  ["PR.PS-01"],               # shareProcessNamespace
        "K8S-040":  ["PR.PS-01"],               # procMount: Unmasked
        "K8S-041":  ["PR.IR-01"],               # Service externalIPs (MITM)
        "K8S-042":  ["PR.AA-05"],               # anonymous RoleBinding
        "K8S-043":  ["PR.IR-01"],               # Ingress wildcard host

        # ── Helm, chart-supply-chain hygiene maps to GV.SC. ────────
        "HELM-001": ["GV.SC-05"],   # legacy v1 schema
        "HELM-002": ["GV.SC-05", "GV.SC-07"],   # Chart.lock missing digests
        "HELM-003": ["GV.SC-05", "PR.DS-02"],   # non-HTTPS dep repo
        "HELM-004": ["GV.SC-05"],   # dep version not exact-pinned
        "HELM-005": ["GV.SC-04"],   # maintainers chain-of-custody
        "HELM-006": ["GV.SC-07"],   # kubeVersion compat range
        "HELM-007": ["GV.SC-04"],   # description empty (chart identity)
        "HELM-008": ["GV.SC-07"],   # Chart.lock stale
        "HELM-009": ["GV.SC-05", "PR.DS-02"],   # non-HTTPS sources
        "HELM-010": ["GV.SC-04"],   # appVersion empty
        # ── Helm extended pack ──
        "HELM-011": ["PR.DS-01"],   # dependency URL embedded creds
        "HELM-012": ["GV.SC-04"],   # deprecated without successor
        "HELM-013": ["GV.SC-04"],   # invalid chart type
        "HELM-014": ["GV.SC-05"],   # known-compromised dep
        "HELM-015": ["GV.SC-07"],  # oci:// dependency not digest-pinned
        "HELM-016": ["PR.DS-01"],  # default secret in values.yaml
        "HELM-017": ["GV.SC-07"],  # tpl of an untrusted .Values value
        # ── Dockerfile, image-build supply chain. ─────────────────
        # Pinning + verification rules tie to GV.SC-05 (supply chain
        # requirements established and verified). Privileged / root
        # rules tie to PR.PS-01 (config management practices).
        # Credential rules tie to PR.AA-01 (identity / credential
        # management). Vuln-scan / outdated-dep rules tie to PR.PS-02.
        "DF-001": ["GV.SC-05"],                 # FROM not digest-pinned
        "MODEL-001": ["GV.SC-05"],              # unpinned base model
        "MODEL-002": ["GV.SC-05"],              # third-party hub base model
        "MODEL-003": ["GV.SC-05"],              # local unverified weights blob
        "MODEL-004": ["GV.SC-05"],              # remote LoRA adapter
        "MODEL-005": ["GV.SC-05"],              # config auto_map = custom loader code
        "DF-031": ["GV.SC-05"],                 # COPY --from external image not digest-pinned
        "DF-002": ["PR.PS-01"],                 # runs as root
        "DF-003": ["GV.SC-05", "PR.DS-02"],     # ADD remote no integrity
        "DF-004": ["GV.SC-05", "PR.DS-02"],     # curl-pipe
        "DF-005": ["PR.PS-05"],                 # shell-eval
        "DF-006": ["PR.AA-01", "PR.DS-01"],     # ENV credential literal
        "DF-007": ["DE.CM-09"],                 # no HEALTHCHECK
        "DF-008": ["PR.PS-01"],                 # docker --privileged
        "DF-010": ["PR.PS-02"],                 # apt upgrade
        "DF-011": ["PR.PS-02"],                 # no cache cleanup
        "DF-012": ["PR.PS-01"],                 # RUN sudo
        "DF-013": ["PR.PS-01", "PR.IR-01"],     # sensitive EXPOSE
        "DF-014": ["PR.PS-01"],                 # WORKDIR /etc
        "DF-015": ["PR.PS-01"],                 # chmod 777
        "DF-016": ["GV.SC-05"],                 # OCI provenance labels
        "DF-017": ["PR.PS-01"],                 # PATH world-writable
        "DF-018": ["PR.PS-01"],                 # chown system path
        "DF-019": ["PR.AA-01"],                 # COPY credential file
        "DF-020": ["PR.AA-01"],                 # credential ARG
        "DF-021": ["GV.SC-05", "PR.DS-02"],     # pip TLS bypass / http index
        "DF-022": ["GV.SC-05"],                 # npm install vs npm ci
        "DF-023": ["PR.PS-01"],                 # ENV loader-hijack var
        # ── Buildkite. CI provider mappings mirror what the GHA /
        # GitLab packs already use: PR.PS-01 (config management),
        # GV.SC-05 (third-party verification), PR.AA-01 (credential
        # mgmt), PR.PS-04 (logs), PR.PS-05 (unauth-software preven-
        # tion), DE.CM-* (monitoring).
        "BK-001": ["GV.SC-05"],                 # plugin not pinned
        "BK-002": ["PR.AA-01", "PR.DS-01"],     # literal secret
        "BK-003": ["PR.PS-05"],                 # untrusted variable interp
        "BK-004": ["GV.SC-05", "PR.DS-02"],     # curl-pipe
        "BK-005": ["PR.PS-01"],                 # privileged container
        "BK-006": ["PR.PS-01"],                 # no timeout
        "BK-007": ["PR.AA-05", "PR.PS-06"],     # no manual deploy gate
        "BK-008": ["PR.DS-02"],                 # TLS bypass
        "BK-009": ["GV.SC-05", "PR.PS-06"],     # no signing
        "HARNESS-015":  ["GV.SC-05", "PR.PS-06"],  # Harness artifacts not signed
        "DR-019":  ["GV.SC-05", "PR.PS-06"],  # Drone artifacts not signed
        "BK-010": ["GV.SC-05"],                 # no SBOM
        "HARNESS-016":  ["GV.SC-05"],  # Harness no SBOM
        "DR-020":  ["GV.SC-05"],  # Drone no SBOM
        "BK-011": ["GV.SC-05"],                 # no SLSA provenance
        "HARNESS-017":  ["GV.SC-05"],  # Harness no SLSA provenance
        "DR-021":  ["GV.SC-05"],  # Drone no SLSA provenance
        "BK-012": ["PR.PS-02", "DE.CM-09"],     # no vuln scan
        "HARNESS-018":  ["PR.PS-02", "DE.CM-09"],  # Harness no vuln scan
        "DR-022":  ["PR.PS-02", "DE.CM-09"],  # Drone no vuln scan
        "BK-013": ["PR.AA-05"],                 # no branches filter
        "BK-014": ["GV.SC-05"],                 # unpinned package install
        "BK-015": ["PR.PS-05"],                 # agents map untrusted interpolation
        # ── Per-CI provider container-relevant gaps ─────────────
        # Follow the existing pattern: pinning/3rd-party → GV.SC-05;
        # secrets/creds → PR.AA-01 (+ PR.DS-01 for at-rest variants);
        # IAM access → PR.AA-05; privileged/runtime → PR.PS-01;
        # dangerous-shell / interpolation / poisoned-pipeline →
        # PR.PS-05; deploy gates / approval / branch filter →
        # PR.PS-06; TLS bypass / data-in-transit → PR.DS-02;
        # cache-poisoning / cross-step taint / fork-PR triggers →
        # PR.IR-01; SBOM → GV.SC-03 + GV.SC-04; signing → PR.PS-06;
        # vuln scan / outdated deps → PR.PS-02; reputation →
        # GV.SC-04 + GV.SC-07; logs → PR.PS-04 + DE.CM-09.
        # ── GitHub Actions ───────────────────────────────────────
        "GHA-014":  ["PR.PS-06"],               # deploy job missing environment
        "GHA-123":  ["PR.PS-06"],               # agentic CLI output lands without review
        "GHA-030":  ["PR.AA-05"],               # OIDC w/o env-protected job
        "GHA-031":  ["PR.PS-05"],               # retired set-output / save-state
        "GHA-032":  ["PR.PS-05"],               # local script on untrusted trigger
        "GHA-033":  ["PR.AA-01", "PR.DS-01"],   # secret echoed
        "GHA-034":  ["PR.AA-05", "PR.AA-01"],   # secrets: inherit
        "GHA-035":  ["PR.PS-05"],               # github-script untrusted context
        "GHA-036":  ["PR.PS-05"],               # runs-on untrusted context
        "GHA-037":  ["PR.AA-01"],               # checkout persists GITHUB_TOKEN
        "GHA-038":  ["PR.PS-05"],               # ACTIONS_ALLOW_UNSECURE_COMMANDS
        "GHA-039":  ["PR.AA-01"],               # services / container creds literal
        "GHA-040":  ["GV.SC-05", "GV.SC-07"],   # known-compromised action ref
        "GHA-041":  ["GV.SC-04", "GV.SC-07"],   # single-maintainer action
        "GHA-042":  ["GV.SC-04", "GV.SC-07"],   # very-young action repo
        "GHA-043":  ["GV.SC-04", "GV.SC-07"],   # low-star + sensitive perms
        "GHA-047":  ["GV.SC-07"],               # fresh-ref cooldown
        "GHA-048":  ["PR.PS-01"],               # workflow self-mutation
        "GHA-049":  ["PR.AA-05"],               # cross-repo push from CI
        "GHA-050":  ["PR.AA-01"],               # long-lived registry publish token
        "GHA-051":  ["GV.SC-05"],               # services / container image unpinned
        "GHA-052":  ["PR.IR-01"],               # cache key untrusted-input poisoning
        "GHA-053":  ["PR.PS-05"],               # if: predicate untrusted-context
        "GHA-054":  ["PR.AA-01"],               # checkout ssh-key persists
        "GHA-055":  ["PR.AA-01"],               # reusable outputs leak secret
        "GHA-056":  ["PR.PS-05", "GV.SC-07"],   # worm IOC strings
        "GHA-057":  ["PR.DS-01", "DE.CM-06"],   # secret-scanner output → egress
        "GHA-058":  ["PR.PS-05"],               # agentic CLI permission-bypass
        "GHA-059":  ["GV.SC-05"],               # npm install without audit signatures
        "GHA-060":  ["GV.SC-05"],               # pip install without --require-hashes
        "GHA-061":  ["PR.AA-05"],               # App token minted without permissions filter
        "GHA-106":  ["PR.AA-05"],               # AI agent with write-scoped token
        "GHA-111":  ["PR.AA-05"],  # AI agent edits IaC applied in the same job
        "GHA-112":  ["PR.PS-01"],  # self-hosted deploy with no environment gate
        "GHA-113":  ["PR.AA-05"],  # OIDC trusted-publish w/o env gate
        "GHA-114":  ["PR.AA-05"],  # publish workflow on an unrestricted push trigger
        "GHA-115":  ["PR.AA-05"],  # id-token granted workflow-wide, not job-scoped
        "GHA-116":  ["PR.AA-05", "PR.AA-01"],   # bulk secrets serialization
        "GHA-062":  ["PR.AA-05"],               # OIDC trust subject in sibling IaC is overly broad
        "GHA-063":  ["PR.AA-01"],               # spoofable bot-actor if-predicate
        "GHA-064":  ["PR.PS-06"],               # unsound contains() with comma-string operand
        "GHA-065":  ["PR.PS-05"],               # zero-width / bidi unicode in workflow body
        "GHA-066":  ["PR.DS-01"],               # upload-artifact wildcard sweeps workspace
        "GHA-067":  ["PR.DS-01"],               # cache step publishes credential-shaped paths
        "GHA-068":  ["PR.PS-02"],               # runs-on targets a deprecated hosted runner
        "GHA-069":  ["PR.AA-05"],               # orphan id-token: write scope
        "GHA-070":  ["PR.DS-02"],               # ssh-keyscan / host-key check TOFU
        "GHA-071":  ["PR.PS-05"],               # powershell on Linux / macOS step
        "GHA-072":  ["PR.AA-01", "PR.DS-01"],   # secret env: at wider scope than consumer
        "GHA-073":  ["PR.AA-01"],               # unused workflow_call.secrets declaration
        "GHA-086":  ["PR.PS-06"],               # wildcard branch trigger + environment binding
        "GHA-087":  ["PR.AA-01", "PR.DS-01"],   # derived-value of secret printed to log
        "GHA-088":  ["GV.SC-05", "GV.SC-07"],   # typosquat uses: near-edit of top action
        "GHA-089":  ["GV.SC-05", "GV.SC-07"],   # archived upstream repo
        "GHA-090":  ["GV.SC-05", "GV.SC-07"],   # impostor-commit: SHA absent from repo
        "GHA-091":  ["GV.SC-05", "GV.SC-07"],   # repojacking: action upstream missing
        "GHA-092":  ["PR.IR-01"],               # TOCTOU PR head SHA force-push race
        "GHA-093":  ["PR.AA-01", "PR.DS-01"],   # LOTP indicators
        "GHA-094":  ["GV.SC-05", "GV.SC-07"],   # stale-action-refs
        "GHA-096":  ["GV.SC-05", "GV.SC-07"],   # known-vulnerable action ref (GHSA)
        # ── GitLab CI ─────────────────────────────────────────────
        "GL-004":  ["PR.PS-06"],                # manual deploy allow_failure
        "GL-044":  ["PR.PS-06"],                # auto production deploy on an MR pipeline
        "GL-029":  ["PR.PS-06"],                # manual deploy allow_failure (variant)
        "GL-031":  ["PR.AA-05"],                # id_tokens missing audience pin
        "GL-040":  ["PR.AA-05"],                # CI_JOB_TOKEN used for cross-project access
        "GL-041":  ["PR.PS-05"],                # IaC apply on an untrusted MR trigger
        "GL-050":   ["PR.AA-01"],  # publish job long-lived registry token (GHA-050 analog)
        "GL-032":  ["PR.PS-05"],                # tags interpolates untrusted
        "GL-033":  ["PR.PS-05"],                # global before_script taint
        "GL-034":  ["GV.SC-05"],                # npm install without audit signatures
        "GL-035":  ["GV.SC-05"],                # pip install without --require-hashes
        # ── Bitbucket Pipelines ──────────────────────────────────
        "BB-004":  ["PR.PS-06"],                # deploy step missing environment
        "BB-034":  ["PR.PS-06"],                # prod deploy on a PR pipeline
        "BB-033":  ["PR.PS-05"],                # IaC apply on a PR pipeline
        "ADO-033": ["PR.PS-05"],                # IaC apply on a PR-validated pipeline
        "BK-016":  ["PR.PS-05"],                # dangerous shell idiom
        "JF-036":  ["PR.PS-05"],                # shell step interpolates params.*
        "BB-028":  ["PR.AA-05"],                # OIDC step w/o env gate
        "BB-029":  ["GV.SC-05"],                # step+service image not pinned
        "BB-030":  ["GV.SC-05"],                # npm install without audit signatures
        "BB-031":  ["GV.SC-05"],                # pip install without --require-hashes
        "BB-038":  ["GV.SC-05"],                # model pulled without a pinned revision
        # ── Azure DevOps Pipelines ───────────────────────────────
        "ADO-004": ["PR.PS-06"],                # deploy missing environment
        "ADO-029": ["PR.PS-06"],                # service-conn job w/o env gate
        "ADO-030": ["PR.PS-05"],                # pool interpolates untrusted
        "ADO-037": ["GV.SC-05"],                # model pulled without a pinned revision
        # ── CircleCI ──────────────────────────────────────────────
        "CC-004":  ["PR.AA-01"],                # unrestricted context
        "CC-009":  ["PR.PS-06"],                # job missing approval gate
        "CC-031":  ["PR.AA-05"],                # OIDC role w/o branch filter
        # ── Jenkins ──────────────────────────────────────────────
        "JF-005":  ["PR.PS-06"],                # deploy stage missing manual input
        "JF-024":  ["PR.PS-06"],                # input approval missing submitter restriction
        "JF-026":  ["PR.PS-01"],                # build job: trigger ignores downstream failure
        "JF-027":  ["GV.SC-04"],                # archiveArtifacts no fingerprint
        "JF-032":  ["PR.PS-05"],                # agent label interpolates untrusted
        # ── Drone CI ─────────────────────────────────────────────
        "DR-001":  ["GV.SC-05"],                # step image not digest-pinned
        "HARNESS-001":   ["GV.SC-05"],  # Harness step image not digest-pinned
        "HARNESS-002":   ["PR.PS-05"],  # Harness expression injection in step command
        "HARNESS-003":   ["PR.PS-01"],  # Harness privileged step
        "HARNESS-004":   ["PR.AA-01"],  # Harness literal credential in variable
        "HARNESS-005":   ["GV.SC-05"],  # Harness pipe-to-shell
        "HARNESS-006":   ["PR.DS-02"],  # Harness TLS bypass in commands
        "HARNESS-007":   ["PR.PS-01"],  # Harness sensitive host-path mount
        "HARNESS-008":   ["PR.PS-05"],  # Harness agentic-CLI prompt injection
        "HARNESS-010":   ["PR.PS-05"],  # Harness model trust_remote_code (code exec)
        "HARNESS-011":   ["PR.PS-05"],  # Harness unsafe model deser (pickle RCE)
        "HARNESS-012":   ["GV.SC-05"],  # Harness model pulled without a pinned revision
        "HARNESS-013":   ["PR.AA-01", "PR.DS-01"],  # Harness secret echoed to step log
        "GCB-028":  ["PR.AA-01", "PR.DS-01"],  # Cloud Build secret echoed to build log
        "ARGO-018":  ["PR.AA-01", "PR.DS-01"],  # Argo secret echoed to template log
        "TKN-017":  ["PR.AA-01", "PR.DS-01"],  # Tekton secret echoed to step log
        "DR-018":  ["PR.AA-01", "PR.DS-01"],  # Drone secret echoed to step log
        "BK-017":  ["PR.AA-01", "PR.DS-01"],  # Buildkite secret echoed to step log
        "HARNESS-009":   ["PR.PS-06"],  # Harness agentic-CLI output autolands without review
        "DR-002":  ["PR.PS-01"],                # privileged step
        "DR-003":  ["PR.PS-05"],                # Drone variable injection
        "DR-004":  ["PR.AA-01"],                # literal credential
        "DR-005":  ["GV.SC-05"],                # plugin floating tag
        "DR-006":  ["PR.DS-02"],                # TLS bypass in commands
        "DR-007":  ["PR.PS-01"],                # sensitive host-path mount
        "DR-008":  ["GV.SC-05"],                # pull: never (skips registry verify)
        "DR-009":  ["PR.IR-01"],                # cache key tainted
        "DR-010":  ["GV.SC-05"],                # unpinned package install
        "DR-011":  ["PR.PS-05"],                # node map interpolates untrusted
        # ── Drone extended pack ──
        "DR-012":  ["GV.SC-05"],                # service image not pinned
        "DR-013":  ["GV.SC-07"],                # no trigger event filter
        "DR-014":  ["GV.SC-05"],                # pipe-to-shell
        "DR-015":  ["GV.SC-05"],                # clone recursive
        "DR-016":  ["GV.SC-07"],                # image field interpolation
        "DR-017":  ["PR.PS-05"],                # dangerous shell idiom
        # ── Tekton (K8s-native pipeline kinds) ────────────────────
        "TKN-001": ["GV.SC-05", "PR.PS-02"],    # step image not digest-pinned
        "TKN-016": ["GV.SC-05", "PR.PS-02"],  # remote resolver / bundle task body not pinned
        "TKN-002": ["PR.PS-01"],                # step privileged / root
        "TKN-003": ["PR.PS-05"],                # param injection in script
        "TKN-004": ["PR.PS-01"],                # hostPath / host namespaces
        "TKN-005": ["PR.AA-01", "PR.DS-01"],    # leaked creds
        "TKN-006": ["PR.PS-01"],                # no explicit timeout
        "TKN-007": ["PR.AA-05"],                # default ServiceAccount
        "TKN-008": ["GV.SC-05", "PR.DS-02"],    # remote install / TLS bypass
        "TKN-009": ["PR.PS-06"],                # artifacts not signed
        "TKN-010": ["GV.SC-03", "GV.SC-04"],    # SBOM not generated
        "TKN-011": ["PR.PS-06", "GV.SC-05"],    # SLSA provenance
        "TKN-012": ["PR.PS-02"],                # no vulnerability scanning
        "TKN-013": ["PR.PS-01"],                # sidecar privileged / root
        "TKN-014": ["GV.SC-05"],                # unpinned package install
        "TKN-015": ["PR.PS-05"],                # workspace subPath param injection
        # ── Argo Workflows ───────────────────────────────────────
        "ARGO-001": ["GV.SC-05", "PR.PS-02"],   # template image not digest-pinned
        "ARGO-002": ["PR.PS-01"],               # template privileged / root
        "ARGO-003": ["PR.AA-05"],               # default ServiceAccount
        "ARGO-016": ["PR.AA-05"],               # cluster-admin / over-privileged ServiceAccount
        "ARGO-004": ["PR.PS-01"],               # hostPath / host namespaces
        "ARGO-005": ["PR.PS-05"],               # parameter injection
        "ARGO-017": ["PR.PS-05"],               # resource template manifest injection
        "ARGO-006": ["PR.AA-01", "PR.DS-01"],   # leaked creds
        "ARGO-007": ["PR.PS-01"],               # missing activeDeadlineSeconds
        "ARGO-008": ["GV.SC-05", "PR.DS-02"],   # remote install / TLS bypass
        "ARGO-009": ["PR.PS-06"],               # artifacts not signed
        "ARGO-010": ["GV.SC-03", "GV.SC-04"],   # SBOM not generated
        "ARGO-011": ["PR.PS-06", "GV.SC-05"],   # SLSA provenance
        "ARGO-012": ["PR.PS-02"],               # no vulnerability scanning
        "ARGO-013": ["PR.AA-01"],               # SA token automount default
        "ARGO-014": ["GV.SC-05"],               # unpinned package install
        "ARGO-015": ["PR.DS-02"],               # insecure (non-HTTPS) artifact URL
        # ── Argo CD (GitOps deployment) ──
        "ARGOCD-010": ["GV.SC-07"],             # mutable targetRevision
        "ARGOCD-017": ["GV.SC-07"],  # in-cluster mutable source
        "ARGOCD-019": ["GV.SC-07"],  # drift detection disabled on a sensitive field
        "ARGOCD-016": ["GV.SC-07"],  # Helm valueFiles from a remote URL
        "ARGOCD-018": ["GV.SC-07"],  # custom resource health / action Lua
        "ARGOCD-011": ["PR.AA-05"],             # cluster-resource wildcard
        "ARGOCD-012": ["GV.SC-07"],             # no sync windows
        "ARGOCD-013": ["GV.SC-07"],             # no revision history cap
        # ── Cloud Build container-touching extras ─────────────────
        "GCB-010": ["GV.SC-05", "PR.DS-02"],    # remote script piped to shell
        "GCB-011": ["PR.DS-02"],                # TLS bypass
        "GCB-012": ["PR.AA-01"],                # literal secret in pipeline body
        "GCB-013": ["GV.SC-05"],                # pkg install bypasses registry integrity
        "GCB-014": ["PR.PS-04", "DE.CM-09"],    # build logging disabled
        "GCB-015": ["GV.SC-03", "GV.SC-04"],    # no SBOM step
        "GCB-016": ["PR.PS-05"],                # dir path escape
        "GCB-017": ["PR.PS-06", "GV.SC-05"],    # no SLSA provenance
        "GCB-018": ["PR.AA-01"],                # legacy KMS secrets block
        "GCB-019": ["PR.PS-05"],                # shell entrypoint + user substitution
        "GCB-020": ["PR.AA-05"],                # default Cloud Build SA
        "GCB-021": ["PR.IR-01"],                # no private worker pool
        "GCB-022": ["PR.PS-05"],                # ALLOW_LOOSE substitution
        "GCB-023": ["PR.PS-05"],                # undeclared user substitution
        "GCB-024": ["GV.SC-04"],                # images: missing for docker push
        "GCB-025": ["PR.PS-04"],                # tags: empty (audit/discoverability)
        "GCB-026": ["PR.PS-01"],                # waitFor unknown step id
        "GCB-027": ["PR.PS-05"],                # malicious-activity indicators
        # ── AWS extras ───────────────────────────────────────────
        "CB-008":  ["PR.PS-06"],                # inline buildspec, not from protected repo
        "CB-010":  ["PR.IR-01"],                # fork-PR webhook unfiltered
        "CP-001":  ["PR.PS-06"],                # no manual approval
        "CP-005":  ["PR.PS-06"],                # prod Deploy stage no manual approval
        "CD-002":  ["PR.IR-03"],                # AllAtOnce deployment
        "CCM-001": ["PR.PS-06"],                # CodeCommit no approval rule
        "CCM-002": ["PR.DS-01"],                # CodeCommit repo not CMK
        "CA-003":  ["PR.AA-05"],                # CodeArtifact cross-account wildcard
        "ECR-004": ["PR.PS-02"],                # ECR no lifecycle policy
        # ── Terraform / CloudFormation (IaC-native) ───────────────
        "TF-001":   ["PR.AA-01"],               # aws_iam_access_key declared as code
        "TF-002":   ["PR.AA-01", "PR.DS-01"],   # hard-coded secret in resource attr
        "TF-003":   ["PR.IR-01"],               # CodeBuild VPC shares public subnet
        "CF-001":   ["PR.AA-01"],               # AWS::IAM::AccessKey declared as code
        "CF-002":   ["PR.AA-01", "PR.DS-01"],   # hard-coded secret in resource property
        "CF-003":   ["PR.IR-01"],               # CodeBuild VPC shares public subnet
        # ── SCM posture (governance via the platform REST API) ──────
        # Branch protection / review controls map primarily to
        # PR.PS-06 (secure software development practices). Access-
        # control surfaces map to PR.AA-05 (access permissions) and
        # PR.AA-01 (identities and credentials). Scanning / detection
        # surfaces map to DE.CM-09. Supply-chain surfaces (allowed
        # actions, Dependabot) map to GV.SC-05.
        "SCM-001":  ["PR.PS-06", "PR.AA-05"],   # default branch unprotected
        "SCM-002":  ["PR.PS-06"],               # required reviews missing
        "SCM-003":  ["PR.PS-06", "DE.CM-09"],   # default code scanning disabled
        "SCM-004":  ["PR.DS-01", "DE.CM-09"],   # secret scanning disabled
        "SCM-005":  ["PR.PS-02", "GV.SC-05"],   # Dependabot security updates off
        "SCM-006":  ["PR.PS-06", "PR.AA-03"],   # signed commits not required
        "SCM-007":  ["PR.PS-06"],               # force-push allowed
        "SCM-008":  ["PR.PS-06"],               # required status checks missing
        "SCM-009":  ["PR.PS-06"],               # branch deletions allowed
        "SCM-010":  ["PR.AA-05", "PR.PS-06"],   # admin bypass allowed
        "SCM-011":  ["PR.PS-06"],               # CODEOWNERS reviews not required
        "SCM-012":  ["PR.PS-06"],               # stale reviews not dismissed
        "SCM-013":  ["PR.PS-06"],               # conversation resolution not required
        "SCM-014":  ["PR.PS-06"],               # last-push approval not required
        "SCM-015":  ["PR.DS-01", "DE.CM-09"],   # secret scanning push protection off
        "SCM-016":  ["RS.MA-01", "DE.AE-03"],   # private vulnerability reporting (intake + correlation)
        "SCM-017":  ["PR.PS-06"],               # CODEOWNERS file missing
        "SCM-018":  ["PR.PS-06", "PR.AA-05"],   # PR review bypass allowed
        "SCM-019":  ["PR.AA-05", "PR.PS-06"],   # push-restriction allowlist names users
        # Actions governance + environments + deploy keys
        "SCM-020":  ["PR.AA-01", "PR.AA-05"],   # workflow_token default write
        "SCM-021":  ["PR.PS-06"],               # Actions can approve PRs
        "SCM-022":  ["GV.SC-05", "PR.PS-05"],   # allowed_actions unrestricted
        "SCM-023":  ["PR.PS-06"],               # env missing reviewers
        "SCM-024":  ["PR.PS-01"],               # env branch policy missing
        "SCM-025":  ["PR.AA-01"],               # deploy keys write-enabled
        "SCM-026":  ["PR.DS-02", "PR.AA-01", "DE.CM-06"],   # webhook = external service integration
        "SCM-027":  ["PR.AA-05"],               # outside collaborator elevated
        "SCM-028":  ["PR.AA-05"],               # private repo allows forking
        # Ruleset enforcement
        "SCM-029":  ["PR.PS-06", "PR.PS-01"],   # ruleset not enforced
        "SCM-030":  ["PR.AA-05", "PR.PS-06"],   # ruleset always-bypass
        "SCM-031":  ["PR.PS-06"],               # auto-merge enabled
        "SCM-032":  ["PR.PS-06"],               # ruleset lacks PR review
        "SCM-033":  ["PR.PS-06"],               # ruleset lacks status_checks
        "SCM-034":  ["PR.PS-06"],               # ruleset allows force_push
        "SCM-035":  ["PR.PS-06"],               # ruleset allows deletion
        "SCM-036":  ["PR.PS-06", "PR.AA-03"],   # ruleset lacks signed_commits
        "SCM-037":  ["PR.PS-06"],               # ruleset stale-review dismissal
        "SCM-038":  ["PR.PS-06"],               # ruleset lacks linear_history
        "SCM-039":  ["PR.PS-06", "PR.PS-05"],   # ruleset lacks required_workflows
        "SCM-040":  ["DE.CM-09", "PR.PS-06"],   # ruleset lacks code_scanning gate
        "SCM-041":  ["PR.PS-06", "PR.PS-01"],   # ruleset lacks deployment-env gate
        "SCM-042":  ["PR.PS-06"],               # ruleset lacks merge queue
        "SCM-043":  ["PR.PS-06", "PR.AA-03"],   # tag-ruleset lacks signed_commits
        "SCM-044":  ["PR.PS-06"],               # required_signatures bypassed for admins
        "SCM-045":  ["DE.CM-09", "PR.PS-06"],   # default code scanning limited query suite
        "SCM-046":  ["DE.CM-09", "PR.PS-06"],   # default code scanning configured but paused
        "SCM-047":  ["DE.CM-09", "PR.PS-06"],   # repo language not covered
        # ── NPM / PyPI / Maven dep supply-chain ──────────────────
        # Per-package pinning / integrity / non-registry source
        # → GV.SC-05 (third-party verification). Compromised
        # versions also evidence GV.SC-07 (supplier-risk monitoring)
        # and PR.PS-02 (software maintained commensurate with risk).
        # HTTP indexes / wildcard mirrors / TLS bypass add PR.DS-02
        # (data in transit). Install-time lifecycle scripts and
        # secret-shaped file globs evidence PR.PS-05 / PR.AA-01.
        "NPM-001":  ["GV.SC-05"],               # floating range
        "NPM-002":  ["GV.SC-05"],               # lock entry missing integrity
        "NPM-003":  ["GV.SC-05"],               # non-registry source
        "NPM-004":  ["PR.PS-05"],               # install-time lifecycle script
        "NPM-005":  ["GV.SC-05"],               # git dep mutable ref
        "NPM-006":  ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # compromised npm version
        "NPM-007":  ["PR.PS-05"],               # .npmrc ignore-scripts
        "NPM-011":  ["PR.AA-01", "PR.DS-01"],   # secret-shaped paths in files field
        "NPM-013":  ["PR.AA-01", "PR.DS-01"],   # broad files-field publishes everything
        "PYPI-001": ["GV.SC-05"],               # missing ==pin
        "PYPI-002": ["GV.SC-05"],               # hash pinning missing
        "PYPI-003": ["GV.SC-05", "PR.DS-02"],   # http index / --trusted-host
        "PYPI-018": ["GV.SC-05", "PR.DS-02"],  # --no-binary forces sdist build
        "PYPI-019": ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # missing PEP 740 build provenance
        "PYPI-020": ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # low OpenSSF Scorecard upstream
        "PYPI-021": ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # provenance built from a non-release ref
        "PYPI-004": ["GV.SC-05"],               # VCS dep without commit SHA
        "PYPI-015": ["GV.SC-05"],  # direct artifact URL
        "PYPI-005": ["GV.SC-05"],               # --extra-index-url (dep confusion)
        "PYPI-017": ["GV.SC-05"],  # remote --find-links
        "PYPI-016": ["GV.SC-05"],  # primary index repointed
        "PYPI-006": ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # compromised PyPI version
        "MVN-001":  ["GV.SC-05"],               # floating Maven range
        "MVN-002":  ["GV.SC-05"],               # mutable SNAPSHOT dep
        "MVN-003":  ["GV.SC-05", "PR.DS-02"],   # plaintext-HTTP repository
        "MVN-004":  ["GV.SC-05"],               # missing <version>
        "MVN-005":  ["GV.SC-05"],               # lax checksumPolicy
        "MVN-006":  ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # compromised Maven version
        "MVN-007":  ["GV.SC-05"],               # settings.xml wildcard mirror
        "MVN-008":  ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # cooldown gate (--resolve-remote)
        "MVN-009":  ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # OSV advisory (--resolve-remote)
        # ── Maven extended pack ──
        "MVN-010":  ["PR.DS-01"],               # plaintext server password
        "MVN-011":  ["PR.DS-01"],               # repo URL credentials
        "MVN-012":  ["GV.SC-07"],               # build plugin floating
        "MVN-013":  ["GV.SC-07"],               # build extension floating
        "MVN-014":  ["GV.SC-07"],               # wrapper sha256 missing
        "MVN-015": ["GV.SC-07"],  # build-time plugin exec bound to lifecycle
        "MVN-016": ["GV.SC-07"],  # gradle allowInsecureProtocol
        "MVN-017": ["PR.DS-01"],  # settings.xml privateKey + plaintext passphrase
        "MVN-018": ["GV.SC-07"],  # distributionManagement release accepts snapshots
        "NPM-008":  ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # cooldown gate (--resolve-remote)
        "NPM-009":  ["GV.SC-05"],               # new-transitive-dep diff gate
        "NPM-010":  ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # OSV advisory (--resolve-remote)
        "NPM-014":  ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # single-publisher risk
        "NPM-015":  ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # missing build provenance
        "NPM-017":  ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # provenance built from a non-release ref
        "NPM-018":  ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # latest release from a new publisher
        "NPM-019":  ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # overrides / resolutions redirect
        "NPM-020":  ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # .npmrc registry repoint
        "NPM-016":  ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # low OpenSSF Scorecard
        "PYPI-008": ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # cooldown gate (--resolve-remote)
        "PYPI-009": ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # OSV advisory (--resolve-remote)
        # ── PyPI extended pack (PYPI-010..014) ──
        "PYPI-010": ["PR.DS-01"],                # index URL embedded credentials
        "PYPI-011": ["GV.SC-07"],                # --trusted-host disables TLS
        "PYPI-012": ["GV.SC-07"],                # build-system requires floating
        "PYPI-013": ["GV.SC-07"],                # pyproject dynamic dependencies
        "PYPI-014": ["GV.SC-07"],                # custom source HTTP
        # ── nuget (dep supply-chain) ─────────────────────────────
        "NUGET-001": ["GV.SC-05"],              # floating NuGet version range
        "NUGET-002": ["GV.SC-05"],              # wildcard prerelease version
        "NUGET-003": ["GV.SC-05"],              # missing explicit version
        "NUGET-004": ["GV.SC-05", "PR.DS-02"],  # HTTP-only package source
        "NUGET-005": ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # known-compromised package version
        "NUGET-006": ["GV.SC-05"],              # no lock file for reproducible restores
        "NUGET-007": ["GV.SC-05"],              # multiple sources without packageSourceMapping
        "NUGET-008": ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # cooldown gate (--resolve-remote)
        "NUGET-009": ["GV.SC-05", "GV.SC-07", "PR.PS-02"],  # OSV advisory (--resolve-remote)
        "NUGET-010": ["PR.AA-01", "PR.DS-01"],  # NuGet.config cleartext feed credential
        # ── NuGet extended pack ──
        "NUGET-011": ["GV.SC-07"],              # source mapping wildcard
        "NUGET-012": ["GV.SC-07", "GV.SC-05"],  # signature validation off
        "NUGET-013": ["GV.SC-07"],              # dotnet-tools unpinned
        "NUGET-014": ["PR.DS-01"],              # source URL credentials
        "NUGET-015": ["GV.SC-07"],              # VersionOverride breaks CPM
        "NUGET-016": ["GV.SC-05"],              # missing <clear/> inherits public gallery
        "NUGET-017": ["GV.SC-05"],  # public gallery active alongside private feed, not disabled
        "NUGET-018": ["GV.SC-07"],              # build-time MSBuild execution
        "NUGET-019": ["GV.SC-07", "GV.SC-05"],  # require mode, no trusted signers
        # ── Go modules ─────────────────────────────────────────
        "GOMOD-001": ["PR.DS-01", "GV.SC-07"],  # go.sum integrity manifest missing
        "GOMOD-002": ["GV.SC-07", "GV.SC-08"],  # replace directive to local path
        "GOMOD-003": ["GV.SC-07", "GV.SC-08"],  # replace directive to different module
        "GOMOD-004": ["GV.SC-07"],              # +incompatible direct require
        "GOMOD-005": ["GV.SC-07"],              # missing go toolchain directive
        "GOMOD-006": ["GV.SC-05", "GV.SC-08"],  # known-compromised module version
        # ── Go modules extended pack ──
        "GOMOD-007": ["PR.DS-01", "GV.SC-07"],  # vendor/modules.txt stale
        "GOMOD-008": ["GV.SC-07"],              # replace without version pin
        "GOMOD-009": ["GV.SC-07"],              # pre-release direct require
        "GOMOD-010": ["GV.SC-07"],              # stale exclude directive
        "GOMOD-011": ["GV.SC-07"],  # tool directive build-time exec
        "GOMOD-012": ["GV.SC-07"],  # insecure / non-canonical module host
        # ── Cargo ──────────────────────────────────────────────
        "CARGO-001": ["GV.SC-07"],              # floating Cargo.toml version spec
        "CARGO-002": ["GV.SC-07", "GV.SC-08"],  # git dep with mutable ref (no rev)
        "CARGO-003": ["PR.DS-01", "GV.SC-07"],  # missing Cargo.lock
        "CARGO-004": ["GV.SC-07", "GV.SC-08"],  # local-path Cargo dependency
        "CARGO-005": ["GV.SC-07", "GV.SC-08"],  # alternate-registry Cargo dependency
        "CARGO-006": ["GV.SC-05", "GV.SC-08"],  # known-compromised crate version
        # ── Cargo extended pack ──
        "CARGO-007": ["GV.SC-07", "GV.SC-08"],  # build-deps floating
        "CARGO-008": ["GV.SC-07"],              # patch.crates-io substitution
        "CARGO-009": ["GV.SC-07"],              # workspace deps floating
        "CARGO-010": ["GV.SC-07"],              # missing rust-version
        "CARGO-011": ["GV.SC-07"],  # build.rs compile-time egress / exec
        "CARGO-012": ["GV.SC-07"],  # .cargo/config.toml source override / build flags
        "CARGO-013": ["GV.SC-07"],  # Cargo.lock off-crates.io source
        "CARGO-014": ["GV.SC-07"],  # no supply-chain audit-gate config
        # ── Composer / PHP ──
        "COMPOSER-001": ["GV.SC-05", "GV.SC-07"],
        "COMPOSER-002": ["GV.SC-05", "GV.SC-07"],
        "COMPOSER-003": ["GV.SC-05", "PR.DS-02"],
        "COMPOSER-012": ["GV.SC-05", "PR.DS-02"],  # disables Packagist / marks custom repo canonical
        "COMPOSER-011": ["GV.SC-05", "PR.DS-02"],  # external VCS repository re-points a package
        "COMPOSER-004": ["PR.DS-01", "PR.AA-01"],
        "COMPOSER-005": ["GV.SC-05", "GV.SC-07"],
        "COMPOSER-014": ["GV.SC-05", "GV.SC-07"],  # minimum-stability without prefer-stable
        "COMPOSER-006": ["GV.SC-05", "GV.SC-08"],
        "COMPOSER-007": ["GV.SC-05", "GV.SC-08"],
        "COMPOSER-008": ["GV.SC-05", "GV.SC-07"],
        "COMPOSER-009": ["PR.DS-01", "PR.AA-01"],
        "COMPOSER-010": ["GV.SC-05", "PR.DS-02"],
        "COMPOSER-013": ["GV.SC-05", "PR.DS-02"],  # config.disable-tls
        # ── RubyGems / Bundler ──
        "GEM-001": ["GV.SC-05", "GV.SC-07"],
        "GEM-002": ["GV.SC-05", "GV.SC-07"],
        "GEM-003": ["GV.SC-05", "PR.DS-02"],
        "GEM-004": ["PR.DS-01", "PR.AA-01"],
        "GEM-005": ["GV.SC-05", "GV.SC-07"],
        "GEM-006": ["GV.SC-05", "GV.SC-08"],
        "GEM-007": ["GV.SC-05"],
        "GEM-008": ["GV.SC-05", "GV.SC-07"],
        "GEM-009": ["PR.DS-01", "PR.AA-01"],
        "GEM-010": ["GV.SC-05", "GV.SC-07"],
        "GEM-011": ["GV.SC-07"],  # Bundler plugin install-time exec
        "GEM-012": ["GV.SC-07"],  # per-gem :source override
        "GEM-013": ["GV.SC-07"],  # insecure git transport
        # ── Pulumi (PULUMI-001..006) ──
        "PULUMI-001": ["PR.DS-01", "PR.AA-01"],  # passphrase secretsprovider
        "PULUMI-002": ["PR.DS-01"],              # secret-shaped config plaintext
        "PULUMI-003": ["PR.DS-01", "PR.AA-01"],  # hardcoded credentials in source
        "PULUMI-011": ["PR.DS-01", "PR.AA-01"],  # plugin from custom download server
        "PULUMI-004": ["PR.DS-01", "PR.AA-01"],  # insecure state backend
        "PULUMI-005": ["PR.AA-05"],              # wildcard IAM policy in source
        "PULUMI-006": ["GV.SC-07"],              # StackReference unguarded
        # ── Pulumi extended pack ──
        "PULUMI-007": ["PR.AA-05"],              # public-access cloud resource
        "PULUMI-008": ["GV.SC-07"],              # shell-exec with non-constant input
        "PULUMI-013": ["GV.SC-07"],  # dynamic provider deploy-time code
        "PULUMI-014": ["GV.SC-07"],  # ESC environment imported without a qualifier
        "PULUMI-009": ["GV.SC-07"],              # runtime / source mismatch
        "PULUMI-012": ["GV.SC-07"],  # plugin version unpinned
        "PULUMI-010": ["PR.DS-01"],              # stack orphaned encryption salt
        # ── OCI image manifest gaps ──────────────────────────────
        "OCI-001":  ["GV.SC-05"],               # provenance annotations missing
        "OCI-002":  ["PR.PS-06", "GV.SC-05"],   # build attestation missing
        "OCI-003":  ["GV.SC-05"],               # missing image.created
        "OCI-004":  ["GV.SC-05"],               # foreign-layer URL reference
        "OCI-005":  ["GV.SC-04"],               # missing image.licenses
        "OCI-006":  ["PR.PS-01"],               # excessive layer count
        "OCI-007":  ["GV.SC-05"],               # legacy schemaVersion 1
        "OCI-008":  ["GV.SC-05"],               # weak digest algorithm
        "OCI-009":  ["GV.SC-05"],               # missing base-image annotations
        # ── SLSA / in-toto attestation content ───────────────────
        "ATTEST-001": ["PR.PS-06", "GV.SC-05"], # untrusted SLSA builder identity
        "ATTEST-002": ["PR.PS-06", "GV.SC-05"], # source-repo claim unverifiable
        "ATTEST-003": ["GV.SC-04"],             # SBOM floating versions
        "ATTEST-004": ["GV.SC-04"],             # provenance lacks materials
        "ATTEST-005": ["PR.PS-06", "GV.SC-05"], # in-toto subject digest unpinned
        "ATTEST-006": ["PR.PS-06"],             # buildType missing / placeholder
        "ATTEST-007": ["GV.SC-04"],             # SBOM missing supplier
        # ── Cross-cutting dataflow / taint engine ────────────────
        # Cross-step / cross-job untrusted data reaching a privileged
        # sink is both an isolation failure (PR.IR-01) and an unauth-
        # software-execution surface (PR.PS-05).
        "TAINT-001": ["PR.IR-01", "PR.PS-05"],
        "TAINT-002": ["PR.IR-01", "PR.PS-05"],
        "TAINT-003": ["PR.IR-01", "PR.PS-05"],
        "TAINT-004": ["PR.IR-01", "PR.PS-05"],
        "TAINT-005": ["PR.IR-01", "PR.PS-05"],
        "TAINT-006": ["PR.IR-01", "PR.PS-05"],
        "TAINT-007": ["PR.IR-01", "PR.PS-05"],
        "TAINT-008": ["PR.IR-01", "PR.PS-05"],
        "TAINT-009": ["PR.AA-01", "PR.DS-01"],  # env-protected secret flows to unprotected job
        # ── Dockerfile extras ───────────────────────────────────
        "DF-009":   ["GV.SC-05"],               # ADD where COPY suffices
        "DF-024":   ["PR.PS-05"],               # npm install runs lifecycle scripts
        "DF-025":   ["PR.AA-01"],               # registry token in image layer
        "DF-026":   ["GV.SC-05", "PR.DS-02"],   # NODE_TLS_REJECT_UNAUTHORIZED=0
        "DF-027":   ["GV.SC-05", "PR.DS-02"],   # PYTHONHTTPSVERIFY=0
        "DF-028":   ["GV.SC-05", "PR.DS-02"],   # GIT_SSL_NO_VERIFY=1
        "DF-029":   ["GV.SC-05", "PR.DS-02"],   # REQUESTS_CA_BUNDLE neutered
        "DF-030":   ["PR.PS-01", "PR.PS-05"],   # NODE_OPTIONS --require / --inspect
        # ── Degraded-mode findings (API access failures) ─────────
        # When the scanner cannot enumerate a provider surface, the
        # visibility gap surfaces as a log/monitoring gap — PR.PS-04
        # (log records generated) + DE.CM-09 (computing hw/sw
        # monitored). Mirrors the cross-standard precedent.
        "CB-000":   ["PR.PS-04", "DE.CM-09"],
        "CP-000":   ["PR.PS-04", "DE.CM-09"],
        "CD-000":   ["PR.PS-04", "DE.CM-09"],
        "ECR-000":  ["PR.PS-04", "DE.CM-09"],
        "IAM-000":  ["PR.PS-04", "DE.CM-09"],
        "PBAC-000": ["PR.PS-04", "DE.CM-09"],
        "CT-000":   ["PR.PS-04", "DE.CM-09"],
        "CWL-000":  ["PR.PS-04", "DE.CM-09"],
        "EB-000":   ["PR.PS-04", "DE.CM-09"],
        "CA-000":   ["PR.PS-04", "DE.CM-09"],
        "CCM-000":  ["PR.PS-04", "DE.CM-09"],
        "LMB-000":  ["PR.PS-04", "DE.CM-09"],
        "KMS-000":  ["PR.PS-04", "DE.CM-09"],
        "SM-000":   ["PR.PS-04", "DE.CM-09"],
        "SSM-000":  ["PR.PS-04", "DE.CM-09"],
        "S3-000":   ["PR.PS-04", "DE.CM-09"],
        # supply-chain posture pack
        "GHA-097":  ["PR.PS-01"],                # recursive PR auto-merge loop
        "GHA-098":  ["PR.PS-06", "PR.PS-02"],    # deploy without security scan gate
        "GHA-099":  ["PR.AA-01", "PR.DS-01"],    # deploy env plaintext secret
        "GHA-100":  ["GV.SC-05", "PR.PS-06"],    # cosign verify no identity binding
        "GHA-102":  ["PR.IR-01", "PR.PS-05"],    # submodule checkout on PR trigger
        "GHA-103":  ["PR.PS-05"],               # AI review bot on untrusted trigger
        "GHA-104":  ["PR.PS-05"],               # AI agent auto-push without PR review
        "GL-036":   ["PR.AA-01", "PR.DS-01"],   # secret echoed to GitLab CI log
        "GL-038":   ["PR.AA-01", "PR.DS-01"],   # CI_DEBUG_TRACE dumps secrets to GitLab CI log
        "BB-032":   ["PR.AA-01", "PR.DS-01"],   # secret echoed to Bitbucket log
        "ADO-031":  ["PR.AA-01", "PR.DS-01"],   # secret echoed to Azure DevOps log
        "ADO-032":  ["PR.AA-01", "PR.DS-01"],   # checkout persistCredentials leaks token to .git/config
        "CC-032":   ["PR.AA-01", "PR.DS-01"],   # secret echoed to CircleCI log
        "CC-034":   ["PR.PS-05"],   # trust_remote_code model load = code exec
        "CC-035":   ["GV.SC-05"],   # model pulled without a pinned revision
        "CC-036":   ["PR.PS-05"],   # unsafe pickle deser of fetched artifact = code exec
        "CC-037":   ["PR.PS-05"],   # agentic CLI ingests untrusted context (prompt injection)
        "CC-038":   ["PR.PS-06"],   # agentic CLI output lands without review
        "SCM-048":  ["PR.AA-05"],                # org codespace secrets scoped to all repos
        "SCM-049":  ["PR.AA-01", "PR.AA-05"],    # classic PAT used where fine-grained suffices
        "ORG-001":  ["PR.AA-01", "PR.AA-05"],    # org governance: 2FA not required org-wide
        "ORG-002":  ["PR.AA-01", "PR.AA-05"],    # org governance: default member permission too broad
        "ORG-003":  ["GV.SC-05", "GV.SC-07"],    # org governance: no Actions allow-list (any action runs)
        "ORG-004":  ["PR.AA-01", "PR.AA-05"],    # org governance: default workflow token is write
        "ORG-005":  ["PR.PS-06"],                # org governance: Actions can approve PRs (review bypass)
        "ORG-006":  ["PR.AA-05"],                # org governance: Actions secret scoped to all repos
        "ORG-007":  ["PR.AA-05"],                # org governance: private-repo forking allowed (code exfiltration)
        "GLGRP-001":  ["PR.AA-01", "PR.AA-05"],  # gitlab group: 2FA not required
        "GLGRP-002":  ["PR.AA-05"],  # gitlab group: forking outside group allowed
        "GLGRP-003":  ["PR.AA-05"],  # gitlab group: sharing projects outside the hierarchy
        "GLGRP-004":  ["PR.PS-06", "PR.AA-05"],  # gitlab group: default branch protection disabled for new projects
        "GLGRP-005":  ["PR.DS-02"],  # gitlab group: group webhook over insecure transport
        "GLGRP-006":  ["PR.AA-01"],  # gitlab group: group CI/CD variable holds a secret with a weak control
        "ORG-008":  ["PR.AA-05"],                # org governance: members can create public repos (code exposure)
        "ORG-009":  ["PR.PS-01"],                # org governance: self-hosted runner group exposed to public repos
        "ORG-010":  ["PR.DS-01", "DE.CM-09"],    # org governance: new-repo secret-scanning push-protection default off
        "ORG-011":  ["PR.DS-02"],                # org governance: org webhook over insecure transport
        "ORG-012":  ["PR.PS-02", "GV.SC-05"],    # org governance: new-repo Dependabot security-updates default off
        "ORG-013":  ["PR.PS-06", "PR.PS-01"],    # org governance: org ruleset not enforced (evaluate/disabled)
        "NPM-012":  ["PR.AA-01", "GV.SC-05"],   # publish token missing restrictions
        # ── Azure Cloud (Entra ID / Storage / Key Vault / ACR / Monitor) ──
        "ENTRA-001": ["PR.AA-05"],               # SP assigned Global Administrator
        "ENTRA-002": ["PR.AA-01"],               # app credential beyond 180 days
        "ENTRA-003": ["PR.AA-01"],               # SP uses password credential
        "AZST-001":  ["PR.IR-01"],               # public blob access
        "AZST-002":  ["PR.DS-02"],               # non-HTTPS traffic
        "AZST-003":  ["PR.DS-01"],               # no CMK encryption
        "AKV-001":   ["PR.DS-01", "PR.IR-03"],   # soft delete not enabled
        "AKV-002":   ["PR.DS-01", "PR.IR-03"],   # purge protection not enabled
        "AKV-003":   ["PR.IR-01"],               # network ACLs allow all
        "ACR-001":   ["PR.AA-05"],               # admin user enabled
        "ACR-002":   ["PR.IR-01"],               # public network access
        "ACR-003":   ["GV.SC-05", "PR.PS-06"],   # content trust not enabled
        "AZMON-001": ["PR.PS-04", "DE.CM-09"],   # no diagnostic setting
        "AZMON-002": ["PR.PS-04"],               # log retention < 365 days
        "AZMON-003": ["DE.CM-09", "RS.MA-01"],   # no alert rule
        # ── GCP (IAM / GCS / KMS / Artifact Registry / Cloud Logging) ────
        "GCIAM-001": ["PR.AA-05"],               # SA has Owner/Editor role
        "GCIAM-002": ["PR.AA-01"],               # user-managed SA key
        "GCIAM-003": ["PR.AA-05"],               # token creator without condition
        "GCS-001":   ["PR.IR-01"],               # public bucket
        "GCS-002":   ["PR.AA-05"],               # no uniform access
        "GCS-003":   ["PR.DS-01", "PR.IR-03"],   # versioning not enabled
        "GCKMS-001": ["PR.DS-01"],               # key rotation > 365 days
        "GCKMS-002": ["PR.AA-05", "PR.DS-01"],   # public KMS key access
        "GCKMS-003": ["PR.DS-01"],               # no HSM protection
        "GAR-001":   ["PR.PS-02"],               # no vulnerability scanning
        "GAR-002":   ["PR.IR-01"],               # publicly readable repo
        "GAR-003":   ["PR.PS-02"],               # no cleanup policy
        "GCLOG-001": ["PR.PS-04", "DE.CM-09"],   # audit logs not enabled
        "GCLOG-002": ["PR.PS-04", "DE.CM-09"],   # no log sink
        "GCLOG-003": ["PR.PS-04"],               # log retention < 365 days
        # ── Azure Cloud phase-2 ──────────────────────────────────────
        "ENTRA-004": ["PR.AA-03"],               # cond access MFA
        "ENTRA-005": ["PR.AA-05"],               # ext user restrict
        "ENTRA-006": ["DE.CM-09"],               # risky signin
        "AZST-004":  ["PR.DS-02"],               # min TLS
        "AZST-005":  ["PR.PS-01"],               # lifecycle
        "AZST-006":  ["PR.AA-01"],               # key rotation
        "AKV-004":   ["PR.AA-01"],               # key expiry
        "AKV-005":   ["PR.AA-01"],               # secret expiry
        "AKV-006":   ["PR.AA-05"],               # RBAC
        "ACR-004":   ["PR.PS-02", "DE.CM-09"],   # defender scan
        "ACR-005":   ["PR.PS-01"],               # tag immutability
        "AZMON-004": ["PR.PS-04", "DE.CM-09"],   # KV diagnostics
        "AZMON-005": ["PR.PS-04"],               # NSG flow retention
        "AZMON-006": ["PR.PS-04"],               # LAW retention
        "AZMON-007": ["DE.CM-09", "RS.MA-01"],   # svc health alert
        "AZNW-001":  ["PR.IR-01"],               # SSH/RDP internet (CRITICAL)
        "AZNW-002":  ["PR.PS-04", "DE.CM-01"],   # flow logs
        "AZNW-003":  ["PR.IR-01"],               # WAF
        "AZNW-004":  ["PR.IR-01"],               # deny-all
        "AZNW-005":  ["PR.IR-01"],               # public IP VM
        "AZAPP-001": ["PR.DS-02"],               # HTTPS
        "AZAPP-002": ["PR.DS-02"],               # TLS
        "AZAPP-003": ["PR.AA-01"],               # managed identity
        "AZAPP-004": ["PR.PS-01"],               # remote debug
        "AZAPP-005": ["PR.PS-01"],               # FTP
        "AZSQL-001": ["PR.DS-01"],               # TDE CMK
        "AZSQL-002": ["PR.PS-04", "DE.CM-09"],   # auditing
        "AZSQL-003": ["PR.IR-01"],               # public access
        "AZSQL-004": ["PR.AA-05"],               # AAD admin
        "AZSQL-005": ["DE.CM-09"],               # threat detect
        "AZVM-001":  ["PR.DS-01"],               # disk encrypt
        "AZVM-002":  ["PR.IR-01"],               # public IP
        "AZVM-003":  ["PR.IR-01"],               # JIT
        "AZVM-004":  ["PR.PS-02"],               # OS patch
        "AZVM-005":  ["PR.AA-01"],               # managed identity
        # ── GCP phase-2 ──────────────────────────────────────────────
        "GCIAM-004": ["PR.AA-05"],               # default SA
        "GCIAM-005": ["PR.AA-05"],               # domain restrict
        "GCIAM-006": ["PR.AA-01"],               # SA key age
        "GCS-004":   ["PR.DS-01"],               # CMEK
        "GCS-005":   ["PR.PS-04", "DE.CM-01"],   # access logging
        "GCLOG-004": ["PR.PS-04", "DE.CM-01"],   # VPC flow logs
        "GCLOG-005": ["PR.PS-04", "DE.CM-01"],   # firewall logging
        "GCLOG-006": ["PR.PS-04", "DE.CM-09"],   # data access
        "GCLOG-007": ["DE.CM-09"],               # metric filter IAM
        "GCLOG-008": ["DE.CM-09"],               # metric filter firewall
        "GCLOG-009": ["DE.CM-09"],               # metric filter route
        "GCLOG-010": ["DE.CM-09"],               # metric filter SQL
        "GCLOG-011": ["DE.CM-09"],               # metric filter custom role
        "GCNET-001": ["PR.IR-01"],               # default network
        "GCNET-002": ["PR.IR-01"],               # deny-all
        "GCNET-003": ["PR.IR-01"],               # SSH/RDP (CRITICAL)
        "GCNET-004": ["PR.IR-01"],               # private access
        "GCNET-005": ["PR.IR-01"],               # Cloud NAT
        "GCCE-001":  ["PR.PS-01"],               # shielded VM
        "GCCE-002":  ["PR.AA-03"],               # OS Login
        "GCCE-003":  ["PR.PS-01"],               # serial port
        "GCCE-004":  ["PR.IR-01"],               # public IP
        "GCCE-005":  ["PR.PS-01"],               # project SSH keys
        "GCSQL-001": ["PR.IR-01"],               # public IP
        "GCSQL-002": ["PR.IR-03"],               # backups
        "GCSQL-003": ["PR.DS-02"],               # SSL
        "GCSQL-004": ["PR.AA-05"],               # IAM auth
        "GCSQL-005": ["PR.IR-03"],               # PITR
        "GCRUN-001": ["PR.IR-01"],               # unauth
        "GCRUN-002": ["PR.AA-05"],               # custom SA
        "GCRUN-003": ["PR.IR-03"],               # min instances
        "GCRUN-004": ["PR.IR-01"],               # VPC connector
        "GCKMS-004": ["PR.AA-05"],               # keyring IAM
        "GCKMS-005": ["PR.DS-01"],               # destroy sched
        "GCKMS-006": ["PR.DS-01"],               # imported key
        # Developer-environment auto-execution
        "DEV-001":   ["PR.PS-05"],
        "DEV-006":   ["PR.PS-05"],
        "DEV-007":   ["PR.PS-05"],   # committed MCP config auto-launches a command server
        "DEV-002":   ["PR.PS-05"],
        "DEV-003":   ["PR.PS-05"],
        "DEV-004":   ["PR.PS-05"],
        "DEV-005":   ["PR.PS-05"],
    },
)
