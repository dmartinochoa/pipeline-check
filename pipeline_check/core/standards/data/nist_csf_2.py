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
        # ── GV.SC. Supply-chain risk management ────────────────────
        "GHA-001":  ["GV.SC-05", "GV.SC-07"],
        "GHA-021":  ["GV.SC-05"],
        "GHA-025":  ["GV.SC-05"],
        "GHA-029":  ["GV.SC-05"],
        "GL-001":   ["GV.SC-05", "GV.SC-07"],
        "GL-005":   ["GV.SC-05"],
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
        "CC-003":   ["GV.SC-05"],
        "CC-021":   ["GV.SC-05"],
        "CC-028":   ["GV.SC-05"],
        "CC-029":   ["GV.SC-05"],
        "GCB-001":  ["GV.SC-05"],
        "CB-009":   ["GV.SC-05"],
        "ECR-006":  ["GV.SC-04", "GV.SC-07"],
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
        "CCM-003":  ["PR.AA-05"],
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
        "GHA-015":  ["PR.PS-01"],
        "GHA-017":  ["PR.PS-01"],
        "GHA-026":  ["PR.PS-01"],
        "GL-014":   ["PR.PS-01"],
        "GL-015":   ["PR.PS-01"],
        "GL-017":   ["PR.PS-01"],
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
        "ECR-002":  ["GV.SC-05", "PR.PS-02"],
        "GHA-020":  ["PR.PS-02"],
        "GL-019":   ["PR.PS-02"],
        "BB-015":   ["PR.PS-02"],
        "ADO-020":  ["PR.PS-02"],
        "JF-020":   ["PR.PS-02"],
        "CC-020":   ["PR.PS-02"],
        "GCB-008":  ["PR.PS-02"],
        "ECR-001":  ["PR.PS-02"],
        "ECR-007":  ["PR.PS-02"],
        # PS-04: log records (co-map with DE.CM-09 monitoring)
        "CB-003":   ["PR.PS-04", "DE.CM-09"],
        "CT-001":   ["PR.PS-04", "DE.CM-09"],
        "CT-002":   ["PR.PS-04", "DE.CM-09", "DE.AE-03"],
        "CT-003":   ["PR.PS-04", "DE.CM-09"],
        "CWL-001":  ["PR.PS-04", "DE.CM-09"],
        "CWL-002":  ["PR.PS-04", "DE.CM-09"],
        "S3-004":   ["PR.PS-04", "DE.CM-01", "DE.AE-03"],
        "JF-011":   ["PR.PS-04"],
        "CC-011":   ["PR.PS-04"],
        # PS-05: prevent unauthorized software execution
        "CB-011":   ["PR.PS-05"],
        "GHA-003":  ["PR.PS-05"],
        "GHA-016":  ["PR.PS-05"],
        "GHA-027":  ["PR.PS-05"],
        "GHA-028":  ["PR.PS-05"],
        "GL-002":   ["PR.PS-05"],
        "GL-016":   ["PR.PS-05"],
        "GL-025":   ["PR.PS-05"],
        "GL-026":   ["PR.PS-05"],
        "BB-002":   ["PR.PS-05"],
        "BB-012":   ["PR.PS-05"],
        "BB-025":   ["PR.PS-05"],
        "BB-026":   ["PR.PS-05"],
        "ADO-002":  ["PR.PS-05"],
        "ADO-016":  ["PR.PS-05"],
        "ADO-026":  ["PR.PS-05"],
        "ADO-027":  ["PR.PS-05"],
        "JF-002":   ["PR.PS-05"],
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

        # ── DE.CM / DE.AE. Monitoring (cross-domain inputs) ────────
        "EB-001":   ["DE.CM-09"],
        "EB-002":   ["DE.CM-06"],
        "CW-001":   ["DE.CM-09"],
        "CB-007":   ["DE.CM-06"],

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
        # ── Dockerfile, image-build supply chain. ─────────────────
        # Pinning + verification rules tie to GV.SC-05 (supply chain
        # requirements established and verified). Privileged / root
        # rules tie to PR.PS-01 (config management practices).
        # Credential rules tie to PR.AA-01 (identity / credential
        # management). Vuln-scan / outdated-dep rules tie to PR.PS-02.
        "DF-001": ["GV.SC-05"],                 # FROM not digest-pinned
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
        "BK-010": ["GV.SC-05"],                 # no SBOM
        "BK-011": ["GV.SC-05"],                 # no SLSA provenance
        "BK-012": ["PR.PS-02", "DE.CM-09"],     # no vuln scan
        "BK-013": ["PR.AA-05"],                 # no branches filter
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
        "SCM-016":  ["RS.MA-01"],               # private vulnerability reporting off
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
        "SCM-026":  ["PR.DS-02", "PR.AA-01"],   # webhook insecure / no HMAC
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
    },
)
