"""NIST SP 800-53 Rev. 5. CI/CD-relevant control subset.

800-53 is the federal security and privacy control catalog. This module
covers the controls whose evidence can be collected from CI/CD state,
spanning the AC (Access Control), AU (Audit & Accountability), CM
(Configuration Management), IA (Identification & Authentication), RA
(Risk Assessment), SA (System & Services Acquisition), SC (System &
Comm Protection), SI (System & Information Integrity), and SR (Supply
Chain Risk Management) families.

Controls for privacy (PT, PM), incident response (IR), personnel
security (PS), physical security (PE), and maintenance (MA) are out of
scope.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="nist_800_53",
    title="NIST SP 800-53 Rev. 5",
    version="Rev. 5",
    url="https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    controls={
        # Access Control
        "AC-2":  "Account Management",
        "AC-3":  "Access Enforcement",
        "AC-6":  "Least Privilege",
        # Audit and Accountability
        "AU-2":  "Event Logging",
        "AU-9":  "Protection of Audit Information",
        "AU-11": "Audit Record Retention",
        "AU-12": "Audit Record Generation",
        # Configuration Management
        "CM-2":  "Baseline Configuration",
        "CM-6":  "Configuration Settings",
        "CM-7":  "Least Functionality",
        "CM-8":  "System Component Inventory",
        # Identification and Authentication
        "IA-5":  "Authenticator Management",
        # Risk Assessment
        "RA-5":  "Vulnerability Monitoring and Scanning",
        # System and Services Acquisition
        "SA-10": "Developer Configuration Management",
        "SA-11": "Developer Testing and Evaluation",
        "SA-15": "Development Process, Standards, and Tools",
        # System and Communications Protection
        "SC-7":  "Boundary Protection",
        "SC-8":  "Transmission Confidentiality and Integrity",
        "SC-12": "Cryptographic Key Establishment and Management",
        "SC-13": "Cryptographic Protection",
        "SC-28": "Protection of Information at Rest",
        # System and Information Integrity
        "SI-2":  "Flaw Remediation",
        "SI-7":  "Software, Firmware, and Information Integrity",
        # Supply Chain Risk Management
        "SR-3":  "Supply Chain Controls and Processes",
        "SR-4":  "Provenance",
        "SR-11": "Component Authenticity",
    },
    mappings={
        # CodeBuild
        "CB-001":   ["IA-5"],                            # plaintext secrets
        "CB-002":   ["CM-6", "CM-7"],                    # privileged mode
        "CB-003":   ["AU-2", "AU-12"],                   # no build logs
        "CB-004":   ["CM-6"],                            # no build timeout
        "CB-005":   ["CM-2", "SI-2", "RA-5"],            # outdated managed image
        "CB-006":   ["IA-5"],                            # long-lived source token
        "CB-007":   ["CM-6", "CM-7"],                    # webhook no filter
        # CodePipeline
        "CP-001":   ["SA-10", "SA-15"],                  # no manual approval
        "CP-002":   ["SC-12", "SC-13", "SC-28", "SI-7", "SR-4"], # artifact store not CMK
        "CP-003":   ["CM-6"],                            # polling source
        "CP-004":   ["IA-5"],                            # OAuth token source
        # CodeDeploy
        "CD-001":   ["SA-10"],                           # no auto rollback
        "CD-002":   ["SA-10"],                           # AllAtOnce
        "CD-003":   ["AU-2", "AU-12"],                   # no CloudWatch alarm
        # ECR
        "ECR-001":  ["RA-5", "SI-2", "SA-11"],           # no scan on push
        "ECR-002":  ["CM-8", "SI-7", "SR-4", "SR-11"],   # mutable tags
        "ECR-003":  ["AC-3", "SC-7", "SR-3"],            # public repo policy
        "ECR-004":  ["CM-2", "CM-8"],                    # no lifecycle
        "ECR-005":  ["SC-12", "SC-13", "SC-28", "SR-4"], # AES256 not CMK
        # IAM
        "IAM-001":  ["AC-3", "AC-6"],
        "IAM-002":  ["AC-3", "AC-6"],
        "IAM-003":  ["AC-2", "AC-6"],
        "IAM-004":  ["AC-3", "AC-6"],
        "IAM-005":  ["AC-2", "AC-3"],                    # sts:ExternalId (confused deputy)
        "IAM-006":  ["AC-3", "AC-6"],
        # PBAC
        "PBAC-001": ["SC-7"],                            # no VPC boundary
        "PBAC-002": ["AC-2", "AC-6"],                    # shared service role
        # S3 artifact bucket
        "S3-001":   ["AC-3", "SC-7", "AU-9"],
        "S3-002":   ["SC-12", "SC-13", "SC-28", "AU-9"],
        "S3-003":   ["SI-7", "AU-9"],
        "S3-004":   ["AU-2", "AU-12"],
        "S3-005":   ["SC-8", "AU-9"],
        # GitHub Actions
        "GHA-001":  ["SR-3", "SR-11", "SI-2", "RA-5"],   # unpinned action
        "GHA-002":  ["CM-6", "SI-7", "SA-11"],           # pull_request_target + PR head
        "GHA-003":  ["CM-6", "SA-11", "SA-15"],          # script injection
        "GHA-004":  ["AC-6", "CM-6", "CM-7"],            # unrestricted GITHUB_TOKEN
        "GHA-005":  ["IA-5"],                            # long-lived AWS keys
        "GHA-034":  ["AC-6", "IA-5"],                    # secrets: inherit
        "GHA-035":  ["CM-6", "SI-7", "SA-11"],           # github-script injection
        # GitLab CI
        "GL-001":   ["SR-3", "SR-11", "SI-2"],
        "GL-002":   ["SI-7", "SA-11", "CM-6"],
        "GL-003":   ["IA-5"],
        "GL-004":   ["SA-10", "AC-3"],
        "GL-005":   ["SR-3", "SR-11", "CM-6"],
        # Bitbucket Pipelines
        "BB-001":   ["SR-3", "SR-11", "SI-2"],
        "BB-002":   ["SI-7", "SA-11", "CM-6"],
        "BB-003":   ["IA-5"],
        "BB-004":   ["SA-10", "AC-3"],
        "BB-005":   ["CM-6"],
        "BB-029":   ["SR-3", "SR-11", "SI-2"],           # step+service image pinning
        # Azure DevOps Pipelines
        "ADO-001":  ["SR-3", "SR-11", "SI-2"],
        "ADO-002":  ["SI-7", "SA-11", "CM-6"],
        "ADO-003":  ["IA-5"],
        "ADO-004":  ["SA-10", "AC-3"],
        "ADO-005":  ["SR-3", "SR-11", "CM-2"],
        # CircleCI
        "CC-001":   ["SR-3", "SR-11", "SI-2", "RA-5"],  # orb not pinned to SHA
        "CC-002":   ["CM-6", "SA-11", "SA-15"],          # script injection
        "CC-003":   ["SR-3", "SR-11", "SI-2", "RA-5"],  # image not pinned to digest
        "CC-004":   ["IA-5"],                            # unrestricted context
        "CC-005":   ["IA-5"],                            # long-lived AWS keys
        "CC-006":   ["SI-7", "SR-4"],                    # unsigned artifacts
        "CC-007":   ["CM-8", "SR-4"],                    # no SBOM / provenance
        "CC-008":   ["IA-5"],                            # literal secrets in config
        "CC-009":   ["SA-10", "SA-15"],                  # no deployment approval
        "CC-010":   ["CM-6", "CM-7"],                    # self-hosted runner
        "CC-011":   ["AU-2", "AU-12"],                   # no build retention
        "CC-012":   ["CM-6", "SA-11", "SA-15"],          # setup / dynamic config
        "CC-013":   ["SA-10"],                           # no branch filter
        "CC-014":   ["AC-6", "CM-6"],                    # resource class isolation
        "CC-015":   ["CM-6"],                            # no timeout
        "CC-016":   ["SR-3", "SR-11"],                   # curl | bash
        "CC-017":   ["CM-6", "CM-7"],                    # insecure Docker config
        "CC-018":   ["SR-3", "SR-11"],                   # insecure package source
        "CC-019":   ["IA-5"],                            # SSH key in config
        "CC-020":   ["RA-5", "SI-2"],                    # no vulnerability scanning
        "CC-021":   ["SR-3", "SR-11"],                   # no lockfile
        "CC-022":   ["SI-2", "SR-3"],                    # no dependency updates
        "CC-023":   ["SC-8"],                            # TLS verification bypass
        # Jenkins
        "JF-001":   ["SR-3", "SR-11"],                   # tools / agents not pinned
        "JF-004":   ["IA-5"],                            # plaintext credentials in Jenkinsfile
        "JF-008":   ["IA-5"],                            # literal secrets in Groovy
        "JF-010":   ["IA-5"],                            # long-lived AWS keys
        "JF-011":   ["AU-2", "AU-12"],                   # build log retention
        "JF-015":   ["CM-6"],                            # no timeout
        "JF-033":   ["IA-5", "AU-9"],                    # withCredentials leaked via Groovy ${}
        "JF-034":   ["IA-5", "SC-28"],                   # password() build parameter
        "JF-035":   ["SC-8", "SC-13"],                   # httpRequest ignoreSslErrors
        # Cloud Build
        "GCB-001":  ["SR-3", "SR-11", "SI-2", "RA-5"],   # step image not digest-pinned
        "GCB-002":  ["AC-3", "AC-6"],                    # default service account
        "GCB-003":  ["IA-5"],                            # secrets fetched in args
        "GCB-005":  ["CM-6"],                            # no timeout
        "GCB-006":  ["CM-6", "SA-11"],                   # shell-eval idiom
        "GCB-007":  ["CM-2", "SR-4"],                    # rolling 'latest' secret version
        "GCB-008":  ["RA-5", "SI-2", "SA-11"],           # no vuln scanning
        "GCB-009":  ["SI-7", "SR-4"],                    # unsigned artifact
        "GCB-010":  ["SR-3", "SR-11"],                   # remote script via curl-pipe
        "GCB-011":  ["SC-8"],                            # TLS bypass
        "GCB-012":  ["IA-5"],                            # literal secret in YAML
        "GCB-013":  ["SR-3", "SR-11"],                   # package source integrity
        "GCB-014":  ["AU-2", "AU-12", "AU-9"],           # logging disabled
        "GCB-015":  ["SR-4", "CM-8"],                    # no SBOM
        "GCB-016":  ["CM-6", "AC-6"],                    # dir path escape
        "GCB-017":  ["SR-4", "SI-7", "CM-2"],            # no SLSA provenance
        "GCB-018":  ["IA-5", "CM-2"],                    # legacy KMS secrets block
        "GCB-019":  ["CM-6", "SA-11"],                   # shell entrypoint + user substitution
        "GCB-020":  ["AC-3", "AC-6"],                    # default Cloud Build SA email
        "GCB-021":  ["SC-7"],                            # no private worker pool
        "GCB-022":  ["CM-6", "SA-11"],                   # substitutionOption ALLOW_LOOSE
        "GCB-023":  ["CM-6", "SA-11"],                   # undeclared user substitution
        "GCB-024":  ["SR-4", "CM-8"],                    # images: missing
        "GCB-025":  ["AU-2", "SI-2"],                    # tags: empty
        "GCB-026":  ["CM-6"],                            # waitFor unknown id
        # Kubernetes, runtime configuration evidences SC-7 (boundary
        # protection), CM-6/CM-7 (least functionality), AC-3/AC-6
        # (least privilege), AU-2/AU-12 (audit), SC-28 (data at rest).
        "K8S-001":  ["SR-3", "SR-11", "SI-2"],           # image not digest-pinned
        "K8S-002":  ["SC-7", "CM-7"],                    # hostNetwork: true
        "K8S-003":  ["SC-7", "CM-7"],                    # hostPID: true
        "K8S-004":  ["SC-7", "CM-7"],                    # hostIPC: true
        "K8S-005":  ["AC-6", "CM-6", "CM-7"],            # privileged container
        "K8S-006":  ["AC-6", "CM-6"],                    # allowPrivilegeEscalation
        "K8S-007":  ["AC-6", "CM-6"],                    # runAsNonRoot
        "K8S-008":  ["SC-28", "CM-6"],                   # readOnlyRootFilesystem
        "K8S-009":  ["AC-6", "CM-7"],                    # capabilities
        "K8S-010":  ["CM-6", "SI-7"],                    # seccompProfile missing
        "K8S-011":  ["AC-2", "AC-6"],                    # default service account
        "K8S-012":  ["AC-6", "CM-7"],                    # automountServiceAccountToken
        "K8S-013":  ["SC-7", "AC-6", "SI-7"],            # hostPath volumes
        "K8S-014":  ["SC-7", "AC-6", "SI-7"],            # sensitive hostPath
        "K8S-015":  ["CM-6"],                            # no memory limit
        "K8S-016":  ["CM-6"],                            # no CPU limit
        "K8S-017":  ["IA-5"],                            # credential literals in env
        "K8S-018":  ["IA-5", "SC-28"],                   # Secret carries plaintext
        "K8S-019":  ["CM-6"],                            # default namespace
        "K8S-020":  ["AC-3", "AC-6"],                    # cluster-admin binding
        "K8S-021":  ["AC-3", "AC-6", "CM-7"],            # wildcard RBAC
        "K8S-022":  ["SC-7", "CM-7"],                    # service exposes SSH
        "K8S-023":  ["AC-6", "CM-6"],                    # PSA enforce label missing
        "K8S-024":  ["AU-2", "SI-2"],                    # missing health probes
        "K8S-025":  ["AC-6", "CM-7"],                    # system-* priority class
        "K8S-026":  ["SC-7", "AC-3"],                    # LB without source ranges
        "K8S-027":  ["SC-8", "SC-13"],                   # Ingress without TLS
        "K8S-028":  ["SC-7", "CM-7"],                    # container hostPort
        "K8S-029":  ["AC-3", "AC-6"],                    # default-SA binding
        "K8S-030":  ["AC-6", "SC-7", "CM-7"],            # control-plane scheduling
        "K8S-031":  ["CM-6", "AC-6"],                    # PSA warn missing
        "K8S-032":  ["SC-7", "AC-3"],                    # NetworkPolicy default-deny missing
        "K8S-033":  ["CM-6", "SI-2"],                    # ResourceQuota / LimitRange missing
        "K8S-034":  ["AC-6", "AC-2"],                    # ServiceAccount automount default
        "K8S-035":  ["AC-6", "CM-6"],                    # runAsUser: 0
        "K8S-036":  ["SR-3", "SR-11", "SI-7"],           # SA imagePullSecret missing
        "K8S-037":  ["IA-5", "SC-28"],                   # ConfigMap credential literal
        "K8S-038":  ["SC-7", "AC-3"],                    # NetworkPolicy allow-all
        "K8S-039":  ["AC-6", "CM-6"],                    # shareProcessNamespace
        "K8S-040":  ["AC-6", "CM-6"],                    # procMount: Unmasked
        "K8S-041":  ["SC-7", "AC-3"],                    # Service externalIPs (CVE-2020-8554)
        "K8S-042":  ["AC-2", "AC-3", "AC-6"],            # anonymous RoleBinding
        "K8S-043":  ["SC-7", "CM-6"],                    # Ingress wildcard host
        # Helm chart-supply-chain. The same SR family that covers
        # image pinning (K8S-001 / DF-001) covers chart pinning;
        # SC-8 (transmission integrity) covers HELM-003's plaintext
        # repo URL. SR-3, supply chain controls. SR-11, component
        # authenticity (the Chart.lock digest is the authenticity
        # signal). SI-2, flaw remediation hooks on the schema lock.
        "HELM-001": ["SR-3", "CM-2"],                    # legacy v1 schema
        "HELM-002": ["SR-3", "SR-11", "SI-7"],           # Chart.lock digest
        "HELM-003": ["SR-3", "SC-8", "SC-13"],           # non-HTTPS dep repo
        "HELM-004": ["SR-3", "SR-11", "SI-2"],           # version not exact-pinned
        "HELM-005": ["SR-3", "SR-4"],                    # maintainers chain-of-custody
        "HELM-006": ["CM-2", "CM-6"],                    # kubeVersion compat range
        "HELM-007": ["SR-3"],                            # description (chain-of-custody)
        "HELM-008": ["SR-3", "SI-2"],                    # Chart.lock stale (flaw remediation cadence)
        "HELM-009": ["SR-3", "SC-8"],                    # home / sources non-HTTPS
        "HELM-010": ["CM-2"],                            # appVersion (config baseline)
        # Buildkite, pipeline-config posture maps to the same SR /
        # CM / IA families as the other CI providers' rules.
        "BK-001":   ["SR-3", "SR-11", "SI-2"],           # plugin not pinned
        "BK-002":   ["IA-5", "SC-28"],                   # secret in env
        "BK-003":   ["CM-6", "SA-11"],                   # untrusted variable injection
        "BK-004":   ["SR-3", "SR-11", "SI-7"],           # curl | bash
        "BK-005":   ["AC-6", "CM-7"],                    # Docker privileged
        "BK-006":   ["AU-2", "SI-2"],                    # no timeout
        "BK-007":   ["AC-3", "SA-10"],                   # deploy not gated
        "BK-008":   ["SC-8", "SC-13"],                   # TLS bypass
        "BK-009":   ["SI-7", "SR-4"],                    # artifacts not signed
        "BK-010":   ["SR-4", "CM-8"],                    # no SBOM
        "BK-011":   ["SI-7", "SR-4", "CM-2"],            # no SLSA provenance
        "BK-012":   ["RA-5", "SI-2"],                    # no vuln scanning
        "BK-013":   ["AC-3"],                            # deploy without branch filter
        # Tekton. Kubernetes-native pipeline kinds.
        "TKN-001":  ["SR-3", "SR-11", "SI-2"],           # step image not digest-pinned
        "TKN-002":  ["AC-6", "CM-7"],                    # step privileged
        "TKN-003":  ["CM-6", "SA-11"],                   # param injection
        "TKN-004":  ["SC-7", "AC-6", "SI-7"],            # hostPath / host namespaces
        "TKN-005":  ["IA-5", "SC-28"],                   # leaked creds
        "TKN-006":  ["AU-2", "SI-2"],                    # no timeout
        "TKN-007":  ["AC-2", "AC-6"],                    # default ServiceAccount
        "TKN-008":  ["SR-3", "SR-11", "SC-8", "SI-7"],   # remote install / TLS
        "TKN-009":  ["SI-7", "SR-4"],                    # artifacts not signed
        "TKN-010":  ["SR-4", "CM-8"],                    # no SBOM
        "TKN-011":  ["SI-7", "SR-4", "CM-2"],            # no SLSA provenance
        "TKN-012":  ["RA-5", "SI-2"],                    # no vuln scanning
        "TKN-013":  ["AC-6", "CM-7"],                    # sidecar privileged
        # Argo Workflows
        "ARGO-001": ["SR-3", "SR-11", "SI-2"],           # template image not pinned
        "ARGO-002": ["AC-6", "CM-7"],                    # template privileged
        "ARGO-003": ["AC-2", "AC-6"],                    # default SA
        "ARGO-004": ["SC-7", "AC-6", "SI-7"],            # hostPath / namespaces
        "ARGO-005": ["CM-6", "SA-11"],                   # parameter injection
        "ARGO-006": ["IA-5", "SC-28"],                   # leaked creds
        "ARGO-007": ["AU-2", "SI-2"],                    # no activeDeadlineSeconds
        "ARGO-008": ["SR-3", "SR-11", "SC-8", "SI-7"],   # remote install / TLS
        "ARGO-009": ["SI-7", "SR-4"],                    # artifacts not signed
        "ARGO-010": ["SR-4", "CM-8"],                    # no SBOM
        "ARGO-011": ["SI-7", "SR-4", "CM-2"],            # no SLSA provenance
        "ARGO-012": ["RA-5", "SI-2"],                    # no vuln scanning
        "ARGO-013": ["AC-6", "IA-5"],                    # SA token automount
        # Dockerfile, image build choices evidence supply-chain (SR)
        # and configuration (CM) controls primarily.
        "DF-001":   ["SR-3", "SR-11", "SI-2"],           # FROM not digest-pinned
        "DF-002":   ["AC-6", "CM-6"],                    # no USER
        "DF-003":   ["SR-3", "SR-11", "SI-7"],           # ADD URL no checksum
        "DF-004":   ["SR-3", "SR-11", "SI-7"],           # curl-pipe
        "DF-005":   ["CM-6", "SA-11"],                   # shell-eval
        "DF-006":   ["IA-5"],                            # secret in ENV/ARG
        "DF-007":   ["SI-2", "AU-2"],                    # no HEALTHCHECK
        "DF-008":   ["AC-6", "CM-7"],                    # privileged in RUN
        "DF-009":   ["CM-6"],                            # ADD where COPY suffices
        "DF-010":   ["CM-2", "SR-3", "SI-2"],            # apt dist-upgrade
        "DF-011":   ["CM-6"],                            # apt cache not cleaned
        "DF-012":   ["AC-6", "CM-6"],                    # sudo in RUN
        "DF-013":   ["SC-7", "CM-7"],                    # EXPOSE 22
        "DF-014":   ["CM-6", "AC-6"],                    # WORKDIR system path
        "DF-015":   ["AC-6", "CM-6"],                    # chmod 777
        "DF-016":   ["SR-4", "CM-8"],                    # OCI provenance labels
        "DF-017":   ["AC-6", "CM-6"],                    # ENV PATH writable prefix
        "DF-018":   ["AC-6", "CM-6"],                    # RUN chown system path
        "DF-019":   ["IA-5", "SC-28"],                   # COPY/ADD credential-shaped file
        "DF-020":   ["IA-5", "AU-2"],                    # ARG credential-shaped name
        "DF-021":   ["SC-8", "SC-13", "SR-3"],           # pip install TLS bypass / http index
        "DF-022":   ["SR-3", "SR-11", "CM-2"],           # npm install (no lockfile enforcement)
        "DF-023":   ["CM-6", "AC-6"],                    # ENV LD_PRELOAD / LD_LIBRARY_PATH
        # Additional AWS services not previously mapped.
        "KMS-001":  ["SC-12", "SC-13"],                  # CMK rotation disabled
        "KMS-002":  ["AC-3", "AC-6"],                    # CMK policy wildcard
        "CT-001":   ["AU-2", "AU-12", "AU-9"],           # no trail
        "CT-002":   ["AU-9", "SI-7"],                    # log file validation off
        "CT-003":   ["AU-2", "AU-12"],                   # not multi-region
        "CWL-001":  ["AU-2", "AU-11"],                   # no log retention
        "CWL-002":  ["AU-9", "SC-12", "SC-28"],          # logs not KMS-encrypted
        "CW-001":   ["AU-2", "SI-2"],                    # failed-build alarm
        "SM-001":   ["IA-5", "SC-12"],                   # secret rotation off
        "SM-002":   ["AC-3", "SC-7"],                    # secret resource policy public
        "SSM-001":  ["IA-5"],                            # SSM string not SecureString
        "SSM-002":  ["SC-12", "SC-13"],                  # SSM default KMS key
        "SIGN-001": ["SI-7", "SR-4"],                    # signing profile missing
        "SIGN-002": ["SI-7", "SR-4"],                    # signing profile revoked
        "LMB-001":  ["SI-7", "SR-4"],                    # Lambda code-signing config
        "LMB-002":  ["AC-3"],                            # function URL no auth
        "LMB-003":  ["IA-5"],                            # Lambda env plaintext secret
        "LMB-004":  ["AC-3", "SC-7"],                    # Lambda resource policy public
        "EB-001":   ["AU-2", "SI-2"],                    # no pipeline-failure rule
        "EB-002":   ["AC-6"],                            # wildcard event target
        "CCM-001":  ["SA-10", "AC-3"],                   # CodeCommit approval rules
        "CCM-002":  ["SC-12", "SC-28"],                  # CodeCommit repo not KMS
        "CCM-003":  ["AC-3", "SC-7"],                    # cross-account trigger
        "CA-001":   ["SC-12", "SC-13"],                  # CodeArtifact domain encryption
        "CA-002":   ["SR-3", "SR-11"],                   # public upstream repo
        "CA-003":   ["AC-3", "SC-7"],                    # domain policy public
        "CA-004":   ["AC-6"],                            # repo wildcard actions
        # ── SCM posture (governance via the platform REST API) ──────
        # Branch protection / review controls map primarily to SA-15
        # (Development Process, Standards, and Tools) — the developer-
        # side governance regime — supplemented by AC-3 / AC-6 for
        # access enforcement, SI-7 for history-integrity surfaces,
        # and IA-5 for credential-shaped surfaces (workflow tokens,
        # deploy keys). AU-9 (audit-log tamper protection) is not used
        # here: git-history rewrite is not an audit log.
        "SCM-001":  ["SA-15", "AC-3"],                  # default branch unprotected
        "SCM-002":  ["SA-15"],                          # required reviews missing
        "SCM-003":  ["SA-11"],                          # default code scanning disabled (SAST)
        "SCM-004":  ["SI-7", "IA-5"],                   # secret scanning disabled
        "SCM-005":  ["RA-5", "SI-2"],                   # Dependabot security updates off
        "SCM-006":  ["SI-7", "SR-4"],                   # signed commits not required (provenance)
        "SCM-007":  ["SI-7"],                           # force-push allowed (history rewrite)
        "SCM-008":  ["SA-15", "SA-11"],                 # required status checks missing
        "SCM-009":  ["SI-7"],                           # branch deletions allowed
        "SCM-010":  ["AC-6", "SA-15"],                  # admin bypass allowed
        "SCM-011":  ["SA-15", "AC-3"],                  # CODEOWNERS reviews not required
        "SCM-012":  ["SA-15"],                          # stale reviews not dismissed
        "SCM-013":  ["SA-15"],                          # conversation resolution not required
        "SCM-014":  ["SA-15"],                          # last-push approval not required
        "SCM-015":  ["SI-7", "IA-5"],                   # secret scanning push protection off
        # SCM-016 (private vulnerability reporting) is an incident-
        # response surface; 800-53's IR family isn't currently in
        # this standard's catalog. Left unmapped.
        "SCM-017":  ["SA-15"],                          # CODEOWNERS file missing
        "SCM-018":  ["SA-15", "AC-6"],                  # PR review bypass allowed
        "SCM-019":  ["AC-3", "AC-6"],                   # push-restriction allowlist names users
        # Actions governance + environments + deploy keys
        "SCM-020":  ["AC-6", "IA-5"],                   # workflow_token default write
        "SCM-021":  ["AC-3", "SA-15"],                  # Actions can approve PRs (self-approval)
        "SCM-022":  ["SR-3", "SR-11", "CM-7"],          # allowed_actions unrestricted
        "SCM-023":  ["SA-10", "AC-3"],                  # env missing reviewers
        "SCM-024":  ["CM-6", "SA-10"],                  # env branch policy missing
        "SCM-025":  ["IA-5", "AC-6"],                   # deploy keys write-enabled
        "SCM-026":  ["SC-8", "IA-5"],                   # webhook insecure transport / no HMAC
        "SCM-027":  ["AC-2", "AC-6"],                   # outside collaborator elevated
        "SCM-028":  ["AC-3"],                           # private repo allows forking
        # Ruleset enforcement (modern variant of branch protection)
        "SCM-029":  ["SA-15", "CM-6"],                  # ruleset not enforced
        "SCM-030":  ["AC-6", "SA-15"],                  # ruleset always-bypass
        "SCM-031":  ["SA-15"],                          # auto-merge enabled
        "SCM-032":  ["SA-15"],                          # ruleset lacks PR review
        "SCM-033":  ["SA-11", "SA-15"],                 # ruleset lacks status_checks
        "SCM-034":  ["SI-7"],                           # ruleset allows force_push
        "SCM-035":  ["SI-7"],                           # ruleset allows deletion
        "SCM-036":  ["SI-7", "SR-4"],                   # ruleset lacks signed_commits
        "SCM-037":  ["SA-15"],                          # ruleset stale-review dismissal
        "SCM-038":  ["SA-15"],                          # ruleset lacks linear_history (audit hygiene, not info-integrity)
        "SCM-039":  ["SA-11", "SA-15"],                 # ruleset lacks required_workflows
        "SCM-040":  ["SA-11", "RA-5"],                  # ruleset lacks code_scanning gate
        "SCM-041":  ["SA-10", "SA-15"],                 # ruleset lacks deployment-env gate
        "SCM-042":  ["SA-11", "SA-15"],                 # ruleset lacks merge queue (post-merge re-test)
    },
)
