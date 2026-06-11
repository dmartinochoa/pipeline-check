"""PCI DSS v4.0, subset covering CI/CD-relevant requirements.

Only requirements whose evidence can be collected from CI/CD
configuration state are mapped here. Requirements about network
segmentation, physical security, cryptographic key management
lifecycles, and cardholder data handling are out of scope.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="pci_dss_v4",
    title="PCI DSS v4.0",
    version="4.0",
    url="https://www.pcisecuritystandards.org/document_library/",
    controls={
        # Req 6, develop and maintain secure systems and software
        "6.3.1": "Security vulnerabilities are identified and managed",
        "6.3.3": "All system components protected from known vulnerabilities by installing applicable patches",
        "6.4.1": "Public-facing web apps are protected against attacks (secure build/config)",
        "6.4.3": "Changes to systems are managed via documented change control",
        "6.5.1": "Changes to system components follow secure development procedures",
        # Req 7, restrict access by business need to know
        "7.2.1": "Access control is defined per job role with least privilege",
        "7.2.2": "Access is assigned based on job classification and function",
        "7.2.5": "System and application accounts have least-privilege access",
        # Req 8, identify users and authenticate access
        "8.2.1": "Strong unique identifiers are assigned to each user and service account",
        "8.2.2": "Group, shared, or generic accounts are managed and justified",
        # Req 10, log and monitor all access to system components
        "10.2.1": "Audit logs are enabled and active for all system components",
        "10.3.2": "Audit logs are protected from unauthorized modifications",
        "10.3.3": "Audit logs are promptly backed up to a centralized log server",
    },
    mappings={
        # CodeBuild
        "CB-001":   ["6.5.1", "8.2.1"],                  # plaintext secrets
        "CB-002":   ["6.4.1", "6.5.1"],                  # privileged mode
        "CB-003":   ["10.2.1"],                          # build logging disabled
        "CB-004":   ["6.4.1"],                           # no build timeout
        "CB-005":   ["6.3.3"],                           # outdated managed image
        "CB-006":   ["8.2.1"],                           # long-lived source token
        "CB-007":   ["6.4.1"],                           # webhook no filter
        # CodePipeline
        "CP-001":   ["6.4.3", "6.5.1"],                  # no manual approval
        "CP-002":   ["6.5.1", "10.3.2"],                 # artifact store not CMK-encrypted
        "CP-003":   ["6.4.1"],                           # polling source
        "CP-004":   ["8.2.1"],                           # OAuth-token source
        # CodeDeploy
        "CD-001":   ["6.4.3"],                           # no auto rollback
        "CD-002":   ["6.4.3"],                           # AllAtOnce deployment
        "CD-003":   ["10.2.1"],                          # no CloudWatch alarm
        # ECR
        "ECR-001":  ["6.3.1", "6.3.3"],                  # no image scan on push
        "ECR-002":  ["6.5.1", "10.3.2"],                 # mutable tags
        "ECR-003":  ["7.2.5"],                           # public repo policy
        "ECR-004":  ["6.5.1"],                           # no lifecycle policy
        "ECR-005":  ["10.3.2"],                          # AES256 not CMK
        "ECR-006":  ["6.3.3"],                           # pull-through cache untrusted upstream
        "ECR-007":  ["6.3.1"],                           # Inspector v2 enhanced scanning disabled
        # CodeArtifact, CodeCommit (registry + source posture)
        "CA-001":   ["10.3.2"],                          # CodeArtifact domain no CMK
        "CA-002":   ["7.2.5"],                           # public external connection
        "CA-003":   ["7.2.5"],                           # domain policy cross-account wildcard
        "CA-004":   ["7.2.5"],                           # repo policy wildcard codeartifact:*
        "CCM-001":  ["6.4.3", "7.2.2"],                  # no approval rule template = no job-classification gate
        "CCM-002":  ["10.3.2"],                          # CodeCommit no CMK
        "CCM-003":  ["7.2.5"],                           # cross-account trigger sink
        # KMS / Secrets Manager / SSM (key + secret posture)
        "KMS-002":  ["7.2.5"],                           # KMS policy wildcard actions
        "SM-001":   ["8.2.1"],                           # Secrets Manager no rotation
        "SM-002":   ["7.2.5"],                           # Secrets Manager resource policy wildcard
        "SSM-001":  ["8.2.1"],                           # SSM secret-named String (not SecureString)
        "SSM-002":  ["10.3.2"],                          # SSM SecureString uses AWS-managed key
        # Lambda + AWS Signer (deployment artifact signing)
        "LMB-001":  ["6.5.1"],                           # no code-signing config
        "LMB-002":  ["7.2.5"],                           # function URL AuthType=NONE
        "LMB-004":  ["7.2.5"],                           # resource policy wildcard principal
        "SIGN-001": ["6.5.1"],                           # no AWS Signer profile
        "SIGN-002": ["6.5.1"],                           # Signer profile revoked / inactive
        # CloudTrail + CloudWatch Logs + alarms + EventBridge (audit + monitoring)
        "CT-001":   ["10.2.1", "10.3.3"],                # no active trail = nothing centrally logged
        "CT-002":   ["10.2.1", "10.3.2"],                # log-file validation off
        "CT-003":   ["10.2.1", "10.3.3"],                # single-region trail = not centralized
        "CWL-001":  ["10.2.1", "10.3.3"],                # log group no retention
        "CWL-002":  ["10.3.2"],                          # log group not KMS-encrypted
        "CW-001":   ["10.2.1"],                          # no FailedBuilds alarm
        "EB-001":   ["10.2.1"],                          # no EventBridge rule for pipeline failure
        "EB-002":   ["7.2.5"],                           # EventBridge wildcard target ARN
        # IAM
        "IAM-001":  ["7.2.1", "7.2.5"],
        "IAM-002":  ["7.2.1", "7.2.5"],
        "IAM-003":  ["7.2.5"],
        "IAM-004":  ["7.2.5"],
        "IAM-005":  ["7.2.1"],                           # sts:ExternalId confused-deputy
        "IAM-006":  ["7.2.5"],
        "IAM-007":  ["8.2.1"],                           # access key > 90 days
        "IAM-008":  ["7.2.1", "8.2.1"],                  # OIDC trust no aud/sub pin
        "IAM-009":  ["7.2.1", "8.2.1"],                  # Azure WIF broad subject
        "IAM-010":  ["7.2.1", "8.2.1"],                  # GCP WIF no repo condition
        # PBAC
        "PBAC-001": ["6.4.1"],                           # no VPC boundary
        "PBAC-002": ["7.2.2", "7.2.5", "8.2.2"],         # shared role = no per-classification access
        "PBAC-003": ["6.4.1"],                           # SG 0.0.0.0/0 egress
        "PBAC-005": ["7.2.5", "8.2.2"],                  # pipeline stage role reuse
        # S3 artifact bucket
        "S3-001":   ["10.3.2"],
        "S3-002":   ["10.3.2"],
        "S3-003":   ["10.3.2"],
        "S3-004":   ["10.2.1", "10.3.3"],
        "S3-005":   ["10.3.2"],
        # GitHub Actions
        "GHA-001":  ["6.3.3"],                           # unpinned action
        "GHA-110": ["6.3.1"],  # CI env disables Go module verification
        "GHA-002":  ["6.5.1"],                           # pull_request_target + PR head
        "RUN-001":  ["6.5.1"],                           # forensics: fork PR ran on privileged trigger
        "RUN-002":  ["6.5.1"],                           # forensics: privileged trigger fired
        "GLRUN-001": ["6.5.1"],  # gitlab forensics: merge-request pipeline executed
        "GLRUN-002": ["6.5.1"],  # gitlab forensics: fork merge-request pipeline executed
        "GLRUN-003": ["6.5.1"],  # gitlab forensics: secret leaked in fork pipeline trace
        "GLRUN-004": ["6.5.1"],  # gitlab forensics: fork pipeline minted a cloud OIDC token
        "GLRUN-005": ["6.5.1"],  # gitlab forensics: fork pipeline ran on a self-managed runner
        "RUN-003":  ["6.5.1"],                           # forensics: secret leaked in run logs
        "RUN-004":  ["6.5.1"],                           # forensics: fork run minted a cloud OIDC token
        "RUN-005":  ["6.5.1"],                           # forensics: fork run on a self-hosted runner
        "RUN-006":  ["6.3.1", "6.3.3"],                           # forensics: known-compromised action executed
        "RUN-007":  ["6.3.1", "6.3.3"],                           # forensics: unpinned third-party action ran
        "GHA-003":  ["6.5.1"],                           # script injection
        "GHA-119":  ["6.5.1"],                           # untrusted context into an agentic AI CLI
        "GHA-120":  ["6.5.1"],                           # trust_remote_code model load = code exec
        "GHA-122":  ["6.5.1"],                           # unsafe pickle deser of fetched artifact = code exec
        "GHA-117":  ["6.5.1"],                           # IaC apply on untrusted PR trigger
        "GHA-118":  ["6.5.1"],                           # untrusted content into $GITHUB_ENV / $GITHUB_PATH
        "GHA-004":  ["7.2.5"],                           # unrestricted GITHUB_TOKEN
        "GHA-005":  ["8.2.1"],                           # long-lived AWS keys
        # GitLab CI
        "GL-001":   ["6.3.3"],
        "GL-037": ["6.3.1"],  # CI env disables Go module verification
        "GL-002":   ["6.5.1"],
        "GL-045":   ["6.5.1"],   # trust_remote_code model load = code exec
        "GL-047":   ["6.5.1"],   # unsafe pickle deser of fetched artifact = code exec
        "GL-048":   ["6.5.1"],   # untrusted MR context into agentic CLI = prompt injection
        "GL-049":   ["6.4.3"],   # agentic CLI output lands without review
        "GL-003":   ["8.2.1", "6.5.1"],
        "GL-004":   ["6.4.3"],
        "GL-044":   ["6.4.3"],
        "GL-005":   ["6.3.3"],
        "GL-042":   ["6.3.3"],    # include: component unpinned
        # Bitbucket Pipelines
        "BB-001":   ["6.3.3"],
        "BB-002":   ["6.5.1"],
        "BB-035":   ["6.5.1"],   # trust_remote_code model load = code exec
        "BB-036":   ["6.5.1"],   # untrusted PR context into agentic CLI = prompt injection
        "BB-037":   ["6.5.1"],   # unsafe pickle deser of fetched artifact = code exec
        "BB-039":   ["6.4.3"],   # agentic CLI output lands without review
        "JF-038":   ["6.4.3"],   # agentic CLI output lands without review
        "BB-003":   ["8.2.1", "6.5.1"],
        "BB-004":   ["6.4.3"],
        "BB-034":   ["6.4.3"],
        "BB-033":   ["6.5.1"],                           # IaC apply on a PR pipeline
        "ADO-033":  ["6.5.1"],                           # IaC apply on a PR-validated pipeline
        "BK-016":   ["6.5.1"],                           # dangerous shell idiom
        "JF-036":   ["6.5.1"],                           # shell step interpolates params.*
        "BB-005":   ["6.4.1"],
        # Azure DevOps Pipelines
        "ADO-001":  ["6.3.3"],
        "ADO-002":  ["6.5.1"],
        "ADO-034":  ["6.5.1"],   # trust_remote_code model load = code exec
        "ADO-035":  ["6.5.1"],   # untrusted PR context into agentic CLI = prompt injection
        "ADO-036":  ["6.5.1"],   # unsafe pickle deser of fetched artifact = code exec
        "ADO-038":  ["6.4.3"],   # agentic CLI output lands without review
        "ADO-003":  ["8.2.1", "6.5.1"],
        "ADO-004":  ["6.4.3"],
        "ADO-005":  ["6.3.3"],
        # CircleCI
        "CC-001":   ["6.3.3"],                           # orb not pinned to SHA
        "CC-033": ["6.3.1"],  # CI env disables Go module verification
        "CC-002":   ["6.5.1"],                           # script injection
        "CC-003":   ["6.3.3"],                           # image not pinned to digest
        "CC-004":   ["8.2.1", "6.5.1"],                  # unrestricted context
        "CC-005":   ["8.2.1"],                           # long-lived AWS keys
        "CC-006":   ["6.5.1", "10.3.2"],                 # unsigned artifacts
        "CC-007":   ["6.5.1"],                           # no SBOM / provenance
        "CC-008":   ["8.2.1", "6.5.1"],                  # literal secrets in config
        "CC-009":   ["6.4.3"],                           # no deployment approval
        "CC-010":   ["6.4.1"],                           # self-hosted runner
        "CC-011":   ["10.2.1"],                          # no build retention
        "CC-012":   ["6.5.1"],                           # setup / dynamic config
        "CC-013":   ["6.4.3"],                           # no branch filter
        "CC-014":   ["7.2.5"],                           # resource class isolation
        "CC-015":   ["6.4.1"],                           # no timeout
        "CC-016":   ["6.3.3"],                           # curl | bash
        "CC-017":   ["6.4.1"],                           # insecure Docker config
        "CC-018":   ["6.3.3"],                           # insecure package source
        "CC-019":   ["8.2.1"],                           # SSH key in config
        "CC-020":   ["6.3.1", "6.3.3"],                  # no vulnerability scanning
        "CC-021":   ["6.3.3"],                           # no lockfile
        "CC-022":   ["6.3.3"],                           # no dependency updates
        "CC-023":   ["6.5.1"],                           # TLS verification bypass
        # Buildkite, pipeline-config posture maps to the same Req-6 /
        # Req-7 / Req-8 / Req-10 families as the other CI providers.
        "BK-001":   ["6.3.3"],                           # plugin not pinned
        "BK-002":   ["8.2.1", "6.5.1"],                  # literal secret
        "BK-003":   ["6.5.1"],                           # untrusted interpolation
        "BK-004":   ["6.3.3"],                           # curl | bash
        "BK-005":   ["6.4.1", "6.5.1"],                  # docker --privileged
        "BK-006":   ["6.4.1"],                           # no timeout
        "BK-007":   ["6.4.3"],                           # deploy step not gated
        "BK-008":   ["6.5.1"],                           # TLS verification bypass
        "BK-009":   ["6.5.1", "10.3.2"],                 # artifacts not signed
        "BK-010":   ["6.5.1"],                           # no SBOM
        "BK-011":   ["6.5.1", "10.3.2"],                 # SLSA provenance
        "BK-012":   ["6.3.1", "6.3.3"],                  # no vuln scanning
        "BK-013":   ["6.4.3"],                           # deploy w/o branches filter
        # Tekton. Kubernetes-native pipeline kinds.
        "TKN-001":  ["6.3.3"],                           # step image not digest-pinned
        "TKN-016": ["6.3.3"],  # remote resolver / bundle task body not pinned
        "TKN-002":  ["6.4.1", "6.5.1"],                  # step privileged
        "TKN-003":  ["6.5.1"],                           # param injection
        "TKN-004":  ["6.4.1"],                           # hostPath / host namespaces
        "TKN-005":  ["8.2.1", "6.5.1"],                  # literal secrets
        "TKN-006":  ["6.4.1"],                           # no timeout
        "TKN-007":  ["7.2.2", "7.2.5", "8.2.2"],         # default SA = shared identity, no per-classification access
        "TKN-008":  ["6.3.3"],                           # remote install / TLS
        "TKN-009":  ["6.5.1", "10.3.2"],                 # artifacts not signed
        "TKN-010":  ["6.5.1"],                           # no SBOM
        "TKN-011":  ["6.5.1", "10.3.2"],                 # SLSA provenance
        "TKN-012":  ["6.3.1", "6.3.3"],                  # no vuln scanning
        "TKN-013":  ["6.4.1", "6.5.1"],                  # sidecar privileged
        # Argo Workflows.
        "ARGO-001": ["6.3.3"],                           # template image not pinned
        "ARGO-002": ["6.4.1", "6.5.1"],                  # template privileged / root
        "ARGO-003": ["7.2.2", "7.2.5", "8.2.2"],         # default SA
        "ARGO-016": ["7.2.2", "7.2.5", "8.2.2"],         # cluster-admin / over-privileged ServiceAccount
        "ARGO-004": ["6.4.1"],                           # hostPath / host namespaces
        "ARGO-005": ["6.5.1"],                           # param injection
        "ARGO-017": ["6.5.1"],                           # resource template manifest injection
        "ARGO-006": ["8.2.1", "6.5.1"],                  # literal secrets
        "ARGO-007": ["6.4.1"],                           # no activeDeadlineSeconds
        "ARGO-008": ["6.3.3"],                           # remote install / TLS
        "ARGO-009": ["6.5.1", "10.3.2"],                 # artifacts not signed
        "ARGO-010": ["6.5.1"],                           # no SBOM
        "ARGO-011": ["6.5.1", "10.3.2"],                 # SLSA provenance
        "ARGO-012": ["6.3.1", "6.3.3"],                  # no vuln scanning
        "ARGO-013": ["7.2.5"],                           # SA token automount
        # ── Dockerfile (image build = system component change) ─
        # Pinning rules tie to 6.4.3 / 6.5.1 (change control,
        # secure dev). Privileged / root rules tie to 6.4.1
        # (secure build/config). Credential rules tie to 8.2.1
        # (strong unique identifiers). Vuln-related rules tie to
        # 6.3.1 / 6.3.3.
        "DF-001": ["6.4.3", "6.5.1"],                    # FROM not digest-pinned
        "MODEL-001": ["6.4.3", "6.5.1"],                 # unpinned base model
        "MODEL-002": ["6.4.3", "6.5.1"],                 # third-party hub base model
        "MODEL-003": ["6.4.3", "6.5.1"],                 # local unverified weights blob
        "MODEL-004": ["6.4.3", "6.5.1"],                 # remote LoRA adapter
        "MODEL-005": ["6.4.3", "6.5.1"],                 # config auto_map = custom loader code
        "DF-031": ["6.4.3", "6.5.1"],                    # COPY --from external image not digest-pinned
        "DF-002": ["6.4.1", "7.2.5"],                    # runs as root
        "DF-003": ["6.5.1", "6.3.3"],                    # ADD remote no integrity
        "DF-004": ["6.5.1", "6.3.3"],                    # curl-pipe
        "DF-005": ["6.5.1"],                             # shell-eval
        "DF-006": ["8.2.1", "8.2.2"],                    # ENV credential literal
        "DF-008": ["6.4.1", "7.2.5"],                    # docker --privileged
        "DF-010": ["6.3.3"],                             # apt upgrade
        "DF-012": ["7.2.5"],                             # RUN sudo
        "DF-013": ["6.4.1"],                             # sensitive EXPOSE
        "DF-015": ["6.4.1"],                             # chmod 777
        "DF-016": ["10.3.2", "6.5.1"],                   # OCI provenance
        "DF-019": ["8.2.1", "8.2.2"],                    # COPY credential file
        "DF-020": ["8.2.1"],                             # credential ARG
        # ── Helm chart-supply-chain ────────────────────────────
        "HELM-001": ["6.4.3"],                           # legacy apiVersion
        "HELM-002": ["6.5.1", "10.3.2"],                 # missing Chart.lock digests
        "HELM-003": ["6.3.3"],                           # non-HTTPS dep repo
        "HELM-004": ["6.4.3", "6.5.1"],                  # version range
        "HELM-008": ["6.3.3"],                           # stale Chart.lock
        "HELM-009": ["6.3.3"],                           # non-HTTPS home/sources
        # ── Cloud Build ────────────────────────────────────────
        "GCB-001": ["6.4.3", "6.5.1"],                   # step image not pinned
        "GCB-002": ["8.2.1", "8.2.2"],                   # plaintext env secret
        "GCB-003": ["8.2.1"],                            # plain script secret
        "GCB-004": ["6.4.3", "6.5.1"],                   # community step not pinned
        "GCB-005": ["8.2.1"],                            # secret-shaped substitution
        "GCB-006": ["10.2.1"],                           # build logging disabled
        "GCB-008": ["6.5.1", "10.3.2"],                  # no signing
        "GCB-009": ["6.5.1"],                            # no SBOM
        "GCB-010": ["7.2.5"],                            # default network egress
        "GCB-011": ["6.3.3"],                            # TLS bypass
        "GCB-012": ["6.3.1", "6.3.3"],                   # no vuln scan
        "GCB-013": ["7.2.2", "7.2.5", "8.2.2"],          # default service account
        "GCB-014": ["6.5.1"],                            # untrusted substitution
        "GCB-015": ["6.5.1", "10.3.2"],                  # no provenance
        "GCB-016": ["6.4.1"],                            # no timeout
        "GCB-019": ["6.4.1", "7.2.5"],                   # privileged step
        "GCB-020": ["7.2.2", "7.2.5", "8.2.2"],          # default SA email
        "GCB-022": ["6.5.1"],                            # ALLOW_LOOSE substitution
        "GCB-023": ["6.5.1", "10.3.2"],                  # build artifacts not signed
        "GCB-026": ["7.2.1", "7.2.5"],                   # public storage bucket
        "GCB-027": ["6.3.1", "6.5.1"],                   # malicious-activity indicators
        # ── SCM posture (governance via the platform REST API) ──────
        # Branch protection / review controls map to 6.4.3 (change
        # control) and 6.5.1 (secure development procedures) — the
        # two PCI requirements that demand authorized review before
        # code changes land. Access surfaces map to the 7.2.x family
        # (least privilege). Credential surfaces map to 8.2.1 (unique
        # identifiers) and 8.2.2 (group/shared accounts). 10.3.2
        # (audit log integrity) is not used for git-history rewrites:
        # commit history is not an audit log under PCI's definition.
        "SCM-001":  ["6.4.3", "6.5.1"],                  # default branch unprotected
        "SCM-002":  ["6.4.3", "6.5.1"],                  # required reviews missing
        "SCM-003":  ["6.3.1", "6.5.1"],                  # default code scanning disabled
        "SCM-004":  ["6.5.1", "8.2.1"],                  # secret scanning disabled
        "SCM-005":  ["6.3.1", "6.3.3"],                  # Dependabot security updates off
        "SCM-006":  ["8.2.1", "6.5.1"],                  # signed commits not required
        "SCM-007":  ["6.4.3"],                           # force-push allowed
        "SCM-008":  ["6.4.3", "6.5.1"],                  # required status checks missing
        "SCM-009":  ["6.4.3"],                           # branch deletions allowed
        "SCM-010":  ["7.2.1", "6.4.3"],                  # admin bypass allowed
        "SCM-011":  ["6.4.3"],                           # CODEOWNERS reviews not required
        "SCM-012":  ["6.4.3"],                           # stale reviews not dismissed
        "SCM-013":  ["6.4.3"],                           # conversation resolution not required
        "SCM-014":  ["6.4.3"],                           # last-push approval not required
        "SCM-015":  ["6.5.1"],                           # secret scanning push protection off
        "SCM-016":  ["6.3.1"],                           # private vulnerability reporting off
        "SCM-017":  ["6.4.3"],                           # CODEOWNERS file missing
        "SCM-018":  ["6.4.3", "7.2.1"],                  # PR review bypass allowed
        "SCM-019":  ["7.2.1"],                           # push-restriction allowlist names users
        # Actions governance + environments + deploy keys
        "SCM-020":  ["7.2.5", "8.2.1"],                  # workflow_token default write
        "SCM-021":  ["6.4.3"],                           # Actions can approve PRs
        "SCM-022":  ["6.4.1", "6.3.3"],                  # allowed_actions unrestricted
        "SCM-023":  ["6.4.3"],                           # env missing reviewers
        "SCM-024":  ["6.4.3"],                           # env branch policy missing
        "SCM-025":  ["8.2.1", "7.2.5"],                  # deploy keys write-enabled
        "SCM-026":  ["6.4.1", "10.3.2"],                 # webhook insecure / no HMAC
        "SCM-027":  ["7.2.1", "7.2.5"],                  # outside collaborator elevated
        "SCM-028":  ["7.2.5"],                           # private repo allows forking
        # Ruleset enforcement
        "SCM-029":  ["6.4.3"],                           # ruleset not enforced
        "SCM-030":  ["6.4.3", "7.2.1"],                  # ruleset always-bypass
        "SCM-031":  ["6.4.3"],                           # auto-merge enabled
        "SCM-032":  ["6.4.3"],                           # ruleset lacks PR review
        "SCM-033":  ["6.4.3", "6.5.1"],                  # ruleset lacks status_checks
        "SCM-034":  ["6.4.3"],                           # ruleset allows force_push
        "SCM-035":  ["6.4.3"],                           # ruleset allows deletion
        "SCM-036":  ["8.2.1", "6.5.1"],                  # ruleset lacks signed_commits
        "SCM-037":  ["6.4.3"],                           # ruleset stale-review dismissal
        "SCM-038":  ["6.4.3"],                           # ruleset lacks linear_history
        "SCM-039":  ["6.3.1", "6.4.3"],                  # ruleset lacks required_workflows
        "SCM-040":  ["6.3.1"],                           # ruleset lacks code_scanning gate
        "SCM-041":  ["6.4.3", "6.5.1"],                  # ruleset lacks deployment-env gate
        "SCM-042":  ["6.4.3", "6.5.1"],                  # ruleset lacks merge queue
        "SCM-043":  ["8.2.1", "6.5.1"],                  # tag-ruleset lacks signed_commits
        "SCM-044":  ["8.2.1", "7.2.1"],                  # required_signatures bypassed for admins
        "SCM-045":  ["6.3.1"],                           # default code scanning limited query suite
        "SCM-046":  ["6.3.1"],                           # default code scanning paused
        "SCM-047":  ["6.3.1"],                           # repo language not covered
        # ── AWS extras ───────────────────────────────────────────
        "CB-008":  ["6.4.3", "6.5.1"],                   # inline buildspec
        "CB-009":  ["6.4.3", "6.5.1"],                   # build image not digest-pinned
        "CB-010":  ["6.4.1", "6.4.3"],                   # fork-PR webhook unfiltered
        "CB-011":  ["6.3.1", "6.5.1"],                   # buildspec malicious-activity
        "CP-005":  ["6.4.3", "6.5.1"],                   # prod Deploy stage no approval
        "CP-007":  ["6.4.1", "6.4.3"],                   # v2 PR trigger all branches
        "LMB-003": ["8.2.1"],                            # Lambda plaintext env secrets
        "KMS-001": ["10.3.2"],                           # CMK rotation disabled
        # ── Terraform / CloudFormation (IaC-native) ──────────────
        "TF-001":  ["8.2.1"],                            # aws_iam_access_key as code
        "TF-002":  ["8.2.1"],                            # hard-coded secret in resource attr
        "TF-003":  ["6.4.1"],                            # CodeBuild VPC public subnet
        "CF-001":  ["8.2.1"],                            # AWS::IAM::AccessKey as code
        "CF-002":  ["8.2.1"],                            # hard-coded secret in resource property
        "CF-003":  ["6.4.1"],                            # CodeBuild VPC public subnet
        # ── GitHub Actions ───────────────────────────────────────
        "GHA-006":  ["6.5.1", "10.3.2"],                 # unsigned artifacts
        "GHA-007":  ["6.5.1"],                           # no SBOM
        "GHA-008":  ["8.2.1", "6.5.1"],                  # literal secrets in workflow
        "GHA-009":  ["6.4.1", "6.5.1"],                  # workflow_run upstream artifact unverified
        "GHA-010":  ["6.4.1", "6.5.1"],                  # local action on untrusted trigger
        "GHA-011":  ["6.4.1", "6.5.1"],                  # cache key tainted
        "GHA-012":  ["6.4.1"],                           # self-hosted runner not ephemeral
        "GHA-105":  ["6.4.1"],                           # self-hosted runner on PR trigger
        "GHA-013":  ["6.4.1", "6.5.1"],                  # issue_comment no author guard
        "GHA-014":  ["6.4.3"],                           # deploy job missing environment
        "GHA-123":  ["6.4.3"],                           # agentic CLI output lands without review
        "GHA-015":  ["6.4.1"],                           # no timeout-minutes
        "GHA-016":  ["6.3.3", "6.5.1"],                  # remote script piped to shell
        "GHA-017":  ["6.3.3", "6.5.1"],                  # package install insecure source
        "GHA-018":  ["8.2.1"],                           # GITHUB_TOKEN persisted to storage
        "GHA-019":  ["6.3.3", "6.5.1"],                  # install without lockfile
        "GHA-020":  ["6.3.1", "6.3.3"],                  # no vulnerability scanning
        "GHA-021":  ["6.3.3", "6.5.1"],                  # dep-update bypasses lockfile pins
        "GHA-022":  ["6.5.1"],                           # TLS / cert verification bypass
        "GHA-023":  ["6.3.3", "6.5.1"],                  # reusable workflow not SHA-pinned
        "GHA-024":  ["6.5.1", "10.3.2"],                 # no SLSA provenance attestation
        "GHA-025":  ["6.3.3", "6.5.1"],                  # unpinned reusable workflow
        "GHA-026":  ["6.4.1", "6.5.1"],                  # container job disables isolation
        "GHA-107":  ["6.4.1", "6.5.1"],                  # harden-runner in audit mode (egress not blocked)
        "GHA-108":  ["6.4.1", "6.5.1"],                  # no runtime egress control on OIDC/deploy workflow
        "GHA-109":  ["6.4.1", "6.5.1"],                  # harden-runner not the first step
        "GHA-027":  ["6.5.1"],                           # dangerous shell idiom
        "GHA-028":  ["6.3.3", "6.5.1"],                  # install bypasses registry integrity
        "GHA-029":  ["6.3.3", "6.5.1"],                  # package source bypasses lockfile
        "GHA-030":  ["7.2.1", "8.2.1"],                  # OIDC w/o env-protected job
        "GHA-031":  ["6.5.1"],                           # retired set-output / save-state
        "GHA-032":  ["6.4.1", "6.5.1"],                  # local script on untrusted trigger
        "GHA-033":  ["8.2.1", "10.3.2"],                 # secret echoed
        "GHA-034":  ["8.2.1", "7.2.5"],                  # secrets: inherit
        "GHA-035":  ["6.5.1"],                           # github-script untrusted context
        "GHA-036":  ["6.5.1"],                           # runs-on untrusted context
        "GHA-037":  ["8.2.1"],                           # checkout persists GITHUB_TOKEN
        "GHA-038":  ["6.5.1"],                           # ACTIONS_ALLOW_UNSECURE_COMMANDS
        "GHA-039":  ["8.2.1"],                           # services / container creds literal
        "GHA-040":  ["6.3.1", "6.3.3"],                  # known-compromised action ref
        "GHA-041":  ["6.3.3"],                           # single-maintainer action
        "GHA-042":  ["6.3.3"],                           # very-young action repo
        "GHA-043":  ["6.3.3", "7.2.5"],                  # low-star + sensitive perms
        "GHA-044":  ["6.4.1", "6.5.1"],                  # build-tool PPE on untrusted trigger
        "GHA-045":  ["6.4.1", "6.5.1"],                  # caller-ref input drives checkout
        "GHA-046":  ["6.4.1", "6.5.1"],                  # manual PR-head fetch
        "GHA-047":  ["6.3.3"],                           # fresh-ref cooldown
        "GHA-048":  ["6.4.3", "10.3.2"],                 # workflow self-mutation
        "GHA-049":  ["7.2.5", "6.4.3"],                  # cross-repo push from CI
        "GHA-050":  ["8.2.1"],                           # long-lived registry publish token
        "GHA-051":  ["6.3.3", "6.5.1"],                  # services / container image unpinned
        "GHA-052":  ["6.4.1", "6.5.1"],                  # cache key untrusted-input poisoning
        "GHA-053":  ["6.5.1"],                           # if: predicate untrusted-context
        "GHA-054":  ["8.2.1"],                           # checkout ssh-key persists
        "GHA-055":  ["8.2.1"],                           # reusable outputs leak secret
        "GHA-056":  ["6.3.1", "6.5.1"],                  # worm IOC strings
        "GHA-057":  ["8.2.1", "10.3.2"],                 # secret-scanner output → egress
        "GHA-058":  ["6.4.1", "6.5.1"],                  # agentic CLI permission-bypass
        "GHA-059":  ["6.3.3", "6.5.1"],                  # npm install without audit signatures
        "GHA-060":  ["6.3.3", "6.5.1"],                  # pip install without --require-hashes
        "GHA-061":  ["7.2.5", "8.2.1"],                  # App token minted without permissions filter
        "GHA-106":  ["7.2.5", "8.2.1"],                  # AI agent with write-scoped token
        "GHA-111":  ["7.2.5", "8.2.1"],  # AI agent edits IaC applied in the same job
        "GHA-112":  ["6.4.1", "6.4.3"],  # self-hosted deploy with no environment gate
        "GHA-113":  ["7.2.1", "8.2.1"],  # OIDC trusted-publish w/o env gate
        "GHA-114":  ["7.2.1", "8.2.1"],  # publish workflow on an unrestricted push trigger
        "GHA-115":  ["7.2.5"],                           # id-token granted workflow-wide, not job-scoped
        "GHA-116":  ["8.2.1", "7.2.5"],                  # bulk secrets serialization
        "GHA-062":  ["7.2.1", "7.2.5"],                  # OIDC trust subject in sibling IaC is overly broad
        "GHA-063":  ["7.2.5", "8.2.1"],                  # spoofable bot-actor if-predicate
        "GHA-064":  ["6.4.3"],                           # unsound contains() with comma-string operand
        "GHA-065":  ["6.4.3"],                           # zero-width / bidi unicode in workflow body
        "GHA-066":  ["8.2.1", "10.3.2"],                 # upload-artifact wildcard sweeps workspace
        "GHA-067":  ["8.2.1", "10.3.2"],                 # cache step publishes credential-shaped paths
        "GHA-068":  ["6.3.3"],                           # runs-on targets a deprecated hosted runner
        "GHA-069":  ["7.2.5"],                           # orphan id-token: write scope
        "GHA-070":  ["6.3.3", "8.2.1"],                  # ssh-keyscan / host-key check TOFU
        "GHA-071":  ["6.4.3"],                           # powershell on Linux / macOS step
        "GHA-072":  ["8.2.1"],                           # secret env: at wider scope than consumer
        "GHA-073":  ["8.2.1"],                           # unused workflow_call.secrets declaration
        "GHA-086":  ["6.4.3"],                           # wildcard branch trigger + environment binding
        "GHA-087":  ["8.2.1", "10.3.2"],                 # derived-value of secret printed to log
        "GHA-088":  ["6.3.1", "6.3.3"],                  # typosquat uses: near-edit of top action
        "GHA-089":  ["6.3.1", "6.3.3"],                  # archived upstream repo
        "GHA-090":  ["6.3.1", "6.3.3"],                  # impostor-commit: SHA absent from repo
        "GHA-091":  ["6.3.1", "6.3.3"],                  # repojacking: action upstream missing
        "GHA-092":  ["6.4.1", "6.5.1"],                  # TOCTOU PR head SHA force-push race
        "GHA-093":  ["8.2.1", "10.3.2"],                 # LOTP indicators
        "GHA-094":  ["6.3.3"],                           # stale-action-refs
        "GHA-096":  ["6.3.1", "6.3.3"],                  # known-vulnerable action ref (GHSA)
        # ── GitLab CI ─────────────────────────────────────────────
        "GL-006":   ["6.5.1", "10.3.2"],                 # unsigned artifacts
        "GL-007":   ["6.5.1"],                           # no SBOM
        "GL-008":   ["8.2.1", "6.5.1"],                  # literal secrets
        "DEV-008":   ["8.2.1", "6.5.1"],                 # literal secret in a devenv config
        "GL-009":   ["6.3.3", "6.5.1"],                  # image not digest-pinned
        "GL-010":   ["6.4.1", "6.5.1"],                  # multi-project artifact unverified
        "GL-011":   ["6.4.1", "6.5.1"],                  # include: local on MR pipeline
        "GL-012":   ["6.4.1", "6.5.1"],                  # cache key tainted
        "GL-013":   ["8.2.1"],                           # long-lived AWS keys
        "GL-014":   ["6.4.1"],                           # self-managed runner not ephemeral
        "GL-015":   ["6.4.1"],                           # no timeout
        "GL-016":   ["6.3.3", "6.5.1"],                  # remote script piped to shell
        "GL-017":   ["6.4.1", "6.5.1"],                  # docker privileged
        "GL-039":   ["6.4.1", "6.5.1"],                  # dind daemon TLS disabled / exposed on 2375
        "GL-018":   ["6.3.3", "6.5.1"],                  # package install insecure source
        "GL-019":   ["6.3.1", "6.3.3"],                  # no vulnerability scanning
        "GL-043":   ["6.3.1", "6.3.3"],                  # native security scanner disabled
        "GL-020":   ["8.2.1"],                           # CI_JOB_TOKEN persisted
        "GL-021":   ["6.3.3", "6.5.1"],                  # install without lockfile
        "GL-022":   ["6.3.3", "6.5.1"],                  # dep-update bypasses lockfile pins
        "GL-023":   ["6.5.1"],                           # TLS bypass
        "GL-024":   ["6.5.1", "10.3.2"],                 # no SLSA provenance
        "GL-025":   ["6.3.1", "6.5.1"],                  # malicious-activity indicators
        "GL-026":   ["6.5.1"],                           # dangerous shell idiom
        "GL-027":   ["6.3.3", "6.5.1"],                  # install bypasses registry integrity
        "GL-028":   ["6.3.3", "6.5.1"],                  # services: image not pinned
        "GL-029":   ["6.4.3"],                           # manual deploy allow_failure
        "GL-030":   ["6.3.3", "6.5.1"],                  # trigger: include w/o pinned ref
        "GL-031":   ["7.2.1", "8.2.1"],                  # id_tokens missing audience pin
        "GL-040":   ["7.2.1", "8.2.1"],                  # CI_JOB_TOKEN used for cross-project access
        "GL-041":   ["6.5.1"],                           # IaC apply on an untrusted MR trigger
        "GL-032":   ["6.5.1"],                           # tags interpolates untrusted
        "GL-033":   ["6.4.1", "6.5.1"],                  # global before_script taint
        "GL-034":   ["6.3.3", "6.5.1"],                  # npm install without audit signatures
        "GL-035":   ["6.3.3", "6.5.1"],                  # pip install without --require-hashes
        # ── Bitbucket Pipelines ──────────────────────────────────
        "BB-006":   ["6.5.1", "10.3.2"],                 # unsigned artifacts
        "BB-007":   ["6.5.1"],                           # no SBOM
        "BB-008":   ["8.2.1", "6.5.1"],                  # literal secrets
        "BB-009":   ["6.3.3", "6.5.1"],                  # pipe not digest-pinned
        "BB-010":   ["6.4.1", "6.5.1"],                  # deploy step PR artifact unverified
        "BB-011":   ["8.2.1"],                           # long-lived AWS keys
        "BB-012":   ["6.3.3", "6.5.1"],                  # remote script piped to shell
        "BB-013":   ["6.4.1", "6.5.1"],                  # docker privileged
        "BB-014":   ["6.3.3", "6.5.1"],                  # package install insecure source
        "BB-015":   ["6.3.1", "6.3.3"],                  # no vulnerability scanning
        "BB-016":   ["6.4.1"],                           # self-hosted runner not ephemeral
        "BB-017":   ["8.2.1"],                           # repo token persisted to storage
        "BB-018":   ["6.4.1", "6.5.1"],                  # cache key tainted
        "BB-019":   ["8.2.1"],                           # after-script references secrets
        "BB-020":   ["8.2.1"],                           # full clone depth exposes history
        "BB-021":   ["6.3.3", "6.5.1"],                  # install without lockfile
        "BB-022":   ["6.3.3", "6.5.1"],                  # dep-update bypasses lockfile pins
        "BB-023":   ["6.5.1"],                           # TLS bypass
        "BB-024":   ["6.5.1", "10.3.2"],                 # no SLSA provenance
        "BB-025":   ["6.3.1", "6.5.1"],                  # malicious-activity indicators
        "BB-026":   ["6.5.1"],                           # dangerous shell idiom
        "BB-027":   ["6.3.3", "6.5.1"],                  # install bypasses registry integrity
        "BB-028":   ["7.2.1", "8.2.1"],                  # OIDC step w/o env gate
        "BB-029":   ["6.3.3", "6.5.1"],                  # step + service image not pinned
        "BB-030":   ["6.3.3", "6.5.1"],                  # npm install without audit signatures
        "BB-031":   ["6.3.3", "6.5.1"],                  # pip install without --require-hashes
        "BB-038":   ["6.3.3", "6.5.1"],                  # model pulled without a pinned revision
        # ── Azure DevOps Pipelines ───────────────────────────────
        "ADO-006":  ["6.5.1", "10.3.2"],                 # unsigned artifacts
        "ADO-007":  ["6.5.1"],                           # no SBOM
        "ADO-008":  ["8.2.1", "6.5.1"],                  # literal secrets
        "ADO-009":  ["6.3.3", "6.5.1"],                  # container image not digest-pinned
        "ADO-037":  ["6.3.3", "6.5.1"],                  # model pulled without a pinned revision
        "ADO-010":  ["6.4.1", "6.5.1"],                  # cross-pipeline download unverified
        "ADO-011":  ["6.4.1", "6.5.1"],                  # template: local on PR-validated
        "ADO-012":  ["6.4.1", "6.5.1"],                  # Cache@2 PullRequest context
        "ADO-013":  ["6.4.1"],                           # self-hosted pool not ephemeral
        "ADO-014":  ["8.2.1"],                           # long-lived AWS keys
        "ADO-015":  ["6.4.1"],                           # no timeoutInMinutes
        "ADO-016":  ["6.3.3", "6.5.1"],                  # remote script piped to shell
        "ADO-017":  ["6.4.1", "6.5.1"],                  # docker privileged
        "ADO-018":  ["6.3.3", "6.5.1"],                  # package install insecure source
        "ADO-019":  ["6.4.1", "6.5.1"],                  # extends template injection
        "ADO-020":  ["6.3.1", "6.3.3"],                  # no vulnerability scanning
        "ADO-021":  ["6.3.3", "6.5.1"],                  # install without lockfile
        "ADO-022":  ["6.3.3", "6.5.1"],                  # dep-update bypasses lockfile pins
        "ADO-023":  ["6.5.1"],                           # TLS bypass
        "ADO-024":  ["6.5.1", "10.3.2"],                 # no SLSA provenance
        "ADO-025":  ["6.3.3", "6.5.1"],                  # unpinned cross-repo template
        "ADO-026":  ["6.3.1", "6.5.1"],                  # malicious-activity indicators
        "ADO-027":  ["6.5.1"],                           # dangerous shell idiom
        "ADO-028":  ["6.3.3", "6.5.1"],                  # install bypasses registry integrity
        "ADO-029":  ["6.4.3"],                           # service-conn job w/o env gate
        "ADO-030":  ["6.5.1"],                           # pool interpolates untrusted
        # ── CircleCI extras ──────────────────────────────────────
        "CC-024":   ["6.5.1", "10.3.2"],                 # no SLSA provenance
        "CC-025":   ["6.4.1", "6.5.1"],                  # cache key tainted
        "CC-026":   ["6.3.1", "6.5.1"],                  # malicious-activity indicators
        "CC-027":   ["6.5.1"],                           # dangerous shell idiom
        "CC-028":   ["6.3.3", "6.5.1"],                  # install bypasses registry integrity
        "CC-029":   ["6.3.3", "6.5.1"],                  # machine executor image not pinned
        "CC-030":   ["6.4.3"],                           # job w/o branch filter / approval gate
        "CC-031":   ["7.2.1", "8.2.1"],                  # OIDC role w/o branch filter
        # ── Jenkins ──────────────────────────────────────────────
        "JF-001":   ["6.3.3", "6.5.1"],                  # shared library not pinned
        "JF-002":   ["6.5.1"],                           # script step untrusted env
        "JF-037":   ["6.5.1"],                           # agentic CLI ingests untrusted context (prompt injection)
        "JF-003":   ["7.2.5"],                           # agent any (no executor isolation)
        "JF-004":   ["8.2.1"],                           # AWS long-lived keys via withCredentials
        "JF-005":   ["6.4.3"],                           # deploy stage missing manual input
        "JF-006":   ["6.5.1", "10.3.2"],                 # artifacts not signed
        "JF-007":   ["6.5.1"],                           # SBOM not produced
        "JF-008":   ["8.2.1", "6.5.1"],                  # credential-shaped literal
        "JF-009":   ["6.3.3", "6.5.1"],                  # agent docker image not digest-pinned
        "JF-010":   ["8.2.1"],                           # long-lived AWS keys in environment {}
        "JF-011":   ["10.2.1"],                          # no buildDiscarder retention
        "JF-012":   ["6.3.3", "6.5.1"],                  # load step pulls Groovy w/o integrity pin
        "JF-013":   ["6.4.1", "6.5.1"],                  # copyArtifacts ingests upstream unverified
        "JF-014":   ["6.4.1"],                           # agent label missing ephemeral marker
        "JF-015":   ["6.4.1"],                           # pipeline has no timeout wrapper
        "JF-016":   ["6.3.3", "6.5.1"],                  # remote script piped to shell
        "JF-017":   ["6.4.1", "6.5.1"],                  # docker run privileged
        "JF-018":   ["6.3.3", "6.5.1"],                  # package install insecure source
        "JF-019":   ["6.4.1", "6.5.1"],                  # Groovy sandbox escape pattern
        "JF-020":   ["6.3.1", "6.3.3"],                  # no vulnerability scanning
        "JF-021":   ["6.3.3", "6.5.1"],                  # install without lockfile
        "JF-022":   ["6.3.3", "6.5.1"],                  # dep-update bypasses lockfile pins
        "JF-023":   ["6.5.1"],                           # TLS bypass
        "JF-024":   ["6.4.3"],                           # input approval missing submitter restriction
        "JF-025":   ["6.4.1", "6.5.1"],                  # K8s agent pod privileged / hostPath
        "JF-026":   ["6.4.3"],                           # build job: trigger ignores downstream failure
        "JF-027":   ["6.5.1"],                           # archiveArtifacts no fingerprint
        "JF-028":   ["6.5.1", "10.3.2"],                 # no SLSA provenance attestation
        "JF-029":   ["6.3.1", "6.5.1"],                  # malicious-activity indicators
        "JF-030":   ["6.5.1"],                           # dangerous shell idiom
        "JF-031":   ["6.3.3", "6.5.1"],                  # install bypasses registry integrity
        "JF-032":   ["6.5.1"],                           # agent label interpolates untrusted
        "JF-033":   ["8.2.1", "10.3.2"],                 # withCredentials leaked via Groovy ${}
        "JF-034":   ["8.2.1"],                           # password() build parameter
        "JF-035":   ["6.5.1"],                           # httpRequest SSL off
        # ── Drone CI ─────────────────────────────────────────────
        "DR-001":   ["6.3.3", "6.5.1"],                  # step image not digest-pinned
        "HARNESS-001":   ["6.3.3", "6.5.1"],  # Harness step image not digest-pinned
        "HARNESS-002":   ["6.5.1"],  # Harness expression injection in step command
        "HARNESS-003":   ["6.4.1", "6.5.1"],  # Harness privileged step
        "HARNESS-004":   ["8.2.1", "6.5.1"],  # Harness literal credential in variable
        "HARNESS-005":   ["6.3.1"],  # Harness pipe-to-shell
        "HARNESS-006":   ["6.5.1"],  # Harness TLS bypass in commands
        "HARNESS-007":   ["6.4.1", "6.5.1"],  # Harness sensitive host-path mount
        "HARNESS-008":   ["6.5.1"],  # Harness agentic-CLI prompt injection
        "HARNESS-010":   ["6.5.1"],  # Harness model trust_remote_code (code exec)
        "HARNESS-011":   ["6.5.1"],  # Harness unsafe model deser (pickle RCE)
        "HARNESS-009":   ["6.4.3"],  # Harness agentic-CLI output autolands without review
        "DR-002":   ["6.4.1", "6.5.1"],                  # privileged step
        "DR-003":   ["6.5.1"],                           # Drone variable injection
        "DR-004":   ["8.2.1", "6.5.1"],                  # literal credential
        "DR-005":   ["6.3.3", "6.5.1"],                  # plugin floating tag
        "DR-006":   ["6.5.1"],                           # TLS bypass in commands
        "DR-007":   ["6.4.1", "6.5.1"],                  # sensitive host-path mount
        "DR-008":   ["6.3.3", "6.5.1"],                  # pull: never
        "DR-009":   ["6.4.1", "6.5.1"],                  # cache key tainted
        "DR-010":   ["6.3.3", "6.5.1"],                  # unpinned package install
        "DR-011":   ["6.5.1"],                           # node map interpolates untrusted
        # ── Drone extended pack ──
        "DR-012":   ["6.3.1"],                           # service image not pinned
        "DR-013":   ["6.5.1"],                           # no trigger event filter
        "DR-014":   ["6.3.1"],                           # pipe-to-shell
        "DR-015":   ["6.3.1"],                           # clone recursive
        "DR-016":   ["6.5.1"],                           # image field interpolation
        "DR-017":   ["6.5.1"],                           # dangerous shell idiom
        # ── Buildkite extras ─────────────────────────────────────
        "BK-014":   ["6.3.3", "6.5.1"],                  # unpinned package install
        "BK-015":   ["6.5.1"],                           # agents map untrusted interpolation
        # ── Tekton extras ────────────────────────────────────────
        "TKN-014":  ["6.3.3", "6.5.1"],                  # unpinned package install
        "TKN-015":  ["6.5.1"],                           # workspace subPath param injection
        # ── Argo extras ──────────────────────────────────────────
        "ARGO-014": ["6.3.3", "6.5.1"],                  # unpinned package install
        "ARGO-015": ["6.5.1"],                           # insecure (non-HTTPS) artifact URL
        # ── Argo CD (GitOps deployment) ──
        "ARGOCD-010": ["6.3.1"],                         # mutable targetRevision
        "ARGOCD-017": ["6.3.1"],  # in-cluster mutable source
        "ARGOCD-019": ["6.3.1"],  # drift detection disabled on a sensitive field
        "ARGOCD-016": ["6.3.1"],  # Helm valueFiles from a remote URL
        "ARGOCD-018": ["6.3.1"],  # custom resource health / action Lua
        "ARGOCD-011": ["7.2.1"],                         # cluster-resource wildcard
        "ARGOCD-012": ["6.5.1"],                         # no sync windows
        "ARGOCD-013": ["10.3.2"],                        # no revision history cap
        # ── Cloud Build extras ───────────────────────────────────
        "GCB-007":  ["8.2.1"],                           # availableSecrets versions/latest
        "GCB-017":  ["6.5.1", "10.3.2"],                 # no SLSA provenance attestation
        "GCB-018":  ["8.2.1"],                           # legacy KMS secrets block
        "GCB-021":  ["6.4.1"],                           # no private worker pool
        "GCB-024":  ["6.5.1"],                           # images: missing for docker push
        "GCB-025":  ["10.2.1"],                          # tags: empty (audit/discoverability)
        # ── NPM / PyPI / Maven dep supply-chain ──────────────────
        # Pinning / integrity → 6.3.3 (vuln prevention via patch) +
        # 6.5.1 (secure dev). Compromised pkgs add 6.3.1 (vuln id).
        # Lifecycle scripts evidence 6.5.1. Secret-shaped globs add
        # 8.2.1.
        "NPM-001":  ["6.3.3", "6.5.1"],
        "NPM-002":  ["6.3.3", "6.5.1"],
        "NPM-003":  ["6.3.3", "6.5.1"],
        "NPM-004":  ["6.5.1"],
        "NPM-005":  ["6.3.3", "6.5.1"],
        "NPM-006":  ["6.3.1", "6.3.3"],
        "NPM-007":  ["6.5.1"],
        "NPM-011":  ["8.2.1"],
        "NPM-013":  ["8.2.1"],
        "PYPI-001": ["6.3.3", "6.5.1"],
        "PYPI-002": ["6.3.3", "6.5.1"],
        "PYPI-003": ["6.3.3", "6.5.1"],
        "PYPI-018": ["6.3.3", "6.5.1"],  # --no-binary forces sdist build
        "PYPI-019": ["6.3.1", "6.3.3"],  # missing PEP 740 build provenance
        "PYPI-020": ["6.3.1", "6.3.3"],  # low OpenSSF Scorecard upstream
        "PYPI-021": ["6.3.1", "6.3.3"],  # provenance built from a non-release ref
        "PYPI-004": ["6.3.3", "6.5.1"],
        "PYPI-015": ["6.3.3", "6.5.1"],  # direct artifact URL
        "PYPI-005": ["6.3.3", "6.5.1"],
        "PYPI-017": ["6.3.3", "6.5.1"],  # remote --find-links
        "PYPI-016": ["6.3.3", "6.5.1"],  # primary index repointed
        "PYPI-006": ["6.3.1", "6.3.3"],
        "MVN-001":  ["6.3.3", "6.5.1"],
        "MVN-002":  ["6.3.3", "6.5.1"],
        "MVN-003":  ["6.3.3", "6.5.1"],
        "MVN-004":  ["6.3.3", "6.5.1"],
        "MVN-005":  ["6.3.3", "6.5.1"],
        "MVN-006":  ["6.3.1", "6.3.3"],
        "MVN-007":  ["6.3.3", "6.5.1"],
        "MVN-008":  ["6.3.1", "6.3.3"],
        "MVN-009":  ["6.3.1", "6.3.3"],
        # ── Maven extended pack ──
        "MVN-010":  ["8.2.1"],
        "MVN-011":  ["8.2.1"],
        "MVN-012":  ["6.3.1"],
        "MVN-013":  ["6.3.1"],
        "MVN-014":  ["6.3.1"],
        "MVN-015": ["6.3.1"],  # build-time plugin exec bound to lifecycle
        "MVN-016": ["6.3.1"],  # gradle allowInsecureProtocol
        "MVN-017": ["8.2.1"],  # settings.xml privateKey + plaintext passphrase
        "MVN-018": ["6.3.1"],  # distributionManagement release accepts snapshots
        "NPM-008":  ["6.3.1", "6.3.3"],
        "NPM-009":  ["6.3.3", "6.5.1"],
        "NPM-010":  ["6.3.1", "6.3.3"],
        "NPM-014":  ["6.3.1", "6.3.3"],
        "NPM-015":  ["6.3.1", "6.3.3"],
        "NPM-017":  ["6.3.1", "6.3.3"],  # provenance built from a non-release ref
        "NPM-018":  ["6.3.1", "6.3.3"],  # latest release from a new publisher
        "NPM-019":  ["6.3.1", "6.3.3"],  # overrides / resolutions redirect
        "NPM-020":  ["6.3.1", "6.3.3"],  # .npmrc registry repoint
        "NPM-016":  ["6.3.1", "6.3.3"],
        "PYPI-008": ["6.3.1", "6.3.3"],
        "PYPI-009": ["6.3.1", "6.3.3"],
        # ── PyPI extended pack ──
        "PYPI-010": ["8.2.1"],                   # index URL embedded credentials
        "PYPI-011": ["6.3.1"],                   # --trusted-host disables TLS
        "PYPI-012": ["6.3.1"],                   # build-system requires floating
        "PYPI-013": ["6.3.1"],                   # pyproject dynamic dependencies
        "PYPI-014": ["6.3.1"],                   # custom source HTTP
        # ── nuget (dep supply-chain) ─────────────────────────────
        "NUGET-001": ["6.3.3", "6.5.1"],
        "NUGET-002": ["6.3.3", "6.5.1"],
        "NUGET-003": ["6.3.3", "6.5.1"],
        "NUGET-004": ["6.3.3", "6.5.1"],
        "NUGET-005": ["6.3.1", "6.3.3"],
        "NUGET-006": ["6.3.3", "6.5.1"],
        "NUGET-007": ["6.3.3", "6.5.1"],
        "NUGET-008": ["6.3.1", "6.3.3"],
        "NUGET-009": ["6.3.1", "6.3.3"],
        "NUGET-010": ["8.2.1"],                  # NuGet.config cleartext feed credential
        # ── NuGet extended pack ──
        "NUGET-011": ["6.3.1"],
        "NUGET-012": ["6.3.1"],
        "NUGET-013": ["6.3.1"],
        "NUGET-014": ["8.2.1"],
        "NUGET-015": ["6.3.1"],
        "NUGET-016": ["6.3.3", "6.5.1"],  # missing <clear/> inherits public gallery
        "NUGET-017": ["6.3.3", "6.5.1"],  # public gallery active alongside private feed, not disabled
        "NUGET-018": ["6.3.1"],  # build-time MSBuild execution
        "NUGET-019": ["6.3.1"],  # require mode, no trusted signers
        # ── Go modules ──
        "GOMOD-001": ["6.3.1"],                  # go.sum integrity manifest missing
        "GOMOD-002": ["6.3.1"],                  # replace directive to local path
        "GOMOD-003": ["6.3.1"],                  # replace directive to different module
        "GOMOD-004": ["6.3.3"],                  # +incompatible direct require
        "GOMOD-005": ["6.5.1"],                  # missing go toolchain directive
        "GOMOD-006": ["6.3.1", "6.3.3"],         # known-compromised module version
        # ── Go modules extended pack ──
        "GOMOD-007": ["6.3.1"],
        "GOMOD-008": ["6.3.1"],
        "GOMOD-009": ["6.3.1"],
        "GOMOD-010": ["6.3.1"],
        "GOMOD-011": ["6.3.1"],  # tool directive build-time exec
        "GOMOD-012": ["6.3.1"],  # insecure / non-canonical module host
        # ── Cargo ──
        "CARGO-001": ["6.3.1"],                  # floating Cargo.toml version spec
        "CARGO-002": ["6.3.1"],                  # git dep with mutable ref (no rev)
        "CARGO-003": ["6.3.1"],                  # missing Cargo.lock
        "CARGO-004": ["6.3.1"],                  # local-path Cargo dependency
        "CARGO-005": ["6.3.1"],                  # alternate-registry Cargo dependency
        "CARGO-006": ["6.3.1", "6.3.3"],         # known-compromised crate version
        # ── Cargo extended pack ──
        "CARGO-007": ["6.3.1"],
        "CARGO-008": ["6.3.1"],
        "CARGO-009": ["6.3.1"],
        "CARGO-010": ["6.5.1"],
        "CARGO-011": ["6.3.1"],  # build.rs compile-time egress / exec
        "CARGO-012": ["6.3.1"],  # .cargo/config.toml source override / build flags
        "CARGO-013": ["6.3.1"],  # Cargo.lock off-crates.io source
        "CARGO-014": ["6.3.1"],  # no supply-chain audit-gate config
        # ── Composer / PHP ──
        "COMPOSER-001": ["6.3.1"],
        "COMPOSER-002": ["6.3.1"],
        "COMPOSER-003": ["6.3.1"],
        "COMPOSER-012": ["6.3.1"],  # disables Packagist / marks custom repo canonical
        "COMPOSER-011": ["6.3.1"],  # external VCS repository re-points a package
        "COMPOSER-004": ["8.2.1"],
        "COMPOSER-005": ["6.3.1"],
        "COMPOSER-014": ["6.3.1"],  # minimum-stability without prefer-stable
        "COMPOSER-006": ["6.3.1"],
        "COMPOSER-007": ["6.3.1", "6.3.3"],
        "COMPOSER-008": ["6.3.1"],
        "COMPOSER-009": ["8.2.1"],
        "COMPOSER-010": ["6.3.1"],
        "COMPOSER-013": ["6.3.1"],  # config.disable-tls
        # ── RubyGems / Bundler ──
        "GEM-001": ["6.3.1"],
        "GEM-002": ["6.3.1"],
        "GEM-003": ["6.3.1"],
        "GEM-004": ["8.2.1"],
        "GEM-005": ["6.3.1"],
        "GEM-006": ["6.3.1", "6.3.3"],
        "GEM-007": ["6.3.1"],
        "GEM-008": ["6.3.1"],
        "GEM-009": ["8.2.1"],
        "GEM-010": ["6.3.1"],
        "GEM-011": ["6.3.1"],  # Bundler plugin install-time exec
        "GEM-012": ["6.3.1"],  # per-gem :source override
        "GEM-013": ["6.3.1"],  # insecure git transport
        # ── Pulumi ──
        "PULUMI-001": ["8.2.1"],        # passphrase secretsprovider
        "PULUMI-002": ["8.2.1"],        # secret-shaped config plaintext
        "PULUMI-003": ["8.2.1"],        # hardcoded credentials in source
        "PULUMI-011": ["8.2.1"],  # plugin from custom download server
        "PULUMI-004": ["10.3.2", "8.2.1"],       # insecure state backend
        "PULUMI-005": ["7.2.1"],                 # wildcard IAM policy in source
        "PULUMI-006": ["7.2.1"],                 # StackReference unguarded
        # ── Pulumi extended pack ──
        "PULUMI-007": ["8.2.1"],                 # public-access cloud resource
        "PULUMI-008": ["6.5.1"],                 # shell-exec with non-constant input
        "PULUMI-013": ["6.5.1"],  # dynamic provider deploy-time code
        "PULUMI-014": ["6.5.1"],  # ESC environment imported without a qualifier
        "PULUMI-009": ["6.5.1"],                 # runtime / source mismatch
        "PULUMI-012": ["6.5.1"],  # plugin version unpinned
        "PULUMI-010": ["8.2.1"],                 # stack orphaned encryption salt
        # ── OCI image manifest gaps ──────────────────────────────
        "OCI-001":  ["6.5.1", "10.3.2"],                 # provenance annotations missing
        "OCI-002":  ["6.5.1", "10.3.2"],                 # build attestation missing
        "OCI-003":  ["6.5.1"],                           # missing image.created
        "OCI-004":  ["6.3.3"],                           # foreign-layer URL reference
        "OCI-005":  ["6.5.1"],                           # missing image.licenses
        "OCI-006":  ["6.5.1"],                           # excessive layer count
        "OCI-007":  ["6.3.3", "6.5.1"],                  # legacy schemaVersion 1
        "OCI-008":  ["6.3.3", "6.5.1"],                  # weak digest algorithm
        "OCI-009":  ["6.5.1", "10.3.2"],                 # missing base-image annotations
        # ── SLSA / in-toto attestation content ───────────────────
        "ATTEST-001": ["6.5.1", "10.3.2"],               # untrusted SLSA builder identity
        "ATTEST-002": ["6.5.1", "10.3.2"],               # source-repo claim unverifiable
        "ATTEST-003": ["6.5.1"],                         # SBOM floating versions
        "ATTEST-004": ["6.5.1"],                         # provenance lacks materials
        "ATTEST-005": ["6.5.1", "10.3.2"],               # in-toto subject digest unpinned
        "ATTEST-006": ["6.5.1"],                         # buildType missing
        "ATTEST-007": ["6.5.1"],                         # SBOM missing supplier
        # ── Cross-cutting dataflow / taint engine ────────────────
        # Cross-step / cross-job untrusted-data flow into privileged
        # sinks = both a secure-config failure (6.4.1) and secure-
        # development failure (6.5.1).
        "TAINT-001": ["6.4.1", "6.5.1"],
        "TAINT-002": ["6.4.1", "6.5.1"],
        "TAINT-003": ["6.4.1", "6.5.1"],
        "TAINT-004": ["6.4.1", "6.5.1"],
        "TAINT-005": ["6.4.1", "6.5.1"],
        "TAINT-006": ["6.4.1", "6.5.1"],
        "TAINT-007": ["6.4.1", "6.5.1"],
        "TAINT-008": ["6.4.1", "6.5.1"],
        "TAINT-009": ["8.2.1", "6.5.1"],                  # env-protected secret flows to unprotected job
        # ── Dockerfile extras ───────────────────────────────────
        "DF-007":   ["10.2.1"],                          # no HEALTHCHECK
        "DF-009":   ["6.5.1"],                           # ADD where COPY suffices
        "DF-011":   ["6.5.1"],                           # apt cache not cleaned
        "DF-014":   ["6.4.1"],                           # WORKDIR /etc
        "DF-017":   ["6.4.1"],                           # ENV PATH writable prefix
        "DF-018":   ["6.4.1"],                           # RUN chown system path
        "DF-021":   ["6.5.1"],                           # pip TLS bypass / http index
        "DF-022":   ["6.3.3", "6.5.1"],                  # npm install (not npm ci)
        "DF-023":   ["6.4.1"],                           # LD_PRELOAD / LD_LIBRARY_PATH
        "DF-024":   ["6.5.1"],                           # npm install runs lifecycle scripts
        "DF-025":   ["8.2.1"],                           # registry token in image layer
        "DF-026":   ["6.5.1"],                           # NODE_TLS_REJECT_UNAUTHORIZED=0
        "DF-027":   ["6.5.1"],                           # PYTHONHTTPSVERIFY=0
        "DF-028":   ["6.5.1"],                           # GIT_SSL_NO_VERIFY=1
        "DF-029":   ["6.5.1"],                           # REQUESTS_CA_BUNDLE neutered
        "DF-030":   ["6.4.1", "6.5.1"],                  # NODE_OPTIONS --require / --inspect
        # ── Helm chart provenance metadata extras ────────────────
        "HELM-005": ["6.5.1"],                           # missing maintainers
        "HELM-006": ["6.5.1"],                           # missing kubeVersion
        "HELM-007": ["6.5.1"],                           # missing description
        "HELM-010": ["6.5.1"],                           # missing appVersion
        # ── Helm extended pack ──
        "HELM-011": ["8.2.1"],                           # dependency URL embedded creds
        "HELM-012": ["6.3.3"],                           # deprecated without successor
        "HELM-013": ["6.5.1"],                           # invalid chart type
        "HELM-014": ["6.3.1", "6.3.3"],                  # known-compromised dep
        "HELM-015": ["6.3.1"],  # oci:// dependency not digest-pinned
        "HELM-016": ["8.2.1"],  # default secret in values.yaml
        "HELM-017": ["6.3.1"],  # tpl of an untrusted .Values value
        # ── Degraded-mode findings (API access failures) ─────────
        # Visibility gap = audit-log surface gap; req 10.2.1 says
        # "Audit logs are enabled and active for all system
        # components" — when the scanner can't enumerate a surface,
        # that requirement isn't demonstrable. Mirrors the cross-
        # standard precedent.
        "CB-000":   ["10.2.1"],
        "CP-000":   ["10.2.1"],
        "CD-000":   ["10.2.1"],
        "ECR-000":  ["10.2.1"],
        "IAM-000":  ["10.2.1"],
        "PBAC-000": ["10.2.1"],
        "CT-000":   ["10.2.1"],
        "CWL-000":  ["10.2.1"],
        "EB-000":   ["10.2.1"],
        "CA-000":   ["10.2.1"],
        "CCM-000":  ["10.2.1"],
        "LMB-000":  ["10.2.1"],
        "KMS-000":  ["10.2.1"],
        "SM-000":   ["10.2.1"],
        "SSM-000":  ["10.2.1"],
        # ── Kubernetes manifests (deployment payload) ───────────
        # K8s workload manifests are part of the system component
        # change surface PCI's Req-6 covers. Image-pinning → 6.3.3
        # + 6.5.1; privileged / runtime hardening / network →
        # 6.4.1; RBAC / SA → 7.2.5 (least-privilege accounts);
        # secret exposure → 8.2.1.
        "K8S-001":  ["6.3.3", "6.5.1"],                  # image not digest-pinned
        "K8S-002":  ["6.4.1"],                           # hostNetwork
        "K8S-003":  ["6.4.1"],                           # hostPID
        "K8S-004":  ["6.4.1"],                           # hostIPC
        "K8S-005":  ["6.4.1", "6.5.1"],                  # privileged container
        "K8S-006":  ["6.4.1", "6.5.1"],                  # allowPrivilegeEscalation
        "K8S-007":  ["6.4.1"],                           # runAsNonRoot missing
        "K8S-008":  ["6.4.1"],                           # readOnlyRootFilesystem missing
        "K8S-009":  ["6.4.1"],                           # added capabilities
        "K8S-010":  ["6.4.1"],                           # seccompProfile missing
        "K8S-011":  ["7.2.5"],                           # default ServiceAccount
        "K8S-012":  ["7.2.5"],                           # automountServiceAccountToken
        "K8S-013":  ["6.4.1"],                           # hostPath volume
        "K8S-014":  ["6.4.1"],                           # sensitive hostPath
        "K8S-015":  ["6.4.1"],                           # no memory limit
        "K8S-016":  ["6.4.1"],                           # no CPU limit
        "K8S-017":  ["8.2.1"],                           # credential literal in env
        "K8S-018":  ["8.2.1"],                           # Secret data plaintext
        "K8S-019":  ["6.4.1"],                           # default namespace
        "K8S-020":  ["7.2.1", "7.2.5"],                  # cluster-admin RoleBinding
        "K8S-021":  ["7.2.1", "7.2.5"],                  # wildcard RBAC verbs
        "K8S-022":  ["6.4.1"],                           # SSH service exposed
        "K8S-023":  ["6.4.1"],                           # PSA enforce missing
        "K8S-044":  ["6.4.1"],                           # admission webhook fail-open / unscoped mutating
        "K8S-024":  ["10.2.1"],                          # missing health probes
        "K8S-025":  ["6.4.1"],                           # system priority class
        "K8S-026":  ["6.4.1"],                           # LB without source ranges
        "K8S-027":  ["6.5.1"],                           # Ingress without TLS
        "K8S-028":  ["6.4.1"],                           # container hostPort
        "K8S-029":  ["7.2.5"],                           # default-SA RoleBinding
        "K8S-030":  ["6.4.1"],                           # control-plane scheduling
        "K8S-031":  ["6.4.1"],                           # PSA warn missing
        "K8S-032":  ["6.4.1"],                           # NetworkPolicy default-deny missing
        "K8S-033":  ["6.4.1"],                           # ResourceQuota / LimitRange missing
        "K8S-034":  ["7.2.5"],                           # SA token automount default
        "K8S-035":  ["6.4.1"],                           # runAsUser: 0
        "K8S-036":  ["6.3.3"],                           # SA imagePullSecret missing
        "K8S-037":  ["8.2.1"],                           # ConfigMap credential
        "K8S-038":  ["6.4.1"],                           # NetworkPolicy allow-all
        "K8S-039":  ["6.4.1"],                           # shareProcessNamespace
        "K8S-040":  ["6.4.1"],                           # procMount: Unmasked
        "K8S-041":  ["6.4.1"],                           # Service externalIPs
        "K8S-042":  ["7.2.1", "7.2.5"],                  # anonymous RoleBinding
        "K8S-043":  ["6.4.1"],                           # Ingress wildcard host
        # S3-000 visibility gap, same audit-log precedent
        "S3-000":   ["10.2.1"],
        # supply-chain posture pack
        "GHA-097":  ["6.4.3", "6.5.1"],                   # recursive PR auto-merge loop
        "GHA-098":  ["6.3.1", "6.4.3"],                   # deploy without security scan gate
        "GHA-099":  ["8.2.1", "6.5.1"],                   # deploy env plaintext secret
        "GHA-100":  ["6.5.1", "6.3.3"],                   # cosign verify no identity binding
        "GHA-102":  ["6.4.1", "6.5.1"],                   # submodule checkout on PR trigger
        "GHA-103":  ["6.4.1", "6.5.1"],                  # AI review bot on untrusted trigger
        "GHA-104":  ["6.4.1", "6.5.1"],                  # AI agent auto-push without PR review
        "GL-036":   ["8.2.1", "10.3.2"],                  # secret echoed to GitLab CI log
        "GL-038":   ["8.2.1", "10.3.2"],                  # CI_DEBUG_TRACE dumps secrets to GitLab CI log
        "BB-032":   ["8.2.1", "10.3.2"],                  # secret echoed to Bitbucket log
        "ADO-031":  ["8.2.1", "10.3.2"],                  # secret echoed to Azure DevOps log
        "ADO-032":  ["8.2.1", "10.3.2"],                  # checkout persistCredentials leaks token to .git/config
        "CC-032":   ["8.2.1", "10.3.2"],                  # secret echoed to CircleCI log
        "SCM-048":  ["7.2.5", "8.2.1"],                   # org codespace secrets scoped to all repos
        "SCM-049":  ["7.2.5", "8.2.1"],                   # classic PAT used where fine-grained suffices
        "ORG-001":  ["8.2.1", "7.2.5"],                   # org governance: 2FA not required org-wide
        "ORG-002":  ["7.2.1", "7.2.5"],                   # org governance: default member permission too broad
        "NPM-012":  ["8.2.1", "6.5.1"],                   # publish token missing restrictions
        # ── Azure Cloud (Entra ID / Storage / Key Vault / ACR / Monitor) ──
        "ENTRA-001": ["7.2.1", "7.2.5"],                  # SP assigned Global Administrator
        "ENTRA-002": ["8.2.1"],                            # app credential beyond 180 days
        "ENTRA-003": ["8.2.1"],                            # SP uses password credential
        "AZST-001":  ["7.2.5"],                            # public blob access
        "AZST-002":  ["6.5.1"],                            # non-HTTPS traffic
        "AZST-003":  ["10.3.2"],                           # no CMK encryption
        "AKV-001":   ["6.5.1"],                            # soft delete not enabled
        "AKV-002":   ["6.5.1"],                            # purge protection not enabled
        "AKV-003":   ["7.2.5"],                            # network ACLs allow all
        "ACR-001":   ["7.2.1", "8.2.2"],                   # admin user enabled
        "ACR-002":   ["7.2.5"],                            # public network access
        "ACR-003":   ["6.5.1", "10.3.2"],                  # content trust not enabled
        "AZMON-001": ["10.2.1"],                           # no diagnostic setting
        "AZMON-002": ["10.2.1", "10.3.3"],                 # log retention < 365 days
        "AZMON-003": ["10.2.1"],                           # no alert rule
        # ── GCP (IAM / GCS / KMS / Artifact Registry / Cloud Logging) ────
        "GCIAM-001": ["7.2.1", "7.2.5"],                   # SA has Owner/Editor role
        "GCIAM-002": ["8.2.1"],                            # user-managed SA key
        "GCIAM-003": ["7.2.1", "7.2.5"],                   # token creator without condition
        "GCS-001":   ["7.2.5"],                            # public bucket
        "GCS-002":   ["7.2.5"],                            # no uniform access
        "GCS-003":   ["10.3.2"],                           # versioning not enabled
        "GCKMS-001": ["10.3.2"],                           # key rotation > 365 days
        "GCKMS-002": ["7.2.5"],                            # public KMS key access
        "GCKMS-003": ["10.3.2"],                           # no HSM protection
        "GAR-001":   ["6.3.1", "6.3.3"],                   # no vulnerability scanning
        "GAR-002":   ["7.2.5"],                            # publicly readable repo
        "GAR-003":   ["6.5.1"],                            # no cleanup policy
        "GCLOG-001": ["10.2.1"],                           # audit logs not enabled
        "GCLOG-002": ["10.2.1", "10.3.3"],                 # no log sink
        "GCLOG-003": ["10.2.1", "10.3.3"],                 # log retention < 365 days
        # ── Azure Cloud phase-2 ──────────────────────────────────────
        "ENTRA-004": ["7.2.1", "8.2.1"],                   # cond access MFA
        "ENTRA-005": ["7.2.1", "7.2.2"],                   # ext user restrict
        "ENTRA-006": ["10.2.1"],                            # risky signin
        "AZST-004":  ["6.5.1"],                             # min TLS
        "AZST-005":  ["6.5.1"],                             # lifecycle
        "AZST-006":  ["8.2.1"],                             # key rotation
        "AKV-004":   ["8.2.1"],                             # key expiry
        "AKV-005":   ["8.2.1"],                             # secret expiry
        "AKV-006":   ["7.2.1", "7.2.5"],                   # RBAC
        "ACR-004":   ["6.3.1", "6.3.3"],                   # defender scan
        "ACR-005":   ["6.5.1", "10.3.2"],                  # tag immutability
        "AZMON-004": ["10.2.1"],                            # KV diagnostics
        "AZMON-005": ["10.2.1", "10.3.3"],                 # NSG flow retention
        "AZMON-006": ["10.2.1", "10.3.3"],                 # LAW retention
        "AZMON-007": ["10.2.1"],                            # svc health alert
        "AZNW-001":  ["6.4.1"],                             # SSH/RDP internet (CRITICAL)
        "AZNW-002":  ["10.2.1"],                            # flow logs
        "AZNW-003":  ["6.4.1"],                             # WAF
        "AZNW-004":  ["6.4.1"],                             # deny-all
        "AZNW-005":  ["6.4.1"],                             # public IP VM
        "AZAPP-001": ["6.5.1"],                             # HTTPS
        "AZAPP-002": ["6.5.1"],                             # TLS
        "AZAPP-003": ["7.2.5", "8.2.1"],                   # managed identity
        "AZAPP-004": ["6.4.1"],                             # remote debug
        "AZAPP-005": ["6.4.1"],                             # FTP
        "AZSQL-001": ["10.3.2"],                            # TDE CMK
        "AZSQL-002": ["10.2.1"],                            # auditing
        "AZSQL-003": ["6.4.1"],                             # public access
        "AZSQL-004": ["7.2.1", "8.2.1"],                   # AAD admin
        "AZSQL-005": ["6.3.1"],                             # threat detect
        "AZVM-001":  ["10.3.2"],                            # disk encrypt
        "AZVM-002":  ["6.4.1"],                             # public IP
        "AZVM-003":  ["6.4.1"],                             # JIT
        "AZVM-004":  ["6.3.3"],                             # OS patch
        "AZVM-005":  ["7.2.5", "8.2.1"],                   # managed identity
        # ── GCP phase-2 ──────────────────────────────────────────────
        "GCIAM-004": ["7.2.1", "7.2.5"],                   # default SA
        "GCIAM-005": ["7.2.1"],                             # domain restrict
        "GCIAM-006": ["8.2.1"],                             # SA key age
        "GCS-004":   ["10.3.2"],                            # CMEK
        "GCS-005":   ["10.2.1"],                            # access logging
        "GCLOG-004": ["10.2.1"],                            # VPC flow logs
        "GCLOG-005": ["10.2.1"],                            # firewall logging
        "GCLOG-006": ["10.2.1"],                            # data access
        "GCLOG-007": ["10.2.1"],                            # metric filter IAM
        "GCLOG-008": ["10.2.1"],                            # metric filter firewall
        "GCLOG-009": ["10.2.1"],                            # metric filter route
        "GCLOG-010": ["10.2.1"],                            # metric filter SQL
        "GCLOG-011": ["10.2.1"],                            # metric filter custom role
        "GCNET-001": ["6.4.1"],                             # default network
        "GCNET-002": ["6.4.1"],                             # deny-all
        "GCNET-003": ["6.4.1"],                             # SSH/RDP (CRITICAL)
        "GCNET-004": ["6.4.1"],                             # private access
        "GCNET-005": ["6.4.1"],                             # Cloud NAT
        "GCCE-001":  ["6.5.1"],                             # shielded VM
        "GCCE-002":  ["7.2.1", "8.2.1"],                   # OS Login
        "GCCE-003":  ["6.4.1"],                             # serial port
        "GCCE-004":  ["6.4.1"],                             # public IP
        "GCCE-005":  ["6.4.1"],                             # project SSH keys
        "GCSQL-001": ["6.4.1"],                             # public IP
        "GCSQL-002": ["6.5.1"],                             # backups
        "GCSQL-003": ["6.5.1"],                             # SSL
        "GCSQL-004": ["7.2.1", "8.2.1"],                   # IAM auth
        "GCSQL-005": ["6.5.1"],                             # PITR
        "GCRUN-001": ["7.2.5"],                             # unauth
        "GCRUN-002": ["7.2.5", "8.2.1"],                   # custom SA
        "GCRUN-003": ["6.5.1"],                             # min instances
        "GCRUN-004": ["6.4.1"],                             # VPC connector
        "GCKMS-004": ["7.2.1", "7.2.5"],                   # keyring IAM
        "GCKMS-005": ["6.5.1"],                             # destroy sched
        "GCKMS-006": ["10.3.2"],                            # imported key
        # Developer-environment auto-execution
        "DEV-001":   ["6.5.1"],
        "DEV-006":   ["6.5.1"],
        "DEV-007":   ["6.5.1"],   # committed MCP config auto-launches a command server
        "DEV-002":   ["6.5.1"],
        "DEV-003":   ["6.5.1"],
        "DEV-004":   ["6.3.3", "6.5.1"],
        "DEV-005":   ["6.5.1"],
    },
)
