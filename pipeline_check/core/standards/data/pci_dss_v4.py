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
        "GHA-002":  ["6.5.1"],                           # pull_request_target + PR head
        "GHA-003":  ["6.5.1"],                           # script injection
        "GHA-004":  ["7.2.5"],                           # unrestricted GITHUB_TOKEN
        "GHA-005":  ["8.2.1"],                           # long-lived AWS keys
        # GitLab CI
        "GL-001":   ["6.3.3"],
        "GL-002":   ["6.5.1"],
        "GL-003":   ["8.2.1", "6.5.1"],
        "GL-004":   ["6.4.3"],
        "GL-005":   ["6.3.3"],
        # Bitbucket Pipelines
        "BB-001":   ["6.3.3"],
        "BB-002":   ["6.5.1"],
        "BB-003":   ["8.2.1", "6.5.1"],
        "BB-004":   ["6.4.3"],
        "BB-005":   ["6.4.1"],
        # Azure DevOps Pipelines
        "ADO-001":  ["6.3.3"],
        "ADO-002":  ["6.5.1"],
        "ADO-003":  ["8.2.1", "6.5.1"],
        "ADO-004":  ["6.4.3"],
        "ADO-005":  ["6.3.3"],
        # CircleCI
        "CC-001":   ["6.3.3"],                           # orb not pinned to SHA
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
        "ARGO-004": ["6.4.1"],                           # hostPath / host namespaces
        "ARGO-005": ["6.5.1"],                           # param injection
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
    },
)
