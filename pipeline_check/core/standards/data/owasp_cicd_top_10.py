"""OWASP Top 10 CI/CD Security Risks (2022)."""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="owasp_cicd_top_10",
    title="OWASP Top 10 CI/CD Security Risks",
    version="2022",
    url="https://owasp.org/www-project-top-10-ci-cd-security-risks/",
    controls={
        "CICD-SEC-1":  "Insufficient Flow Control Mechanisms",
        "CICD-SEC-2":  "Inadequate Identity and Access Management",
        "CICD-SEC-3":  "Dependency Chain Abuse",
        "CICD-SEC-4":  "Poisoned Pipeline Execution",
        "CICD-SEC-5":  "Insufficient PBAC",
        "CICD-SEC-6":  "Insufficient Credential Hygiene",
        "CICD-SEC-7":  "Insecure System Configuration",
        "CICD-SEC-8":  "Ungoverned Usage of 3rd-Party Services",
        "CICD-SEC-9":  "Improper Artifact Integrity Validation",
        "CICD-SEC-10": "Insufficient Logging and Visibility",
    },
    mappings={
        # Degraded-mode findings (API access failures).
        "CB-000":   ["CICD-SEC-10"],
        "CP-000":   ["CICD-SEC-10"],
        "CD-000":   ["CICD-SEC-10"],
        "ECR-000":  ["CICD-SEC-10"],
        "IAM-000":  ["CICD-SEC-10"],
        "PBAC-000": ["CICD-SEC-10"],
        "S3-000":   ["CICD-SEC-10"],
        # CodeBuild
        "CB-001":   ["CICD-SEC-6"],
        "CB-002":   ["CICD-SEC-7"],
        "CB-003":   ["CICD-SEC-10"],
        "CB-004":   ["CICD-SEC-7"],
        "CB-005":   ["CICD-SEC-7"],
        "CB-006":   ["CICD-SEC-6"],
        "CB-007":   ["CICD-SEC-1"],
        "CB-008":   ["CICD-SEC-4"],
        "CB-009":   ["CICD-SEC-3"],
        "CB-010":   ["CICD-SEC-4"],
        "CB-011":   ["CICD-SEC-4", "CICD-SEC-7"],
        # CodePipeline
        "CP-001":   ["CICD-SEC-1"],
        "CP-002":   ["CICD-SEC-9"],
        "CP-003":   ["CICD-SEC-4"],
        "CP-004":   ["CICD-SEC-6"],
        # CodeDeploy
        "CD-001":   ["CICD-SEC-1"],
        "CD-002":   ["CICD-SEC-1"],
        "CD-003":   ["CICD-SEC-10"],
        # ECR
        "ECR-001":  ["CICD-SEC-3"],
        "ECR-002":  ["CICD-SEC-9"],
        "ECR-003":  ["CICD-SEC-8"],
        "ECR-004":  ["CICD-SEC-7"],
        "ECR-005":  ["CICD-SEC-9"],
        # IAM
        "IAM-001":  ["CICD-SEC-2"],
        "IAM-002":  ["CICD-SEC-2"],
        "IAM-003":  ["CICD-SEC-2"],
        "IAM-004":  ["CICD-SEC-2"],
        "IAM-005":  ["CICD-SEC-2"],
        "IAM-006":  ["CICD-SEC-2"],
        "IAM-007":  ["CICD-SEC-6"],
        "IAM-008":  ["CICD-SEC-2"],
        # CloudTrail
        "CT-000":   ["CICD-SEC-10"],
        "CT-001":   ["CICD-SEC-10"],
        "CT-002":   ["CICD-SEC-10"],
        "CT-003":   ["CICD-SEC-10"],
        # CloudWatch Logs
        "CWL-000":  ["CICD-SEC-10"],
        "CWL-001":  ["CICD-SEC-10"],
        "CWL-002":  ["CICD-SEC-9"],
        # Secrets Manager
        "SM-000":   ["CICD-SEC-10"],
        "SM-001":   ["CICD-SEC-6"],
        "SM-002":   ["CICD-SEC-8"],
        # CodeArtifact
        "CA-000":   ["CICD-SEC-10"],
        "CA-001":   ["CICD-SEC-9"],
        "CA-002":   ["CICD-SEC-3"],
        "CA-003":   ["CICD-SEC-8"],
        "CA-004":   ["CICD-SEC-2"],
        # CodeCommit (CCM- prefix, avoids CC-* collision with CircleCI)
        "CCM-000":  ["CICD-SEC-10"],
        "CCM-001":  ["CICD-SEC-1"],
        "CCM-002":  ["CICD-SEC-9"],
        "CCM-003":  ["CICD-SEC-8"],
        # Lambda
        "LMB-000":  ["CICD-SEC-10"],
        "LMB-001":  ["CICD-SEC-9"],
        "LMB-002":  ["CICD-SEC-8"],
        "LMB-003":  ["CICD-SEC-6"],
        "LMB-004":  ["CICD-SEC-8"],
        # KMS
        "KMS-000":  ["CICD-SEC-10"],
        "KMS-001":  ["CICD-SEC-6"],
        "KMS-002":  ["CICD-SEC-2"],
        # SSM Parameter Store
        "SSM-000":  ["CICD-SEC-10"],
        "SSM-001":  ["CICD-SEC-6"],
        "SSM-002":  ["CICD-SEC-9"],
        # Phase-3 deeper detections
        "CP-005":   ["CICD-SEC-1"],
        "CP-007":   ["CICD-SEC-4"],
        "PBAC-003": ["CICD-SEC-5"],
        "PBAC-005": ["CICD-SEC-5"],
        "ECR-006":  ["CICD-SEC-3"],
        "ECR-007":  ["CICD-SEC-3"],
        "SIGN-001": ["CICD-SEC-9"],
        "SIGN-002": ["CICD-SEC-9"],
        "EB-000":   ["CICD-SEC-10"],
        "EB-001":   ["CICD-SEC-10"],
        "EB-002":   ["CICD-SEC-8"],
        "CW-001":   ["CICD-SEC-10"],
        # Terraform-native (no AWS runtime analogue)
        "TF-001":   ["CICD-SEC-6"],
        "TF-002":   ["CICD-SEC-6"],
        "TF-003":   ["CICD-SEC-7"],
        # CloudFormation-native (no AWS runtime analogue)
        "CF-001":   ["CICD-SEC-6"],
        "CF-002":   ["CICD-SEC-6"],
        "CF-003":   ["CICD-SEC-7"],
        # PBAC
        "PBAC-001": ["CICD-SEC-5"],
        "PBAC-002": ["CICD-SEC-5"],
        # S3
        "S3-001":   ["CICD-SEC-9"],
        "S3-002":   ["CICD-SEC-9"],
        "S3-003":   ["CICD-SEC-9"],
        "S3-004":   ["CICD-SEC-10"],
        "S3-005":   ["CICD-SEC-9"],
        # GitHub Actions
        "GHA-001":  ["CICD-SEC-3"],
        "GHA-002":  ["CICD-SEC-4"],
        "GHA-003":  ["CICD-SEC-4"],
        "GHA-004":  ["CICD-SEC-5"],
        "GHA-005":  ["CICD-SEC-6"],
        "GHA-006":  ["CICD-SEC-9"],
        "GHA-007":  ["CICD-SEC-9"],
        "GHA-008":  ["CICD-SEC-6"],
        "GHA-009":  ["CICD-SEC-4"],
        "GHA-010":  ["CICD-SEC-4"],
        "GHA-011":  ["CICD-SEC-4"],
        "GHA-012":  ["CICD-SEC-7"],
        "GHA-013":  ["CICD-SEC-4"],
        "GHA-014":  ["CICD-SEC-1"],
        "GHA-015":  ["CICD-SEC-7"],
        "GHA-016":  ["CICD-SEC-3"],
        "GHA-017":  ["CICD-SEC-7"],
        "GHA-018":  ["CICD-SEC-3"],
        "GHA-019":  ["CICD-SEC-6"],
        "GHA-020":  ["CICD-SEC-3"],
        "GHA-021":  ["CICD-SEC-3"],
        "GHA-022":  ["CICD-SEC-3"],
        "GHA-023":  ["CICD-SEC-3"],
        "GHA-024":  ["CICD-SEC-9"],
        "GHA-025":  ["CICD-SEC-3"],
        "GHA-026":  ["CICD-SEC-7"],
        "GHA-027":  ["CICD-SEC-4", "CICD-SEC-7"],
        "GHA-028":  ["CICD-SEC-4"],
        "GHA-029":  ["CICD-SEC-3"],
        "GHA-030":  ["CICD-SEC-2"],   # OIDC without environment gate
        "GHA-031":  ["CICD-SEC-4"],   # retired set-output / save-state
        "GHA-032":  ["CICD-SEC-4"],   # local-script invocation on untrusted trigger
        "GHA-033":  ["CICD-SEC-6"],   # secret echoed in run:
        "GHA-034":  ["CICD-SEC-2", "CICD-SEC-6"],  # secrets: inherit
        "GHA-035":  ["CICD-SEC-4"],   # github-script injection
        "GHA-036":  ["CICD-SEC-7"],   # runs-on interpolates untrusted context
        # GitLab CI
        "GL-001":   ["CICD-SEC-3"],
        "GL-002":   ["CICD-SEC-4"],
        "GL-003":   ["CICD-SEC-6"],
        "GL-004":   ["CICD-SEC-1"],
        "GL-005":   ["CICD-SEC-3"],
        "GL-006":   ["CICD-SEC-9"],
        "GL-007":   ["CICD-SEC-9"],
        "GL-008":   ["CICD-SEC-6"],
        "GL-009":   ["CICD-SEC-3"],
        "GL-010":   ["CICD-SEC-4"],
        "GL-011":   ["CICD-SEC-4"],
        "GL-012":   ["CICD-SEC-4"],
        "GL-013":   ["CICD-SEC-6"],
        "GL-014":   ["CICD-SEC-7"],
        "GL-015":   ["CICD-SEC-7"],
        "GL-016":   ["CICD-SEC-3"],
        "GL-017":   ["CICD-SEC-7"],
        "GL-018":   ["CICD-SEC-3"],
        "GL-019":   ["CICD-SEC-3"],
        "GL-020":   ["CICD-SEC-6"],
        "GL-021":   ["CICD-SEC-3"],
        "GL-022":   ["CICD-SEC-3"],
        "GL-023":   ["CICD-SEC-3"],
        "GL-024":   ["CICD-SEC-9"],
        "GL-025":   ["CICD-SEC-4", "CICD-SEC-7"],
        "GL-026":   ["CICD-SEC-4"],
        "GL-027":   ["CICD-SEC-3"],
        "GL-028":   ["CICD-SEC-3"],
        "GL-029":   ["CICD-SEC-1"],
        "GL-030":   ["CICD-SEC-3"],
        "GL-031":   ["CICD-SEC-2"],   # id_tokens missing audience pin / env binding
        "GL-032":   ["CICD-SEC-7"],   # tags interpolates untrusted CI variable
        # Bitbucket Pipelines
        "BB-001":   ["CICD-SEC-3"],
        "BB-002":   ["CICD-SEC-4"],
        "BB-003":   ["CICD-SEC-6"],
        "BB-004":   ["CICD-SEC-1"],
        "BB-005":   ["CICD-SEC-7"],
        "BB-006":   ["CICD-SEC-9"],
        "BB-007":   ["CICD-SEC-9"],
        "BB-008":   ["CICD-SEC-6"],
        "BB-009":   ["CICD-SEC-3"],
        "BB-010":   ["CICD-SEC-4"],
        "BB-011":   ["CICD-SEC-6"],
        "BB-012":   ["CICD-SEC-3"],
        "BB-013":   ["CICD-SEC-7"],
        "BB-014":   ["CICD-SEC-3"],
        "BB-015":   ["CICD-SEC-3"],
        "BB-016":   ["CICD-SEC-7"],
        "BB-017":   ["CICD-SEC-6"],
        "BB-018":   ["CICD-SEC-4"],
        "BB-019":   ["CICD-SEC-6"],
        "BB-020":   ["CICD-SEC-7"],
        "BB-021":   ["CICD-SEC-3"],
        "BB-022":   ["CICD-SEC-3"],
        "BB-023":   ["CICD-SEC-3"],
        "BB-024":   ["CICD-SEC-9"],
        "BB-025":   ["CICD-SEC-4", "CICD-SEC-7"],
        "BB-026":   ["CICD-SEC-4"],
        "BB-027":   ["CICD-SEC-3"],
        "BB-028":   ["CICD-SEC-2"],   # OIDC without deployment-gated environment
        "BB-029":   ["CICD-SEC-3"],   # step+service image pinning
        # Azure DevOps Pipelines
        "ADO-001":  ["CICD-SEC-3"],
        "ADO-002":  ["CICD-SEC-4"],
        "ADO-003":  ["CICD-SEC-6"],
        "ADO-004":  ["CICD-SEC-1"],
        "ADO-005":  ["CICD-SEC-3"],
        "ADO-006":  ["CICD-SEC-9"],
        "ADO-007":  ["CICD-SEC-9"],
        "ADO-008":  ["CICD-SEC-6"],
        "ADO-009":  ["CICD-SEC-3"],
        "ADO-010":  ["CICD-SEC-4"],
        "ADO-011":  ["CICD-SEC-4"],
        "ADO-012":  ["CICD-SEC-4"],
        "ADO-013":  ["CICD-SEC-7"],
        "ADO-014":  ["CICD-SEC-6"],
        "ADO-015":  ["CICD-SEC-7"],
        "ADO-016":  ["CICD-SEC-3"],
        "ADO-017":  ["CICD-SEC-7"],
        "ADO-018":  ["CICD-SEC-3"],
        "ADO-019":  ["CICD-SEC-4"],
        "ADO-020":  ["CICD-SEC-3"],
        "ADO-021":  ["CICD-SEC-3"],
        "ADO-022":  ["CICD-SEC-3"],
        "ADO-023":  ["CICD-SEC-3"],
        "ADO-024":  ["CICD-SEC-9"],
        "ADO-025":  ["CICD-SEC-3"],
        "ADO-026":  ["CICD-SEC-4", "CICD-SEC-7"],
        "ADO-027":  ["CICD-SEC-4"],
        "ADO-028":  ["CICD-SEC-3"],
        "ADO-029":  ["CICD-SEC-2"],   # service-connection job without env gate
        "ADO-030":  ["CICD-SEC-7"],   # pool interpolates attacker-controllable value
        # Jenkins
        "JF-001":   ["CICD-SEC-3"],
        "JF-002":   ["CICD-SEC-4"],
        "JF-003":   ["CICD-SEC-5"],
        "JF-004":   ["CICD-SEC-6"],
        "JF-005":   ["CICD-SEC-1"],
        "JF-006":   ["CICD-SEC-9"],
        "JF-007":   ["CICD-SEC-9"],
        "JF-008":   ["CICD-SEC-6"],
        "JF-009":   ["CICD-SEC-3"],
        "JF-010":   ["CICD-SEC-6"],
        "JF-011":   ["CICD-SEC-10"],
        "JF-012":   ["CICD-SEC-3"],
        "JF-013":   ["CICD-SEC-4"],
        "JF-014":   ["CICD-SEC-7"],
        "JF-015":   ["CICD-SEC-7"],
        "JF-016":   ["CICD-SEC-3"],
        "JF-017":   ["CICD-SEC-7"],
        "JF-018":   ["CICD-SEC-3"],
        "JF-019":   ["CICD-SEC-4"],
        "JF-020":   ["CICD-SEC-3"],
        "JF-021":   ["CICD-SEC-3"],
        "JF-022":   ["CICD-SEC-3"],
        "JF-023":   ["CICD-SEC-3"],
        "JF-024":   ["CICD-SEC-1"],
        "JF-025":   ["CICD-SEC-7"],
        "JF-026":   ["CICD-SEC-4"],
        "JF-027":   ["CICD-SEC-9"],
        "JF-028":   ["CICD-SEC-9"],
        "JF-029":   ["CICD-SEC-4", "CICD-SEC-7"],
        "JF-030":   ["CICD-SEC-4"],
        "JF-031":   ["CICD-SEC-3"],
        "JF-032":   ["CICD-SEC-7"],   # agent label interpolates untrusted ref
        # CircleCI
        "CC-001":   ["CICD-SEC-3"],
        "CC-002":   ["CICD-SEC-4"],
        "CC-003":   ["CICD-SEC-3"],
        "CC-004":   ["CICD-SEC-6"],
        "CC-005":   ["CICD-SEC-6"],
        "CC-006":   ["CICD-SEC-9"],
        "CC-007":   ["CICD-SEC-9"],
        "CC-008":   ["CICD-SEC-6"],
        "CC-009":   ["CICD-SEC-1"],
        "CC-010":   ["CICD-SEC-7"],
        "CC-011":   ["CICD-SEC-10"],
        "CC-012":   ["CICD-SEC-4"],
        "CC-013":   ["CICD-SEC-1"],
        "CC-014":   ["CICD-SEC-5"],
        "CC-015":   ["CICD-SEC-7"],
        "CC-016":   ["CICD-SEC-3"],
        "CC-017":   ["CICD-SEC-7"],
        "CC-018":   ["CICD-SEC-3"],
        "CC-019":   ["CICD-SEC-6"],
        "CC-020":   ["CICD-SEC-3"],
        "CC-021":   ["CICD-SEC-3"],
        "CC-022":   ["CICD-SEC-3"],
        "CC-023":   ["CICD-SEC-3"],
        "CC-024":   ["CICD-SEC-9"],
        "CC-025":   ["CICD-SEC-4"],
        "CC-026":   ["CICD-SEC-4", "CICD-SEC-7"],
        "CC-027":   ["CICD-SEC-4"],
        "CC-028":   ["CICD-SEC-3"],
        "CC-029":   ["CICD-SEC-3"],
        "CC-030":   ["CICD-SEC-6"],
        "CC-031":   ["CICD-SEC-2"],   # OIDC role assumption without branch / approval gate
        # Google Cloud Build
        "GCB-001":  ["CICD-SEC-3"],
        "GCB-002":  ["CICD-SEC-2"],
        "GCB-003":  ["CICD-SEC-6"],
        "GCB-004":  ["CICD-SEC-4"],
        "GCB-005":  ["CICD-SEC-7"],
        "GCB-006":  ["CICD-SEC-4"],
        "GCB-007":  ["CICD-SEC-6"],
        "GCB-008":  ["CICD-SEC-3"],
        "GCB-009":  ["CICD-SEC-9"],
        "GCB-010":  ["CICD-SEC-3"],   # remote script via curl-pipe
        "GCB-011":  ["CICD-SEC-3"],   # TLS bypass
        "GCB-012":  ["CICD-SEC-6"],   # literal secret in YAML
        "GCB-013":  ["CICD-SEC-3"],   # package source integrity
        "GCB-014":  ["CICD-SEC-10"],  # logging disabled
        "GCB-015":  ["CICD-SEC-9"],   # no SBOM
        "GCB-016":  ["CICD-SEC-4", "CICD-SEC-7"],   # dir path escape
        "GCB-017":  ["CICD-SEC-3", "CICD-SEC-9", "CICD-SEC-10"],  # no SLSA provenance
        "GCB-018":  ["CICD-SEC-6"],   # legacy KMS secrets block
        "GCB-019":  ["CICD-SEC-4"],   # shell entrypoint + user substitution
        "GCB-020":  ["CICD-SEC-2"],   # default Cloud Build SA email
        "GCB-021":  ["CICD-SEC-7"],   # no private worker pool
        "GCB-022":  ["CICD-SEC-4"],   # substitutionOption ALLOW_LOOSE
        "GCB-023":  ["CICD-SEC-4"],   # undeclared user substitution
        "GCB-024":  ["CICD-SEC-9"],   # images: missing despite docker push
        "GCB-025":  ["CICD-SEC-10"],  # tags: empty (audit/discoverability)
        "GCB-026":  ["CICD-SEC-4"],   # waitFor references unknown id
        # Kubernetes manifests
        "K8S-001":  ["CICD-SEC-3"],
        "K8S-002":  ["CICD-SEC-7"],
        "K8S-003":  ["CICD-SEC-7"],
        "K8S-004":  ["CICD-SEC-7"],
        "K8S-005":  ["CICD-SEC-7"],
        "K8S-006":  ["CICD-SEC-7"],
        "K8S-007":  ["CICD-SEC-7"],
        "K8S-008":  ["CICD-SEC-7"],
        "K8S-009":  ["CICD-SEC-7"],
        "K8S-010":  ["CICD-SEC-7"],
        "K8S-011":  ["CICD-SEC-2"],
        "K8S-012":  ["CICD-SEC-2", "CICD-SEC-6"],
        "K8S-013":  ["CICD-SEC-7"],
        "K8S-014":  ["CICD-SEC-7"],
        "K8S-015":  ["CICD-SEC-7"],
        "K8S-016":  ["CICD-SEC-7"],
        "K8S-017":  ["CICD-SEC-6"],
        "K8S-018":  ["CICD-SEC-6"],
        "K8S-019":  ["CICD-SEC-2"],
        "K8S-020":  ["CICD-SEC-2", "CICD-SEC-5"],
        "K8S-021":  ["CICD-SEC-2", "CICD-SEC-5"],
        "K8S-022":  ["CICD-SEC-7"],
        "K8S-023":  ["CICD-SEC-7"],   # PSA enforce label missing
        "K8S-024":  ["CICD-SEC-7", "CICD-SEC-10"],  # missing health probes
        "K8S-025":  ["CICD-SEC-2", "CICD-SEC-5", "CICD-SEC-7"],  # system-* priority class
        "K8S-026":  ["CICD-SEC-7"],   # LB without source ranges
        "K8S-027":  ["CICD-SEC-7"],   # Ingress without TLS
        "K8S-028":  ["CICD-SEC-7"],   # container hostPort
        "K8S-029":  ["CICD-SEC-2", "CICD-SEC-5"],  # default-SA binding
        "K8S-030":  ["CICD-SEC-7"],   # control-plane scheduling
        "K8S-031":  ["CICD-SEC-7"],   # PSA warn label missing
        "K8S-032":  ["CICD-SEC-7"],   # NetworkPolicy default-deny missing
        "K8S-033":  ["CICD-SEC-7"],   # ResourceQuota / LimitRange missing
        "K8S-034":  ["CICD-SEC-2"],   # ServiceAccount automount default
        "K8S-035":  ["CICD-SEC-7"],   # container runAsUser: 0
        "K8S-036":  ["CICD-SEC-3"],   # SA imagePullSecret missing
        "K8S-037":  ["CICD-SEC-6"],   # ConfigMap credential literal
        "K8S-038":  ["CICD-SEC-7"],   # NetworkPolicy allow-all
        "K8S-039":  ["CICD-SEC-7"],   # shareProcessNamespace: true
        "K8S-040":  ["CICD-SEC-7"],   # procMount: Unmasked
        # Helm chart-supply-chain
        "HELM-001": ["CICD-SEC-3"],   # legacy apiVersion: v1
        "HELM-002": ["CICD-SEC-3"],   # Chart.lock missing digests
        "HELM-003": ["CICD-SEC-3"],   # non-HTTPS dep repository
        "HELM-004": ["CICD-SEC-3"],   # dep version not exact-pinned
        "HELM-005": ["CICD-SEC-3"],   # maintainers chain-of-custody
        "HELM-006": ["CICD-SEC-3"],   # kubeVersion compat range
        "HELM-007": ["CICD-SEC-3"],   # description empty
        "HELM-008": ["CICD-SEC-3"],   # Chart.lock stale > 90 days
        "HELM-009": ["CICD-SEC-3"],   # home / sources non-HTTPS
        "HELM-010": ["CICD-SEC-3"],   # appVersion empty
        # Dockerfile
        "DF-001":   ["CICD-SEC-3"],   # FROM not digest-pinned
        "DF-002":   ["CICD-SEC-7"],   # no USER
        "DF-003":   ["CICD-SEC-3", "CICD-SEC-9"],   # ADD URL no checksum
        "DF-004":   ["CICD-SEC-3"],   # curl-pipe in RUN
        "DF-005":   ["CICD-SEC-4"],   # shell-eval idiom
        "DF-006":   ["CICD-SEC-6"],   # secret in ENV/ARG
        "DF-007":   ["CICD-SEC-10"],  # no HEALTHCHECK
        "DF-008":   ["CICD-SEC-7"],   # docker --privileged in RUN
        "DF-009":   ["CICD-SEC-3"],   # ADD where COPY suffices
        "DF-010":   ["CICD-SEC-3"],   # apt-get dist-upgrade
        "DF-011":   ["CICD-SEC-7"],   # apt cache not cleaned
        "DF-012":   ["CICD-SEC-7"],   # sudo in RUN
        "DF-013":   ["CICD-SEC-7"],   # EXPOSE 22 / remote-access port
        "DF-014":   ["CICD-SEC-7"],   # WORKDIR system path
        "DF-015":   ["CICD-SEC-7"],   # chmod 777 / world-writable
        "DF-016":   ["CICD-SEC-3", "CICD-SEC-9", "CICD-SEC-10"],   # missing OCI provenance labels
        "DF-017":   ["CICD-SEC-7"],   # ENV PATH prepends a writable dir
        "DF-018":   ["CICD-SEC-7"],   # RUN chown rewrites a system path
        "DF-019":   ["CICD-SEC-6"],   # COPY/ADD credential-shaped file
        "DF-020":   ["CICD-SEC-6"],   # ARG credential-shaped name
        # Buildkite
        "BK-001":   ["CICD-SEC-3"],   # plugin not pinned to exact version
        "BK-002":   ["CICD-SEC-6", "CICD-SEC-7"],  # literal secret in env
        "BK-003":   ["CICD-SEC-4"],   # untrusted variable interpolated
        "BK-004":   ["CICD-SEC-3", "CICD-SEC-1"],  # remote curl-pipe to shell
        "BK-005":   ["CICD-SEC-5"],   # docker --privileged / host bind
        "BK-006":   ["CICD-SEC-9"],   # missing timeout_in_minutes
        "BK-007":   ["CICD-SEC-2", "CICD-SEC-7"],  # deploy step not gated
        "BK-008":   ["CICD-SEC-3"],   # TLS verification disabled
        "BK-009":   ["CICD-SEC-9"],   # artifacts not signed
        "BK-010":   ["CICD-SEC-9"],   # SBOM not generated
        "BK-011":   ["CICD-SEC-9"],   # SLSA provenance not produced
        "BK-012":   ["CICD-SEC-9"],   # no vulnerability scanning
        "BK-013":   ["CICD-SEC-1"],   # deploy step has no branches filter
        # Tekton
        "TKN-001":  ["CICD-SEC-3"],   # step image not pinned to digest
        "TKN-002":  ["CICD-SEC-5"],   # step runs privileged / as root
        "TKN-003":  ["CICD-SEC-4", "CICD-SEC-1"],  # param injection in script
        "TKN-004":  ["CICD-SEC-5"],   # hostPath / host namespaces
        "TKN-005":  ["CICD-SEC-6", "CICD-SEC-7"],  # literal secret in env / param
        "TKN-006":  ["CICD-SEC-9"],   # no explicit timeout
        "TKN-007":  ["CICD-SEC-2"],   # default ServiceAccount
        "TKN-008":  ["CICD-SEC-3"],   # remote install / TLS bypass
        "TKN-009":  ["CICD-SEC-9"],   # artifacts not signed
        "TKN-010":  ["CICD-SEC-9"],   # SBOM not generated
        "TKN-011":  ["CICD-SEC-9"],   # SLSA provenance not produced
        "TKN-012":  ["CICD-SEC-9"],   # no vulnerability scanning
        "TKN-013":  ["CICD-SEC-5"],   # sidecar privileged / root
        # Argo Workflows
        "ARGO-001": ["CICD-SEC-3"],   # template image not digest-pinned
        "ARGO-002": ["CICD-SEC-5"],   # template privileged / root
        "ARGO-003": ["CICD-SEC-2"],   # default ServiceAccount
        "ARGO-004": ["CICD-SEC-5"],   # hostPath / host namespaces
        "ARGO-005": ["CICD-SEC-4", "CICD-SEC-1"],  # parameter injection in script
        "ARGO-006": ["CICD-SEC-6", "CICD-SEC-7"],  # literal secret in env / param
        "ARGO-007": ["CICD-SEC-9"],   # missing activeDeadlineSeconds
        "ARGO-008": ["CICD-SEC-3"],   # remote install / TLS bypass
        "ARGO-009": ["CICD-SEC-9"],   # artifacts not signed
        "ARGO-010": ["CICD-SEC-9"],   # SBOM not generated
        "ARGO-011": ["CICD-SEC-9"],   # SLSA provenance not produced
        "ARGO-012": ["CICD-SEC-9"],   # no vulnerability scanning
        "ARGO-013": ["CICD-SEC-2", "CICD-SEC-7"],  # SA token automount
        # Cross-cutting dataflow / taint engine (provider-spanning,
        # currently GHA-only in v1)
        "TAINT-001": ["CICD-SEC-4", "CICD-SEC-1"],  # cross-step taint via $GITHUB_OUTPUT
        "TAINT-002": ["CICD-SEC-4", "CICD-SEC-1"],  # cross-job taint via jobs.<id>.outputs:
        "TAINT-003": ["CICD-SEC-4", "CICD-SEC-1"],  # tainted with: forward into reusable workflow
        # Drone CI
        "DR-001":   ["CICD-SEC-3"],                 # step image not digest-pinned
        "DR-002":   ["CICD-SEC-5"],                 # step privileged
        "DR-003":   ["CICD-SEC-4", "CICD-SEC-1"],   # Drone variable injection
        "DR-004":   ["CICD-SEC-6", "CICD-SEC-7"],   # literal secret
        "DR-005":   ["CICD-SEC-3"],                 # plugin floating tag
        "DR-006":   ["CICD-SEC-3", "CICD-SEC-1"],   # TLS bypass in commands
        # OCI image manifests
        "OCI-001":  ["CICD-SEC-3", "CICD-SEC-10"],  # missing provenance annotations
        "OCI-002":  ["CICD-SEC-3", "CICD-SEC-9", "CICD-SEC-10"],  # missing build attestation
        "OCI-003":  ["CICD-SEC-3", "CICD-SEC-10"],  # missing image.created
        "OCI-004":  ["CICD-SEC-3", "CICD-SEC-9"],   # foreign-layer URL reference
        "OCI-005":  ["CICD-SEC-3", "CICD-SEC-10"],  # missing image.licenses annotation
        "OCI-006":  ["CICD-SEC-3"],                 # excessive layer count
    },
)
