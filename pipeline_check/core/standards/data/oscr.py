"""OSC&R. Open Software Supply Chain Attack Reference (pbom-dev/OSCAR).

OSC&R mirrors the MITRE ATT&CK matrix structure but focuses exclusively
on software supply chain attacks: 12 tactics (Reconnaissance through
Impact), 86 techniques.  The matrix is maintained at
``github.com/pbom-dev/OSCAR``; technique names and tactic groupings
follow ``matrix.json`` in that repo.

OSC&R does not assign numeric technique IDs.  The control IDs below
use a ``<tactic-abbreviation>-<sequence>`` scheme minted by this
project (not upstream), following the technique order in
``matrix.json``.  The tactic abbreviations are:

    REC   Reconnaissance          PE    Privilege Escalation
    RD    Resource Development    DE    Defense Evasion
    IA    Initial Access          CA    Credential Access
    EX    Execution               LM    Lateral Movement
    PER   Persistence             COL   Collection
    EXF   Exfiltration            IMP   Impact

Many OSC&R techniques describe attacker-side actions (e.g. "Forge
developer reputation") that a CI/CD configuration scanner cannot
detect directly.  Those controls appear in the catalog with no
check mappings; the generated doc page renders "No checks currently
evidence this control" so the operator sees the coverage gap.  The
scanner's value is strongest in the Initial Access, Execution,
Persistence, Credential Access, and Defense Evasion tactics where
pipeline configuration state is the primary defensive surface.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="oscr",
    title="OSC&R (Open Software Supply Chain Attack Reference)",
    version="2024",
    url="https://pbom.dev/",
    controls={
        # ── Reconnaissance ────────────────────────────────────────
        "REC-1":  "Discover naming conventions",
        "REC-2":  "Scan public CI/CD configurations for secrets and vulnerable actions",
        "REC-3":  "Discover technology stacks",
        "REC-4":  "Active scanning",
        "REC-5":  "Discover used open-source dependencies",
        "REC-6":  "Scan public artifacts for secrets",
        "REC-7":  "Discover internal artifact names",
        "REC-8":  "Discover coding flaws",
        "REC-9":  "Accidental public disclosure of internal resources",
        "REC-10": "Scan configuration on public resources",
        # ── Resource Development ──────────────────────────────────
        "RD-1":  "Malicious code contribution to an open-source repository",
        "RD-2":  "Accounts in public registry",
        "RD-3":  "Publish malicious artifact",
        "RD-4":  "Forge developer reputation",
        "RD-5":  "Compromised legitimate artifact",
        "RD-6":  "Advertise malicious artifact",
        # ── Initial Access ────────────────────────────────────────
        "IA-1":  "Combosquatting",
        "IA-2":  "Malicious IDE extension",
        "IA-3":  "External user accounts",
        "IA-4":  "Services / servers compromise",
        "IA-5":  "Vulnerable CI/CD system",
        "IA-6":  "Exposed storage",
        "IA-7":  "Malicious module injection",
        "IA-8":  "Exposed webhook",
        "IA-9":  "Compromised token",
        "IA-10": "Vulnerable CI/CD plugins",
        "IA-11": "Vulnerable CI/CD template",
        "IA-12": "Exposed internal API",
        "IA-13": "Vulnerability in third-party dependency",
        "IA-14": "Compromised developer workstation",
        "IA-15": "Exposed database",
        "IA-16": "Compromised service account",
        "IA-17": "Dependency confusion",
        "IA-18": "Permissive network access",
        "IA-19": "Repojacking",
        "IA-20": "Compromised user account",
        "IA-21": "Typosquatting",
        "IA-22": "Weak authentication methods",
        "IA-23": "Brandjacking",
        "IA-24": "Shadow IT",
        # ── Execution ─────────────────────────────────────────────
        "EX-1":  "Installation scripts",
        "EX-2":  "Runtime logic bomb",
        "EX-3":  "IDE",
        "EX-4":  "Runtime backdoor",
        "EX-5":  "Package manager",
        "EX-6":  "Command injection",
        "EX-7":  "SQL injection",
        "EX-8":  "Cross-site scripting",
        "EX-9":  "Malicious artifact execution",
        "EX-10": "Cloud workload",
        "EX-11": "Auto merge rules in SCM",
        "EX-12": "Trigger pipeline execution",
        # ── Persistence ───────────────────────────────────────────
        "PER-1": "Recursive PR",
        "PER-2": "Deploy keys",
        "PER-3": "Backdoor in code",
        "PER-4": "Add user",
        "PER-5": "Untagged resources",
        "PER-6": "Scheduled task / job on self-hosted runner",
        "PER-7": "Implant in zombie instance",
        "PER-8": "Create access token",
        # ── Privilege Escalation ──────────────────────────────────
        "PE-1":  "Inject malicious dependency to privileged user repository",
        "PE-2":  "Runners / agents running with high user privileges",
        # ── Defense Evasion ───────────────────────────────────────
        "DE-1":  "Bypass review using admin permission",
        "DE-2":  "SaaS sprawl",
        "DE-3":  "Misconfigured audit log settings",
        "DE-4":  "Misconfiguration of security measures",
        "DE-5":  "Malicious compiler / interpreter",
        "DE-6":  "Misconfigured traffic log settings",
        # ── Credential Access ─────────────────────────────────────
        "CA-1":  "Passwords in application logs",
        "CA-2":  "Dumping credentials from files",
        "CA-3":  "Harvest secrets from logs",
        "CA-4":  "Dumping short-lived token",
        "CA-5":  "Dump tokens from environment variable",
        "CA-6":  "Passwords in CI/CD logs",
        "CA-7":  "Runtime leakage of password",
        "CA-8":  "Steal credentials in container artifacts",
        # ── Lateral Movement ──────────────────────────────────────
        "LM-1":  "Push implants across repositories",
        "LM-2":  "Overprivileged user account",
        # ── Collection ────────────────────────────────────────────
        "COL-1": "Unencrypted data in transit",
        "COL-2": "Unencrypted data at rest",
        # ── Exfiltration ──────────────────────────────────────────
        "EXF-1": "Bypass of outbound traffic control",
        "EXF-2": "Source code",
        "EXF-3": "Webhook",
        # ── Impact ────────────────────────────────────────────────
        "IMP-1": "Delete repositories for DoS",
        "IMP-2": "Resource hijacking",
        "IMP-3": "Misconfiguration of serverless workloads",
    },
    mappings={
        # ================================================================
        # Reconnaissance
        # ================================================================
        # REC-2: Scan public CI/CD configurations for secrets
        #   Hardcoded secrets in CI config are the attacker's target.
        "GHA-008":  ["REC-2", "CA-6"],
        "GL-008":   ["REC-2", "CA-6"],
        "DEV-008":   ["REC-2", "CA-6"],   # literal secret in a devenv config
        "BB-008":   ["REC-2", "CA-6"],
        "ADO-008":  ["REC-2", "CA-6"],
        "JF-008":   ["REC-2", "CA-6"],
        "CC-008":   ["REC-2", "CA-6"],
        "GCB-012":  ["REC-2", "CA-6"],
        "BK-002":   ["REC-2", "CA-6"],
        "TKN-005":  ["REC-2", "CA-6"],
        "ARGO-006": ["REC-2", "CA-6"],
        "DR-004":   ["REC-2", "CA-6"],
        "GHA-039":  ["REC-2", "CA-6"],
        "TF-002":   ["REC-2", "CA-2"],
        "CF-002":   ["REC-2", "CA-2"],
        # REC-6: Scan public artifacts for secrets
        "DF-006":   ["REC-6", "CA-8"],
        "DF-019":   ["REC-6", "CA-8"],
        "DF-020":   ["REC-6", "CA-8"],
        "DF-025":   ["REC-6", "CA-8"],
        "K8S-017":  ["REC-6", "CA-8"],
        "K8S-018":  ["REC-6", "CA-8"],
        "K8S-037":  ["REC-6", "CA-8"],
        "NPM-011":  ["REC-6", "CA-8"],
        "NPM-013":  ["REC-6", "CA-8"],
        "NUGET-010": ["REC-6", "CA-8"],
        # REC-10: Scan configuration on public resources
        "SCM-026":  ["REC-10", "EXF-3"],
        "SCM-016":  ["REC-10"],
        # ================================================================
        # Resource Development
        # ================================================================
        # RD-1: Malicious code contribution
        #   Branch protection gaps that allow unauthorized merges.
        "SCM-001":  ["RD-1"],
        "SCM-002":  ["RD-1", "DE-1"],
        "SCM-010":  ["RD-1", "DE-1"],
        "SCM-017":  ["RD-1"],
        "SCM-011":  ["RD-1", "DE-1"],
        "SCM-012":  ["RD-1"],
        # RD-3: Publish malicious artifact
        #   Cooldown gates detect freshly-published packages before trust
        #   has been established.
        "NPM-008":  ["RD-3", "IA-13"],
        "PYPI-008": ["RD-3", "IA-13"],
        "MVN-008":  ["RD-3", "IA-13"],
        "NUGET-008": ["RD-3", "IA-13"],
        # RD-4: Forge developer reputation
        "GHA-041":  ["RD-4"],
        "GHA-042":  ["RD-4"],
        "GHA-043":  ["RD-4"],
        "GHA-047":  ["RD-4"],
        # RD-5: Compromised legitimate artifact
        "GHA-040":  ["RD-5", "IA-10"],
        "GHA-096":  ["RD-5", "IA-10"],
        "NPM-006":  ["RD-5", "IA-13"],
        "PYPI-006": ["RD-5", "IA-13"],
        "MVN-006":  ["RD-5", "IA-13"],
        "NUGET-005": ["RD-5", "IA-13"],
        "COMPOSER-007": ["RD-5", "IA-13"],
        "GEM-006": ["RD-5", "IA-13"],
        # ================================================================
        # Initial Access
        # ================================================================
        # IA-1: Combosquatting (name impersonation)
        "GHA-088":  ["IA-1", "IA-21", "IA-23"],
        # IA-3: External user accounts
        "SCM-027":  ["IA-3", "LM-2"],
        # IA-4: Services / servers compromise
        "GHA-012":  ["IA-4", "PER-6"],
        "GHA-105":  ["IA-4", "PER-6"],
        "GL-014":   ["IA-4", "PER-6"],
        "BB-016":   ["IA-4", "PER-6"],
        "ADO-013":  ["IA-4", "PER-6"],
        "CC-010":   ["IA-4", "PER-6"],
        # IA-5: Vulnerable CI/CD system
        "GHA-068":  ["IA-5"],
        "GHA-015":  ["IA-5"],
        "GL-015":   ["IA-5"],
        "BB-005":   ["IA-5"],
        "ADO-015":  ["IA-5"],
        "JF-015":   ["IA-5"],
        "CC-015":   ["IA-5"],
        "BK-006":   ["IA-5"],
        "TKN-006":  ["IA-5"],
        "ARGO-007": ["IA-5"],
        # IA-6: Exposed storage
        "S3-001":   ["IA-6", "COL-2"],
        "S3-002":   ["IA-6", "COL-2"],
        "S3-003":   ["IA-6", "COL-2"],
        "ECR-003":  ["IA-6"],
        # IA-8: Exposed webhook
        # (SCM-026 already mapped above under REC-10)
        # IA-9: Compromised token
        "GHA-005":  ["IA-9"],
        "GL-013":   ["IA-9"],
        "BB-011":   ["IA-9"],
        "ADO-014":  ["IA-9"],
        "JF-004":   ["IA-9", "CA-6"],
        "CC-019":   ["IA-9"],
        "JF-010":   ["IA-9"],
        "IAM-007":  ["IA-9"],
        "GHA-019":  ["IA-9", "CA-5", "EXF-2"],
        "GHA-037":  ["IA-9", "CA-5"],
        "GHA-054":  ["IA-9", "CA-5"],
        "GL-020":   ["IA-9", "CA-5"],
        "BB-017":   ["IA-9", "CA-5"],
        "CB-001":   ["IA-9", "CA-2"],
        "CB-006":   ["IA-9"],
        "GCB-003":  ["IA-9", "CA-2"],
        "GCB-018":  ["IA-9", "CA-2"],
        # IA-10: Vulnerable CI/CD plugins
        #   (GHA-040 / GHA-096 already mapped under RD-5)
        "GHA-016":  ["IA-10", "EX-1"],
        "GL-016":   ["IA-10", "EX-1"],
        "BB-012":   ["IA-10", "EX-1"],
        "ADO-016":  ["IA-10", "EX-1"],
        "JF-016":   ["IA-10", "EX-1"],
        "CC-016":   ["IA-10", "EX-1"],
        "BK-004":   ["IA-10", "EX-1"],
        "GCB-010":  ["IA-10", "EX-1"],
        "DF-004":   ["IA-10", "EX-1"],
        # IA-11: Vulnerable CI/CD template
        "GHA-001":  ["IA-11"],
        "GHA-025":  ["IA-11"],
        "GL-005":   ["IA-11"],
        "GL-042":   ["IA-11"],
        "BB-001":   ["IA-11"],
        "ADO-001":  ["IA-11"],
        "ADO-025":  ["IA-11"],
        "JF-001":   ["IA-11"],
        "CC-001":   ["IA-11"],
        "BK-001":   ["IA-11"],
        "GCB-001":  ["IA-11"],
        "GCB-004":  ["IA-11"],
        "GL-001":   ["IA-11"],
        "GL-009":   ["IA-11"],
        "BB-009":   ["IA-11"],
        "ADO-005":  ["IA-11"],
        "ADO-009":  ["IA-11"],
        "JF-009":   ["IA-11"],
        "CC-003":   ["IA-11"],
        "CC-029":   ["IA-11"],
        "GHA-051":  ["IA-11"],
        "GL-028":   ["IA-11"],
        "BB-029":   ["IA-11"],
        "TKN-001":  ["IA-11"],
        "TKN-016": ["IA-11"],  # remote resolver / bundle task body not pinned
        "ARGO-001": ["IA-11"],
        "DR-001":   ["IA-11"],
        "DR-005":   ["IA-11"],
        "DF-001":   ["IA-11"],
        "MODEL-001": ["IA-11"],   # unpinned base model
        "MODEL-002": ["IA-11"],   # third-party hub base model
        "MODEL-003": ["IA-11"],   # local unverified weights blob
        "MODEL-004": ["IA-11"],   # remote LoRA adapter
        "DF-031":   ["IA-11"],
        "GHA-089":  ["IA-11"],
        "GHA-094":  ["IA-11"],
        "GHA-095":  ["IA-11"],
        "GHA-090":  ["IA-11", "IA-19"],
        # IA-13: Vulnerability in third-party dependency
        #   OSV advisory rules + vuln-scanning-missing rules.
        #   (cooldown + compromised-package rules already mapped via RD-3/RD-5)
        "NPM-010":  ["IA-13"],
        "PYPI-009": ["IA-13"],
        "MVN-009":  ["IA-13"],
        "NUGET-009": ["IA-13"],
        "GHA-020":  ["IA-13"],
        "GL-019":   ["IA-13"],
        "BB-015":   ["IA-13"],
        "ADO-020":  ["IA-13"],
        "JF-020":   ["IA-13"],
        "CC-020":   ["IA-13"],
        "GCB-008":  ["IA-13"],
        "ECR-001":  ["IA-13"],
        "ECR-007":  ["IA-13"],
        "BK-012":   ["IA-13"],
        "TKN-012":  ["IA-13"],
        "ARGO-012": ["IA-13"],
        "GHA-059":  ["IA-13"],
        "GHA-060":  ["IA-13"],
        "GL-034":   ["IA-13"],
        "GL-035":   ["IA-13"],
        "BB-030":   ["IA-13"],
        "BB-031":   ["IA-13"],
        # IA-16: Compromised service account
        "IAM-001":  ["IA-16", "LM-2"],
        "IAM-002":  ["IA-16", "LM-2"],
        "IAM-003":  ["IA-16"],
        "IAM-004":  ["IA-16", "LM-2"],
        "IAM-005":  ["IA-16"],
        "IAM-006":  ["IA-16", "LM-2"],
        "IAM-008":  ["IA-16"],
        "IAM-009":  ["IA-16"],
        "IAM-010":  ["IA-16"],
        "GCB-020":  ["IA-16"],
        # IA-17: Dependency confusion
        "PYPI-005": ["IA-17"],
        "PYPI-017": ["IA-17"],  # remote --find-links
        "PYPI-016": ["IA-17"],  # primary index repointed
        "NUGET-007": ["IA-17"],
        "NPM-003":  ["IA-17"],
        "CA-002":   ["IA-17"],
        "MVN-007":  ["IA-17"],
        # IA-18: Permissive network access
        "K8S-032":  ["IA-18"],
        "K8S-038":  ["IA-18"],
        "K8S-026":  ["IA-18"],
        "K8S-027":  ["IA-18", "COL-1"],
        "PBAC-001": ["IA-18"],
        "TF-003":   ["IA-18"],
        "CF-003":   ["IA-18"],
        # IA-19: Repojacking
        "GHA-091":  ["IA-19"],
        #   (GHA-090 already mapped above under IA-11)
        # IA-20: Compromised user account
        "SCM-025":  ["IA-20", "PER-2"],
        "SCM-020":  ["IA-20", "LM-2"],
        "GHA-034":  ["IA-20"],
        # IA-22: Weak authentication methods
        "GHA-030":  ["IA-22"],
        "GL-031":   ["IA-22"],
        "GL-040":   ["IA-22"],# CI_JOB_TOKEN used for cross-project access
        "GL-041":   ["EX-6"],# IaC apply on an untrusted MR trigger
        "BB-028":   ["IA-22"],
        "ADO-029":  ["IA-22"],
        "CC-031":   ["IA-22"],
        "GHA-050":  ["IA-22"],
        "GHA-062":  ["IA-22"],
        "GHA-069":  ["IA-22", "CA-4"],
        # IA-24: Shadow IT (uncontrolled third-party integrations)
        "SCM-022":  ["IA-24", "DE-2"],
        "GHA-018":  ["IA-24"],
        # ================================================================
        # Execution
        # ================================================================
        # EX-1: Installation scripts
        #   (curl-pipe rules already mapped under IA-10)
        "NPM-004":  ["EX-1"],
        "DF-024":   ["EX-1"],
        "DF-022":   ["EX-1"],
        "NPM-007":  ["EX-1"],
        # EX-6: Command injection (script injection in CI/CD)
        "GHA-003":  ["EX-6"],
        "GHA-119":  ["EX-6"],# untrusted context into an agentic AI CLI
        "GHA-120":  ["EX-6"],# trust_remote_code model load = code exec
        "GHA-122":  ["EX-6"],# unsafe pickle deser of fetched artifact = code exec
        "GHA-117":  ["EX-6"],# IaC apply on untrusted PR trigger
        "GHA-118":  ["EX-6"],# untrusted content into $GITHUB_ENV / $GITHUB_PATH
        "GHA-002":  ["EX-6", "PE-1"],
        "GL-002":   ["EX-6"],
        "GL-045":   ["EX-6"],# trust_remote_code model load = code exec
        "GL-047":   ["EX-6"],# unsafe pickle deser of fetched artifact = code exec
        "GL-048":   ["EX-6"],# untrusted MR context into agentic CLI = prompt injection
        "GL-049":   ["DE-1"],# agentic CLI output lands without review
        "BB-002":   ["EX-6"],
        "ADO-002":  ["EX-6"],
        "JF-002":   ["EX-6"],
        "CC-002":   ["EX-6"],
        "BK-003":   ["EX-6"],
        "TKN-003":  ["EX-6"],
        "ARGO-005": ["EX-6"],
        "ARGO-017": ["EX-6"],
        "DR-003":   ["EX-6"],
        "GCB-019":  ["EX-6"],
        "GCB-022":  ["EX-6"],
        "GCB-023":  ["EX-6"],
        "GHA-035":  ["EX-6"],
        "GHA-036":  ["EX-6"],
        "GHA-053":  ["EX-6"],
        "GHA-064":  ["EX-6"],
        "GHA-063":  ["EX-6"],
        "GL-032":   ["EX-6"],
        "GL-033":   ["EX-6"],
        "ADO-030":  ["EX-6"],
        "JF-032":   ["EX-6"],
        "BK-015":   ["EX-6"],
        "DR-011":   ["EX-6"],
        "TKN-015":  ["EX-6"],
        "GHA-028":  ["EX-6"],
        "GL-026":   ["EX-6"],
        "BB-026":   ["EX-6"],
        "ADO-027":  ["EX-6"],
        "JF-030":   ["EX-6"],
        "CC-027":   ["EX-6"],
        "GCB-006":  ["EX-6"],
        "DF-005":   ["EX-6"],
        "GHA-031":  ["EX-6"],
        "GHA-038":  ["EX-6", "DE-4"],
        # Taint engine (cross-step/cross-job injection flows)
        "TAINT-001": ["EX-6"],
        "TAINT-002": ["EX-6"],
        "TAINT-003": ["EX-6"],
        "TAINT-004": ["EX-6"],
        "TAINT-005": ["EX-6"],
        "TAINT-006": ["EX-6"],
        "TAINT-007": ["EX-6"],
        "TAINT-008": ["EX-6"],
        "TAINT-009": ["CA-5"],                 # env-protected secret flows to unprotected job
        # EX-9: Malicious artifact execution
        "GHA-009":  ["EX-9"],
        "JF-013":   ["EX-9"],
        "GL-010":   ["EX-9"],
        "BB-010":   ["EX-9"],
        "ADO-010":  ["EX-9"],
        # EX-11: Auto merge rules in SCM
        "SCM-031":  ["EX-11", "PER-1"],
        "SCM-021":  ["EX-11"],
        # EX-12: Trigger pipeline execution
        "GHA-010":  ["EX-12"],
        "GHA-013":  ["EX-12"],
        "GHA-044":  ["EX-12", "PE-1"],
        "GHA-045":  ["EX-12", "PE-1"],
        "GHA-046":  ["EX-12", "PE-1"],
        "GHA-032":  ["EX-12"],
        "GL-011":   ["EX-12"],
        "ADO-019":  ["EX-12"],
        "JF-019":   ["EX-12"],
        "JF-012":   ["EX-12"],
        "CC-012":   ["EX-12"],
        "GHA-058":  ["EX-12"],
        "GHA-071":  ["EX-12"],
        # ================================================================
        # Persistence
        # ================================================================
        # PER-1: Recursive PR
        #   (SCM-031 already mapped above under EX-11)
        "GHA-048":  ["PER-1", "PER-3"],
        # PER-2: Deploy keys
        #   (SCM-025 already mapped above under IA-20)
        # PER-3: Backdoor in code
        "GHA-056":  ["PER-3"],
        "GHA-049":  ["PER-3", "LM-1"],
        "GHA-065":  ["PER-3"],
        # PER-4: Add user
        "SCM-030":  ["PER-4", "DE-1"],
        # PER-6: Scheduled task/job on self-hosted runner
        #   (self-hosted runner rules already mapped under IA-4)
        "JF-014":   ["PER-6"],
        # PER-8: Create access token
        "GHA-061":  ["PER-8", "LM-2"],
        "GHA-106":  ["PER-8", "LM-2"],                   # AI agent with write-scoped token
        "GHA-111":  ["PER-8", "LM-2"],  # AI agent edits IaC applied in the same job
        "GHA-112":  ["DE-1", "PER-6"],  # self-hosted deploy with no environment gate
        "GHA-113":  ["IA-22"],  # OIDC trusted-publish w/o env gate
        "GHA-114":  ["IA-22"],  # publish workflow on an unrestricted push trigger
        "GHA-115":  ["IA-22", "CA-4"],  # id-token granted workflow-wide, not job-scoped
        "GHA-116":  ["IA-20"],  # bulk secrets serialization
        "GHA-055":  ["PER-8", "CA-5"],
        "CP-004":   ["PER-8", "IA-9"],
        # ================================================================
        # Privilege Escalation
        # ================================================================
        # PE-1: Inject malicious dependency to privileged user repository
        #   (GHA-002/044/045/046 already mapped under EX-6/EX-12)
        "GHA-092":  ["PE-1"],
        # PE-2: Runners / agents running with high user privileges
        "GHA-017":  ["PE-2"],
        "GL-017":   ["PE-2"],
        "GL-039":   ["PE-2"],# dind daemon TLS disabled / exposed on 2375
        "BB-013":   ["PE-2"],
        "ADO-017":  ["PE-2"],
        "JF-017":   ["PE-2"],
        "CC-017":   ["PE-2"],
        "GCB-021":  ["PE-2"],
        "K8S-003":  ["PE-2"],
        "K8S-004":  ["PE-2"],
        "K8S-005":  ["PE-2"],
        "K8S-035":  ["PE-2"],
        "TKN-002":  ["PE-2"],
        "TKN-004":  ["PE-2"],
        "TKN-013":  ["PE-2"],
        "ARGO-002": ["PE-2"],
        "ARGO-004": ["PE-2"],
        "DR-002":   ["PE-2"],
        "DR-007":   ["PE-2"],
        "BK-005":   ["PE-2"],
        "GHA-026":  ["PE-2"],
        "GHA-107":  ["PE-2"],   # harden-runner in audit mode (egress not blocked)
        "GHA-108":  ["PE-2"],   # no runtime egress control on OIDC/deploy workflow
        "GHA-109":  ["PE-2"],   # harden-runner not the first step
        "DF-008":   ["PE-2"],
        "DF-012":   ["PE-2"],
        "DF-002":   ["PE-2"],
        "JF-025":   ["PE-2"],
        "JF-003":   ["PE-2"],
        "CC-014":   ["PE-2"],
        "K8S-006":  ["PE-2"],
        "K8S-039":  ["PE-2"],
        "K8S-040":  ["PE-2"],
        # ================================================================
        # Defense Evasion
        # ================================================================
        # DE-1: Bypass review using admin permission
        #   (SCM-002/010/011/030 already mapped above)
        "SCM-018":  ["DE-1"],
        "SCM-029":  ["DE-1", "DE-4"],
        "SCM-044":  ["DE-1"],
        "SCM-032":  ["DE-1"],
        # DE-3: Misconfigured audit log settings
        "CT-001":   ["DE-3"],
        "CT-002":   ["DE-3"],
        "CT-003":   ["DE-3"],
        "CWL-001":  ["DE-3"],
        "SCM-045":  ["DE-3"],
        "SCM-046":  ["DE-3"],
        "SCM-047":  ["DE-3"],
        "SCM-003":  ["DE-3"],
        "GCB-014":  ["DE-3"],
        "JF-011":   ["DE-3"],
        "CC-011":   ["DE-3"],
        "CB-003":   ["DE-3"],
        "S3-004":   ["DE-3"],
        "GCB-025":  ["DE-3"],
        "GHA-087":  ["DE-3", "CA-6"],
        # DE-4: Misconfiguration of security measures
        #   (GHA-038 already mapped under EX-6, DE-4 added there)
        #   (SCM-029 already mapped above)
        "SCM-033":  ["DE-4"],
        "SCM-034":  ["DE-4"],
        "SCM-035":  ["DE-4"],
        "SCM-036":  ["DE-4"],
        "SCM-037":  ["DE-4"],
        "SCM-038":  ["DE-4"],
        "SCM-039":  ["DE-4"],
        "SCM-040":  ["DE-4"],
        "SCM-041":  ["DE-4"],
        "SCM-042":  ["DE-4"],
        "SCM-043":  ["DE-4"],
        "SCM-006":  ["DE-4"],
        "SCM-007":  ["DE-4", "IMP-1"],
        "SCM-008":  ["DE-4"],
        "SCM-009":  ["DE-4", "IMP-1"],
        # DE-6: Misconfigured traffic log settings
        "EB-001":   ["DE-6"],
        "CW-001":   ["DE-6"],
        # ================================================================
        # Credential Access
        # ================================================================
        # CA-1: Passwords in application logs
        "K8S-012":  ["CA-1"],
        # CA-2: Dumping credentials from files
        #   (TF-002, CF-002, CB-001, GCB-003/018 already mapped above)
        "JF-033":   ["CA-2"],
        "JF-034":   ["CA-2"],
        "SSM-001":  ["CA-2"],
        "SM-001":   ["CA-2"],
        "KMS-001":  ["CA-2"],
        "TF-001":   ["CA-2"],
        "CF-001":   ["CA-2"],
        # CA-3: Harvest secrets from logs
        "GHA-057":  ["CA-3", "EXF-1"],
        "GHA-093":  ["CA-3", "CA-6"],
        # CA-4: Dumping short-lived token
        #   (GHA-069 already mapped under IA-22)
        # CA-5: Dump tokens from environment variable
        #   (GHA-019/037/054, GL-020, BB-017 already mapped under IA-9)
        #   (GHA-055 already mapped under PER-8)
        "GHA-033":  ["CA-5", "CA-6"],
        "BB-019":   ["CA-5"],
        "GHA-072":  ["CA-5"],
        "GHA-073":  ["CA-5"],
        # CA-6: Passwords in CI/CD logs
        #   (many rules already mapped above via multi-tactic entries)
        "GCB-007":  ["CA-6"],
        "CC-005":   ["CA-6"],
        "CC-004":   ["CA-6"],
        "GHA-066":  ["CA-6", "EXF-2"],
        "GHA-067":  ["CA-6"],
        # CA-8: Steal credentials in container artifacts
        #   (DF-006/019/020/025, K8S-017/018/037, NPM-011 already mapped
        #    via REC-6)
        "DF-023":   ["CA-8"],
        "DF-030":   ["CA-8"],
        # ================================================================
        # Lateral Movement
        # ================================================================
        # LM-1: Push implants across repositories
        #   (GHA-049 already mapped under PER-3)
        # LM-2: Overprivileged user account
        #   (IAM-001/002/004/006, SCM-027, SCM-020 already mapped above)
        "GHA-004":  ["LM-2"],
        #   (GHA-061 already mapped under PER-8 with LM-2 included)
        "PBAC-002": ["LM-2"],
        "PBAC-003": ["LM-2"],
        "PBAC-005": ["LM-2"],
        "K8S-011":  ["LM-2"],
        "K8S-019":  ["LM-2"],
        "K8S-020":  ["LM-2"],
        "K8S-021":  ["LM-2"],
        "K8S-025":  ["LM-2"],
        "K8S-029":  ["LM-2"],
        "K8S-034":  ["LM-2"],
        "K8S-042":  ["LM-2"],
        "ARGO-003": ["LM-2"],
        "ARGO-016": ["LM-2"],# cluster-admin / over-privileged ServiceAccount
        "ARGO-013": ["LM-2"],
        "TKN-007":  ["LM-2"],
        "ARGOCD-001": ["LM-2"],
        "ARGOCD-002": ["LM-2"],
        "ARGOCD-004": ["LM-2"],
        "ARGOCD-009": ["LM-2"],
        "ARGOCD-014": ["LM-2"],  # web terminal exec.enabled
        "ARGOCD-011": ["LM-2"],
        "GCB-002":  ["LM-2"],
        "CB-002":   ["LM-2", "PE-2"],
        # ================================================================
        # Collection
        # ================================================================
        # COL-1: Unencrypted data in transit (TLS bypass)
        "GHA-023":  ["COL-1"],
        "GL-023":   ["COL-1"],
        "BB-023":   ["COL-1"],
        "ADO-023":  ["COL-1"],
        "JF-023":   ["COL-1"],
        "CC-023":   ["COL-1"],
        "JF-035":   ["COL-1"],
        "BK-008":   ["COL-1"],
        "TKN-008":  ["COL-1"],
        "ARGO-008": ["COL-1"],
        "ARGO-015": ["COL-1"],
        "DR-006":   ["COL-1"],
        "GCB-011":  ["COL-1"],
        "DF-021":   ["COL-1"],
        "DF-026":   ["COL-1"],
        "DF-027":   ["COL-1"],
        "DF-028":   ["COL-1"],
        "DF-029":   ["COL-1"],
        "PYPI-003": ["COL-1"],
        "PYPI-018": ["COL-1"],  # --no-binary forces sdist build
        "MVN-003":  ["COL-1"],
        "NUGET-004": ["COL-1"],
        "HELM-003": ["COL-1"],
        "HELM-009": ["COL-1"],
        "NPM-005":  ["COL-1"],
        "GHA-070":  ["COL-1"],
        "OCI-004":  ["COL-1"],
        # COL-2: Unencrypted data at rest
        #   (S3-001/002/003 already mapped under IA-6)
        "CP-002":   ["COL-2"],
        "ECR-005":  ["COL-2"],
        "S3-005":   ["COL-2"],
        "CA-001":   ["COL-2"],
        "KMS-002":  ["COL-2"],
        "CWL-002":  ["COL-2"],
        # ================================================================
        # Exfiltration
        # ================================================================
        # EXF-1: Bypass of outbound traffic control
        #   (GHA-057 already mapped under CA-3)
        # EXF-2: Source code
        #   (GHA-066 already mapped under CA-6)
        #   (GHA-019 already mapped under IA-9 with EXF-2 included)
        # EXF-3: Webhook
        #   (SCM-026 already mapped under REC-10)
        # ================================================================
        # Impact
        # ================================================================
        # IMP-1: Delete repositories for DoS
        #   (SCM-007/009 already mapped under DE-4)
        # IMP-2: Resource hijacking
        "K8S-033":  ["IMP-2"],
        "K8S-008":  ["IMP-2"],
        "K8S-009":  ["IMP-2"],
        "K8S-010":  ["IMP-2"],
        "K8S-024":  ["IMP-2"],
        # IMP-3: Misconfiguration of serverless workloads
        "LMB-001":  ["IMP-3", "DE-4"],
        "LMB-002":  ["IMP-3"],
        "LMB-003":  ["IMP-3"],
        "LMB-004":  ["IMP-3"],
        # ================================================================
        # Signing / provenance / integrity cluster
        # These checks cut across IA (untrusted artifact) + DE (evasion
        # of integrity controls) + COL (unverifiable data).  Mapped to
        # the closest single tactic to keep the matrix clean.
        # ================================================================
        "GHA-006":  ["DE-4"],
        "GL-006":   ["DE-4"],
        "BB-006":   ["DE-4"],
        "ADO-006":  ["DE-4"],
        "JF-006":   ["DE-4"],
        "CC-006":   ["DE-4"],
        "BK-009":   ["DE-4"],
        "TKN-009":  ["DE-4"],
        "ARGO-009": ["DE-4"],
        "GCB-009":  ["DE-4"],
        "GHA-007":  ["DE-4"],
        "GL-007":   ["DE-4"],
        "BB-007":   ["DE-4"],
        "ADO-007":  ["DE-4"],
        "JF-007":   ["DE-4"],
        "CC-007":   ["DE-4"],
        "BK-010":   ["DE-4"],
        "TKN-010":  ["DE-4"],
        "ARGO-010": ["DE-4"],
        "GHA-024":  ["DE-4"],
        "GL-024":   ["DE-4"],
        "BB-024":   ["DE-4"],
        "ADO-024":  ["DE-4"],
        "JF-028":   ["DE-4"],
        "CC-024":   ["DE-4"],
        "BK-011":   ["DE-4"],
        "TKN-011":  ["DE-4"],
        "ARGO-011": ["DE-4"],
        "GCB-015":  ["DE-4"],
        "GCB-017":  ["DE-4"],
        "GCB-024":  ["DE-4"],
        "OCI-001":  ["DE-4"],
        "OCI-002":  ["DE-4"],
        "OCI-007":  ["DE-4"],
        "OCI-008":  ["DE-4"],
        "OCI-009":  ["DE-4"],
        "ATTEST-001": ["DE-4"],
        "ATTEST-002": ["DE-4"],
        "ATTEST-003": ["DE-4"],
        "ATTEST-004": ["DE-4"],
        "ATTEST-005": ["DE-4"],
        "ATTEST-006": ["DE-4"],
        "ATTEST-007": ["DE-4"],
        "SIGN-001": ["DE-4"],
        "SIGN-002": ["DE-4"],
        "DF-016":   ["DE-4"],
        "HELM-002": ["DE-4"],
        "JF-027":   ["DE-4"],
        # ================================================================
        # Lockfile / pinning / dep-update cluster
        # These checks span IA-11 (vulnerable template via floating ref)
        # + IA-13 (vulnerable dep) but the primary attacker enablement
        # is the mutable resolution window.
        # ================================================================
        "NPM-001":  ["IA-11"],
        "NPM-002":  ["IA-11"],
        "PYPI-001": ["IA-11"],
        "PYPI-002": ["IA-11"],
        "PYPI-004": ["IA-11"],
        "PYPI-015": ["IA-11"],  # direct artifact URL
        "MVN-001":  ["IA-11"],
        "MVN-002":  ["IA-11"],
        "MVN-004":  ["IA-11"],
        "MVN-005":  ["IA-11"],
        "NUGET-001": ["IA-11"],
        "NUGET-002": ["IA-11"],
        "NUGET-003": ["IA-11"],
        "NUGET-006": ["IA-11"],
        "HELM-004": ["IA-11"],
        "HELM-008": ["IA-11"],
        "GHA-021":  ["IA-11"],
        "GL-021":   ["IA-11"],
        "BB-021":   ["IA-11"],
        "ADO-021":  ["IA-11"],
        "JF-021":   ["IA-11"],
        "CC-021":   ["IA-11"],
        "DR-008":   ["IA-11"],
        "GHA-022":  ["IA-13"],
        "GL-022":   ["IA-13"],
        "BB-022":   ["IA-13"],
        "ADO-022":  ["IA-13"],
        "JF-022":   ["IA-13"],
        "CC-022":   ["IA-13"],
        # Insecure package install source
        "GHA-029":  ["IA-13"],
        "GL-027":   ["IA-13"],
        "BB-027":   ["IA-13"],
        "ADO-028":  ["IA-13"],
        "JF-031":   ["IA-13"],
        "CC-028":   ["IA-13"],
        "BK-014":   ["IA-13"],
        "TKN-014":  ["IA-13"],
        "ARGO-014": ["IA-13"],
        "DR-010":   ["IA-13"],
        # Malicious-activity indicators
        "CB-011":   ["RD-5"],
        "GL-025":   ["RD-5"],
        "BB-025":   ["RD-5"],
        "ADO-026":  ["RD-5"],
        "JF-029":   ["RD-5"],
        "CC-026":   ["RD-5"],
        # ================================================================
        # Argo CD-specific (CD-side attack surface)
        # ================================================================
        "ARGOCD-003": ["DE-4"],
        "ARGOCD-005": ["CA-2"],
        "ARGOCD-006": ["EX-12", "PE-1"],
        "ARGOCD-007": ["EX-6"],
        "ARGOCD-008": ["EX-1"],
        "ARGOCD-015": ["EX-1"],  # kustomize --enable-helm
        # ================================================================
        # Kubernetes workload-security cluster
        # ================================================================
        "K8S-002":  ["PE-2"],
        "K8S-007":  ["PE-2"],
        "K8S-013":  ["PE-2"],
        "K8S-014":  ["PE-2"],
        "K8S-015":  ["DE-4"],
        "K8S-016":  ["DE-4"],
        "K8S-022":  ["DE-4"],
        "K8S-023":  ["DE-4"],
        "K8S-044":  ["DE-4"],
        "K8S-028":  ["PE-2"],
        "K8S-030":  ["PE-2"],
        "K8S-031":  ["DE-4"],
        "K8S-036":  ["IA-11"],
        "K8S-041":  ["IA-18"],
        "K8S-043":  ["IA-18"],
        # ================================================================
        # Remaining CI/CD provider rules with clear OSC&R mapping
        # ================================================================
        # Cache poisoning
        "GHA-011":  ["EX-6"],
        "GL-012":   ["EX-6"],
        "BB-018":   ["EX-6"],
        "ADO-012":  ["EX-6"],
        "CC-025":   ["EX-6"],
        #   (BK-003 already mapped under EX-6 above)
        "DR-009":   ["EX-6"],
        "GHA-052":  ["EX-6"],
        # Approval-gate / flow-control gaps
        "GHA-014":  ["DE-1"],
        "GHA-123":  ["DE-1"],
        "GL-004":   ["DE-1"],
        "BB-004":   ["DE-1"],
        "ADO-004":  ["DE-1"],
        "JF-005":   ["DE-1"],
        "CC-009":   ["DE-1"],
        "JF-024":   ["DE-1"],
        "CP-001":   ["DE-1"],
        "CP-005":   ["DE-1"],
        "CD-001":   ["DE-1"],
        "CD-002":   ["DE-1"],
        "BK-007":   ["DE-1"],
        "BK-013":   ["DE-1"],
        "CC-013":   ["DE-1"],
        "CC-030":   ["DE-1"],
        "GHA-086":  ["DE-1"],
        "SCM-023":  ["DE-1"],
        "SCM-024":  ["DE-1"],
        "SCM-028":  ["DE-1"],
        "JF-026":   ["DE-1"],
        # Webhook / SCM config
        "GL-029":   ["DE-1"],
        # OCI / Helm / Dockerfile remaining
        "DF-003":   ["IA-11"],
        "DF-009":   ["IA-11"],
        "DF-010":   ["IA-11"],
        "OCI-003":  ["DE-4"],
        "OCI-005":  ["DE-4"],
        "OCI-006":  ["DE-4"],
        "HELM-001": ["IA-11"],
        "HELM-005": ["DE-4"],
        "HELM-006": ["DE-4"],
        "HELM-007": ["DE-4"],
        "HELM-010": ["DE-4"],
        # Remaining Dockerfile rules
        "DF-007":   ["DE-3"],
        "DF-011":   ["DE-4"],
        "DF-013":   ["IA-18"],
        "DF-014":   ["PE-2"],
        "DF-015":   ["PE-2"],
        "DF-017":   ["PE-2"],
        "DF-018":   ["PE-2"],
        # GHA deploy/env rules
        "GHA-027":  ["EX-6"],
        "GL-003":   ["CA-6"],
        "BB-003":   ["CA-6"],
        "ADO-003":  ["CA-6"],
        #   (JF-004 already mapped under IA-9 with CA-6 included)
        #   (CC-005 already mapped under CA-6 above)
        # Degraded-mode findings
        "CB-000":   ["DE-3"],
        "CP-000":   ["DE-3"],
        "CD-000":   ["DE-3"],
        "ECR-000":  ["DE-3"],
        "IAM-000":  ["DE-3"],
        "PBAC-000": ["DE-3"],
        "S3-000":   ["DE-3"],
        "CT-000":   ["DE-3"],
        "CWL-000":  ["DE-3"],
        "SM-000":   ["DE-3"],
        "CA-000":   ["DE-3"],
        "CCM-000":  ["DE-3"],
        "EB-000":   ["DE-3"],
        "LMB-000":  ["DE-3"],
        "KMS-000":  ["DE-3"],
        "SSM-000":  ["DE-3"],
        # Remaining AWS rules
        "CB-004":   ["IA-5"],
        "CB-005":   ["IA-5"],
        "CB-007":   ["EX-12"],
        "CB-008":   ["EX-12"],
        "CB-009":   ["IA-11"],
        "CB-010":   ["EX-12"],
        "CP-003":   ["EX-12"],
        "CP-007":   ["EX-12"],
        "CD-003":   ["DE-3"],
        "ECR-002":  ["IA-11"],
        "ECR-004":  ["DE-4"],
        "ECR-006":  ["IA-17"],
        "SSM-002":  ["CA-2"],
        "SM-002":   ["CA-2"],
        "CCM-001":  ["DE-1"],
        "CCM-002":  ["DE-4"],
        "CCM-003":  ["IA-6"],
        "EB-002":   ["IA-8"],
        #   (LMB-001 already mapped under IMP-3 with DE-4 included)
        "GCB-005":  ["IA-5"],
        "GCB-016":  ["PE-2"],
        "GCB-026":  ["DE-4"],
        "CA-003":   ["IA-6"],
        "CA-004":   ["LM-2"],
        "NPM-009":  ["IA-13"],
        #   (NUGET-008 already mapped under RD-3 with IA-13 included)
        # SCM remaining
        "SCM-004":  ["CA-6"],
        "SCM-005":  ["IA-13"],
        "SCM-013":  ["DE-1"],
        "SCM-014":  ["DE-1"],
        "SCM-015":  ["CA-6"],
        "SCM-019":  ["DE-1"],
        #   (DF-024 already mapped under EX-1 above)
        # ── Supply-chain posture pack ─────────────────────────────
        "GHA-097":  ["PER-1"],                     # recursive PR auto-merge loop
        "GHA-098":  ["DE-4"],                      # deploy without security scan gate
        "GHA-099":  ["CA-6"],                      # deploy env plaintext secret
        "GHA-100":  ["DE-4"],                      # cosign verify no identity binding
        "GHA-102":  ["EX-12", "PE-1"],             # submodule checkout on PR trigger
        "GHA-103":  ["EX-12"],                     # AI review bot on untrusted trigger
        "GHA-104":  ["EX-12"],                     # AI agent auto-push without PR review
        "GL-036":   ["CA-5", "CA-6"],              # secret echoed to GitLab CI log
        "GL-038":   ["CA-5", "CA-6"],              # CI_DEBUG_TRACE dumps secrets to GitLab CI log
        "BB-032":   ["CA-5", "CA-6"],              # secret echoed to Bitbucket log
        "ADO-031":  ["CA-5", "CA-6"],              # secret echoed to Azure DevOps log
        "ADO-032":  ["CA-5", "CA-6"],              # checkout persistCredentials leaks token to .git/config
        "CC-032":   ["CA-5", "CA-6"],              # secret echoed to CircleCI log
        "SCM-048":  ["CA-5"],                      # org codespace secrets scoped to all repos
        "SCM-049":  ["IA-9"],                      # classic PAT where fine-grained suffices
        "NPM-012":  ["IA-9"],                      # publish token lacking restrictions
    },
)
