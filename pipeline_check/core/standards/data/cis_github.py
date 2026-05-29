"""CIS GitHub Benchmark v1.0.

The CIS GitHub Benchmark is the platform-side companion to the CIS
Software Supply Chain Security Guide. It scores how a GitHub
organization or repository is configured against the Center for
Internet Security's recommended posture, branch protection, review
requirements, code-owners, scanning enablement, third-party app
governance, webhook hygiene, and so on.

Coverage scope
--------------
Pipeline-Check's SCM provider reads the GitHub REST API directly, so
the bulk of section 1.1 (Code Changes), 1.4 (Third-Party), and 1.5
(Code Risks) maps 1:1 onto ``SCM-*`` rules. Sections that require
org-admin endpoints the SCM provider does not currently scan, member
inventories, MFA enforcement at the org level, app installation lists,
are left without check mappings on purpose; the controls are listed
so the generated page is comparable to other standards' coverage
tables.

Why this is a separate standard
-------------------------------
The CIS Software Supply Chain guide (``cis_supply_chain``) is
platform-agnostic; the CIS GitHub Benchmark is GitHub-specific. They
overlap (branch protection, signed commits) but the GitHub-side
benchmark adds Actions governance, deploy keys, webhook hygiene, and
ruleset-versus-classic-protection distinctions that don't appear in
the supply-chain guide. Keep both standards: ``cis_supply_chain`` for
the abstract CI/CD trust chain, ``cis_github`` for the platform
posture audit.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="cis_github",
    title="CIS GitHub Benchmark",
    version="1.1.0",
    url="https://benchmarks.cisecurity.org/cis-benchmarks",
    controls={
        # 1.1 Code Changes
        "1.1.3":  "Ensure any change to code is approved by two strongly authenticated users",
        "1.1.4":  "Ensure previous approvals are dismissed when updates are introduced",
        "1.1.5":  "Ensure there are restrictions on who can dismiss code change reviews",
        "1.1.6":  "Ensure code owners are set for extra sensitive code or configuration",
        "1.1.7":  "Ensure code owner's review is required when a change affects owned code",
        "1.1.9":  "Ensure all checks have passed before merging new code",
        "1.1.10": "Ensure open Git branches are up to date before they can be merged",
        "1.1.11": "Ensure all open comments are resolved before merging code",
        "1.1.12": "Ensure verification of signed commits for new changes",
        "1.1.13": "Ensure linear history is required",
        "1.1.14": "Ensure branch protection rules are enforced for administrators",
        "1.1.15": "Ensure pushing/merging on default branches is restricted",
        "1.1.16": "Ensure force push is denied",
        "1.1.17": "Ensure branch deletion is denied",
        "1.1.18": "Ensure any merging of code is automatically scanned for security",
        "1.1.19": "Ensure any merging of code is automatically scanned for vulnerabilities",
        "1.1.20": "Ensure any merging of code is automatically scanned for secrets",
        # 1.2 Repository Management
        "1.2.5":  "Ensure all copies (forks) of code are tracked and accounted for",
        "1.2.6":  "Ensure all code projects are tracked for changes in dependents/dependencies",
        # 1.3 Contribution Access
        "1.3.8":  "Ensure strict base permissions are set for repositories",
        "1.3.10": "Ensure SCM administrators control contribution access (deploy keys, write)",
        # 1.4 Third-Party
        "1.4.1":  "Ensure administrator approval is required for every installed application",
        "1.4.3":  "Ensure the access granted to each installed application is limited",
        "1.4.4":  "Ensure only secured webhooks are used",
        # 1.5 Code Risks
        "1.5.1":  "Ensure scanners are in place to identify and prevent sensitive data in code",
        "1.5.2":  "Ensure scanners are in place to secure CI/CD pipeline instructions",
        "1.5.3":  "Ensure scanners are in place to secure IaC instructions",
        "1.5.4":  "Ensure scanners are in place to identify and confirm presence of vulnerabilities",
    },
    mappings={
        # ── 1.1 Code Changes ─────────────────────────────────────────
        # 1.1.3 require approving review(s)
        "SCM-002": ["1.1.3"],
        # CODEOWNERS-review missing = no owner-review AND CODEOWNERS toothless
        "SCM-011": ["1.1.3", "1.1.6", "1.1.7"],
        "SCM-014": ["1.1.3", "1.1.4"],
        "SCM-023": ["1.1.3"],                                 # deployment environment reviewers
        "SCM-032": ["1.1.3"],                                 # ruleset lacks PR review
        # 1.1.4 dismiss previous approvals on new commits
        "SCM-012": ["1.1.4"],
        "SCM-037": ["1.1.4"],
        # 1.1.5 restrict who can dismiss / bypass review
        "SCM-018": ["1.1.5"],
        "SCM-021": ["1.1.5", "1.4.1"],                        # Actions-approve = PR-authoritative installed app
        "SCM-031": ["1.1.5"],                                 # auto-merge enabled (review-bypass surface)
        # 1.1.6 CODEOWNERS file present for sensitive code
        "SCM-017": ["1.1.6", "1.1.7"],                        # no CODEOWNERS = no owner-review possible either
        # 1.1.9 status checks must pass before merge
        # required status checks AND the strict ``up-to-date`` knob ride together
        "SCM-008": ["1.1.9", "1.1.10"],
        "SCM-033": ["1.1.9"],
        "SCM-039": ["1.1.9", "1.1.18"],                       # required workflows (often SAST/SCA gates)
        # 1.1.10 branch up to date before merge (merge queue is the GitHub control)
        "SCM-042": ["1.1.10"],
        # 1.1.11 conversation resolution
        "SCM-013": ["1.1.11"],
        # 1.1.12 signed commit verification
        "SCM-006": ["1.1.12"],
        "SCM-036": ["1.1.12"],
        "SCM-043": ["1.1.12", "1.1.17"],                      # tag-side signing + history protection
        "SCM-044": ["1.1.12", "1.1.14"],                      # admin bypass on signed-commits = admin-enforcement gap
        # 1.1.13 linear history
        "SCM-038": ["1.1.13"],
        # 1.1.14 admin enforcement
        "SCM-010": ["1.1.14"],
        # bypass list defeats every rule the ruleset is supposed to enforce
        "SCM-030": [
            "1.1.12", "1.1.13", "1.1.14", "1.1.16", "1.1.17",
        ],
        # 1.1.15 restrict push / merge on default branch
        "SCM-001": ["1.1.15"],
        "SCM-019": ["1.1.15"],
        "SCM-024": ["1.1.15"],
        "SCM-029": ["1.1.15"],
        # 1.1.16 force push denied
        "SCM-007": ["1.1.16"],
        "SCM-034": ["1.1.16"],
        # 1.1.17 branch deletion denied
        "SCM-009": ["1.1.17"],
        "SCM-035": ["1.1.17"],
        # 1.1.18 security scanning gate on merge
        "SCM-003": ["1.1.18", "1.5.4"],
        "SCM-040": ["1.1.18"],
        "SCM-045": ["1.1.18", "1.5.4"],                       # limited query suite = shallow gate
        "SCM-046": ["1.1.18", "1.5.4"],                       # configured but paused = no effective gate
        "SCM-047": ["1.1.18", "1.5.4"],                       # missing language = scan blind spot
        # 1.1.19 vulnerability scanning on merge
        "SCM-005": ["1.1.19", "1.2.6", "1.5.4"],
        # 1.1.20 secret scanning on merge
        "SCM-004": ["1.1.20", "1.5.1"],
        "SCM-015": ["1.1.20", "1.5.1"],
        # 1.2.5 fork tracking
        "SCM-028": ["1.2.5"],
        # 1.3.8 strict base permissions (outside-collaborator audit)
        # outside-collab elevation also bypasses admin write control
        "SCM-027": ["1.3.8", "1.3.10"],
        # 1.3.10 deploy keys / SCM-admin controlled write
        "SCM-025": ["1.3.10"],
        # 1.4.1 / 1.4.3 third-party app / action governance
        "SCM-022": ["1.4.1", "1.4.3"],
        # 1.4.4 webhook security
        "SCM-026": ["1.4.4"],
        # 1.5.2 CI/CD pipeline-instruction security
        # The SCM rules below cover the platform's governance over what
        # Actions can do; the ``GHA-*`` half (pipeline-config scanning)
        # is captured by a representative subset that maps onto the same
        # control without forcing every workflow rule into this surface.
        "SCM-016": ["1.5.1", "1.2.6"],                        # private vuln reporting = supply-chain tracking intake
        # default workflow_token scope = installed-app access ceiling
        "SCM-020": ["1.5.2", "1.4.3"],
        "SCM-041": ["1.5.2"],                                 # ruleset deployment-env gate
        # GHA pipeline-instruction security: dangerous-workflow / token /
        # privileged-runtime patterns. Anchors of 1.5.2 evidence; the
        # full GHA pack still maps via OWASP CICD-SEC-* on every page.
        "GHA-001": ["1.5.2"],                                 # action not pinned to SHA
        "GHA-002": ["1.5.2"],                                 # pull_request_target + checkout PR head
        "GHA-003": ["1.5.2"],                                 # script injection via ${{ }}
        "GHA-004": ["1.5.2"],                                 # GITHUB_TOKEN unrestricted
        "GHA-005": ["1.5.2", "1.5.1"],                        # long-lived AWS keys in workflow
        "GHA-019": ["1.5.2"],                                 # job-level permissions broader than needed
        "GHA-038": ["1.5.2"],                                 # ACTIONS_ALLOW_UNSECURE_COMMANDS
        "GHA-040": ["1.5.2"],                                 # known-compromised action ref
        # GHA worm-mitigation + advanced-PPE pack: each rule
        # represents a CI/CD pipeline-instruction security gap that
        # 1.5.2 is designed to catch. Anchoring this subset (not the
        # full GHA pack) keeps the surface scoped to GitHub-specific
        # patterns the CIS benchmark explicitly enumerates.
        "GHA-030": ["1.5.2"],                                 # OIDC w/o env-protected job
        "GHA-031": ["1.5.2"],                                 # retired set-output / save-state
        "GHA-032": ["1.5.2"],                                 # local script on untrusted trigger
        "GHA-033": ["1.5.2", "1.5.1"],                        # secret echoed in run:
        "GHA-034": ["1.5.2"],                                 # secrets: inherit
        "GHA-035": ["1.5.2"],                                 # github-script untrusted context
        "GHA-036": ["1.5.2"],                                 # runs-on untrusted context
        "GHA-037": ["1.5.2"],                                 # checkout persists GITHUB_TOKEN
        "GHA-039": ["1.5.2", "1.5.1"],                        # services container creds literal
        "GHA-041": ["1.5.2"],                                 # single-maintainer action (reputation)
        "GHA-042": ["1.5.2"],                                 # very-young action repo
        "GHA-043": ["1.5.2"],                                 # low-star + sensitive perms
        "GHA-044": ["1.5.2"],                                 # build-tool PPE on untrusted trigger
        "GHA-045": ["1.5.2"],                                 # caller-ref input drives checkout
        "GHA-046": ["1.5.2"],                                 # manual PR-head fetch
        "GHA-047": ["1.5.2"],                                 # fresh-ref cooldown
        "GHA-048": ["1.5.2"],                                 # workflow self-mutation
        "GHA-049": ["1.5.2"],                                 # cross-repo push from CI
        "GHA-050": ["1.5.2"],                                 # long-lived registry publish token
        "GHA-051": ["1.5.2"],                                 # services / container image unpinned
        "GHA-052": ["1.5.2"],                                 # cache key untrusted-input poisoning
        "GHA-053": ["1.5.2"],                                 # if: predicate untrusted-context
        "GHA-054": ["1.5.2"],                                 # checkout ssh-key persists
        "GHA-055": ["1.5.2", "1.5.1"],                        # reusable outputs leak secret
        "GHA-056": ["1.5.2"],                                 # worm IOC strings
        "GHA-057": ["1.5.2", "1.5.1"],                        # secret-scanner output → egress
        "GHA-058": ["1.5.2"],                                 # agentic CLI permission-bypass
        "GHA-059": ["1.5.2"],                                 # npm install without audit signatures
        "GHA-060": ["1.5.2"],                                 # pip install without --require-hashes
        "GHA-061": ["1.5.2"],                                 # App token minted without permissions filter
        "GHA-106": ["1.5.2"],                                 # AI agent with write-scoped token
        "GHA-062": ["1.5.2"],                                 # OIDC trust subject in sibling IaC is overly broad
        "GHA-092": ["1.5.2"],                                 # TOCTOU PR head SHA force-push race
        "GHA-093": ["1.5.2"],                                 # LOTP indicators
        # TAINT family: cross-step / cross-job untrusted-data flow
        # into privileged sinks is the canonical pipeline-instruction
        # security failure the 1.5.2 scanner is meant to find.
        "TAINT-001": ["1.5.2"],
        "TAINT-002": ["1.5.2"],
        "TAINT-003": ["1.5.2"],
        "TAINT-004": ["1.5.2"],
        "TAINT-005": ["1.5.2"],
        "TAINT-006": ["1.5.2"],
        "TAINT-007": ["1.5.2"],
        "TAINT-008": ["1.5.2"],
        # Dockerfile / IaC scanning, 1.5.3
        "DF-001":  ["1.5.3"],                                 # FROM image not digest-pinned
        "DF-005":  ["1.5.3"],                                 # shell-eval pattern
        "DF-006":  ["1.5.3", "1.5.1"],                        # ENV credential literal
        "DF-008":  ["1.5.3"],                                 # docker --privileged
        "DF-019":  ["1.5.3", "1.5.1"],                        # COPY credential file
        "DF-020":  ["1.5.3", "1.5.1"],                        # credential ARG
        "DF-021":  ["1.5.3"],                                 # pip TLS bypass / http index
        "DF-024":  ["1.5.3"],                                 # npm install runs lifecycle scripts
        "DF-026":  ["1.5.3"],                                 # NODE_TLS_REJECT_UNAUTHORIZED=0
        "DF-027":  ["1.5.3"],                                 # PYTHONHTTPSVERIFY=0
        "DF-028":  ["1.5.3"],                                 # GIT_SSL_NO_VERIFY=1
        "DF-029":  ["1.5.3"],                                 # REQUESTS_CA_BUNDLE neutered
        "K8S-001": ["1.5.3"],                                 # image not pinned in manifest
        "K8S-002": ["1.5.3"],                                 # privileged container
        "K8S-005": ["1.5.3"],                                 # privileged container (securityContext)
        "K8S-013": ["1.5.3"],                                 # hostPath volume
        "K8S-017": ["1.5.3", "1.5.1"],                        # env credential literal
        "K8S-018": ["1.5.3", "1.5.1"],                        # Secret carries plaintext
        "K8S-037": ["1.5.3", "1.5.1"],                        # ConfigMap credential
        "TF-001":  ["1.5.3"],                                 # aws_iam_access_key long-lived
        "TF-002":  ["1.5.3", "1.5.1"],                        # hard-coded secret in TF resource attr
        "TF-003":  ["1.5.3"],                                 # CodeBuild VPC public subnet
        "CF-001":  ["1.5.3"],                                 # inline credential in CFN
        "CF-002":  ["1.5.3", "1.5.1"],                        # hard-coded secret in CFN property
        "CF-003":  ["1.5.3"],                                 # CodeBuild VPC public subnet
        # Vulnerability scanning, 1.5.4 (registry + workflow side)
        "ECR-001": ["1.5.4"],                                 # ECR scan-on-push disabled
        "ECR-007": ["1.5.4"],                                 # Inspector v2 enhanced scanning
        "GHA-020": ["1.5.4"],                                 # workflow lacks vulnerability scan
    },
)
