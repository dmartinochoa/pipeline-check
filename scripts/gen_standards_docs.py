"""Generate per-standard reference pages from the rule + standards registry.

Replaces the old hand-maintained ``docs/standards/<name>.md`` pages
that carried just a flat ``check_id -> control`` mapping table.

Each generated page now answers, on a single visit, three questions
the original tables left dangling:

1. *What is this standard, and why would I scan against it?* ,
   page header, scope, version, URL, and a short prose blurb.
2. *Which of my controls does the scanner cover, and how strongly?*
   , per-control sections grouped by control_id, each carrying the
   list of checks that evidence it (with severity, provider,
   autofix flag, click-through to the per-rule reference page).
3. *How do I run a scan filtered to this standard?* , the
   ``--standard <slug>`` snippet inline.

Source of truth for mappings stays in
``pipeline_check/core/standards/data/<name>.py``. Source of truth
for per-check titles / severities / provider routing stays in
the rule registry under
``pipeline_check/core/checks/<provider>/rules/``. This script just
joins the two and renders Markdown.

Usage
-----
    python scripts/gen_standards_docs.py                   # all standards
    python scripts/gen_standards_docs.py owasp_cicd_top_10 # one
    python scripts/gen_standards_docs.py --check           # exit 1 if stale
"""
from __future__ import annotations

import argparse
import importlib
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

from pipeline_check.core.autofix import _FIXERS
from pipeline_check.core.checks.rule import discover_rules
from pipeline_check.core.standards.base import Standard

# --------------------------------------------------------------------------- #
# Provider registry, every package whose ``rules/`` exports ``RULE`` objects.
# Used to build the global ``check_id -> (Rule, provider_slug)`` index.
# Order is irrelevant; the index is keyed by check_id.
# --------------------------------------------------------------------------- #
_PROVIDER_PACKAGES: tuple[tuple[str, str, str], ...] = (
    # (provider_slug, package fqn, display title used in tables)
    ("github",     "pipeline_check.core.checks.github.rules",     "GitHub Actions"),
    ("gitlab",     "pipeline_check.core.checks.gitlab.rules",     "GitLab CI"),
    ("bitbucket",  "pipeline_check.core.checks.bitbucket.rules",  "Bitbucket"),
    ("azure",      "pipeline_check.core.checks.azure.rules",      "Azure DevOps"),
    ("jenkins",    "pipeline_check.core.checks.jenkins.rules",    "Jenkins"),
    ("circleci",   "pipeline_check.core.checks.circleci.rules",   "CircleCI"),
    ("cloudbuild", "pipeline_check.core.checks.cloudbuild.rules", "Cloud Build"),
    ("buildkite",  "pipeline_check.core.checks.buildkite.rules",  "Buildkite"),
    ("drone",      "pipeline_check.core.checks.drone.rules",      "Drone CI"),
    ("tekton",     "pipeline_check.core.checks.tekton.rules",     "Tekton"),
    ("argo",       "pipeline_check.core.checks.argo.rules",       "Argo Workflows"),
    ("dockerfile", "pipeline_check.core.checks.dockerfile.rules", "Dockerfile"),
    ("kubernetes", "pipeline_check.core.checks.kubernetes.rules", "Kubernetes"),
    ("helm",       "pipeline_check.core.checks.helm.rules",       "Helm"),
    ("oci",        "pipeline_check.core.checks.oci.rules",        "OCI manifest"),
    ("scm",        "pipeline_check.core.checks.scm.rules",        "SCM"),
    ("aws",        "pipeline_check.core.checks.aws.rules",        "AWS"),
    ("maven",      "pipeline_check.core.checks.maven.rules",      "maven"),
)

# --------------------------------------------------------------------------- #
# Provider docs that emit pinned per-rule anchors (`{ #gha-001 }`). Standards
# rows render the check_id as ``../providers/<slug>.md#<id-lowercase>`` for
# these and as ``../providers/<slug>.md`` (page top) for the rest.
# Kept here, not imported from ``link_standards_check_ids``, so this script
# stays standalone.
# --------------------------------------------------------------------------- #
_ANCHORED_PROVIDERS: frozenset[str] = frozenset({
    "github", "gitlab", "bitbucket", "azure", "jenkins", "circleci",
    "cloudbuild", "buildkite", "drone", "tekton", "argo", "dockerfile",
    "kubernetes", "scm", "oci", "maven",
    # AWS provider doc carries hand-written ``### CB-001: …`` headers
    # that mkdocs slugifies to anchors of shape
    # ``cb-001-secrets-in-plaintext-environment-variables``. Linking with
    # just ``#cb-001`` won't land. Treat AWS as un-anchored so the link
    # points at the page top, the per-rule sections are still alphabetised
    # so the reader scrolls a screen at most.
})

# --------------------------------------------------------------------------- #
# Fallback metadata for check_ids that have no Rule object in the registry:
#   - ``*-000`` degraded-mode AWS findings (synthesised when an API call
#     fails, all INFO, all CICD-SEC-10);
#   - the legacy class-based Terraform / CloudFormation checks
#     (TF-001..003, CF-001..003) which still live as Finding builders
#     under ``checks/terraform/`` and ``checks/cloudformation/``.
# Each entry: (title, severity, provider_slug, provider_title).
# --------------------------------------------------------------------------- #
_FALLBACK: dict[str, tuple[str, str, str, str]] = {
    # AWS degraded-mode synthetic findings
    "CA-000":   ("CodeArtifact API access failed", "INFO", "aws", "AWS"),
    "CB-000":   ("CodeBuild API access failed", "INFO", "aws", "AWS"),
    "CCM-000":  ("CodeCommit API access failed", "INFO", "aws", "AWS"),
    "CD-000":   ("CodeDeploy API access failed", "INFO", "aws", "AWS"),
    "CP-000":   ("CodePipeline API access failed", "INFO", "aws", "AWS"),
    "CT-000":   ("CloudTrail API access failed", "INFO", "aws", "AWS"),
    "CWL-000":  ("CloudWatch Logs API access failed", "INFO", "aws", "AWS"),
    "EB-000":   ("EventBridge API access failed", "INFO", "aws", "AWS"),
    "ECR-000":  ("ECR API access failed", "INFO", "aws", "AWS"),
    "IAM-000":  ("IAM API access failed", "INFO", "aws", "AWS"),
    "KMS-000":  ("KMS API access failed", "INFO", "aws", "AWS"),
    "LMB-000":  ("Lambda API access failed", "INFO", "aws", "AWS"),
    "PBAC-000": ("PBAC enumeration failed", "INFO", "aws", "AWS"),
    "S3-000":   ("S3 API access failed", "INFO", "aws", "AWS"),
    "SM-000":   ("Secrets Manager API access failed", "INFO", "aws", "AWS"),
    "SSM-000":  ("SSM Parameter Store API access failed", "INFO", "aws", "AWS"),
    # Legacy class-based Terraform / CloudFormation checks
    "TF-001":   ("aws_iam_access_key declares a long-lived access key", "CRITICAL", "terraform", "Terraform"),
    "TF-002":   ("Resource attribute carries a hard-coded secret shape", "CRITICAL", "terraform", "Terraform"),
    "TF-003":   ("CodeBuild VPC shares its VPC with a public subnet", "HIGH", "terraform", "Terraform"),
    "CF-001":   ("Inline credential parameter on a CloudFormation resource",
                 "HIGH", "cloudformation", "CloudFormation"),
    "CF-002":   ("CloudFormation parameter declares a default secret value",
                 "HIGH", "cloudformation", "CloudFormation"),
    "CF-003":   ("CloudFormation resource opens a 0.0.0.0/0 ingress",
                 "HIGH", "cloudformation", "CloudFormation"),
}


@dataclass(frozen=True, slots=True)
class _CheckRow:
    """Flat per-check view used to render the per-control tables AND the
    bottom-of-page check details section.

    The prose fields (``docs_note``, ``recommendation``, ``known_fp``,
    ``incident_refs``, ``exploit_example``) are taken straight from the
    Rule registry and rendered verbatim in the details block. For
    ``_FALLBACK`` entries (AWS degraded-mode synthesized findings and
    the legacy class-based Terraform / CloudFormation checks), the
    prose fields are empty — the details block falls back to a short
    auto-generated stub pointing at the provider page.
    """

    check_id: str
    title: str
    severity: str
    provider_slug: str
    provider_title: str
    autofix: bool
    docs_note: str = ""
    recommendation: str = ""
    known_fp: tuple[str, ...] = ()
    incident_refs: tuple[str, ...] = ()
    exploit_example: str | None = None


def _build_index() -> dict[str, _CheckRow]:
    """``check_id -> _CheckRow`` for every check the scanner ships."""
    out: dict[str, _CheckRow] = {}
    autofixable = frozenset(_FIXERS.keys())
    for slug, pkg, title in _PROVIDER_PACKAGES:
        for rule, _ in discover_rules(pkg):
            out[rule.id] = _CheckRow(
                check_id=rule.id,
                title=rule.title,
                severity=rule.severity.value,
                provider_slug=slug,
                provider_title=title,
                autofix=rule.id in autofixable,
                docs_note=rule.docs_note,
                recommendation=rule.recommendation,
                known_fp=rule.known_fp,
                incident_refs=rule.incident_refs,
                exploit_example=rule.exploit_example,
            )
    for cid, (title, severity, slug, prov_title) in _FALLBACK.items():
        if cid in out:
            continue
        out[cid] = _CheckRow(
            check_id=cid,
            title=title,
            severity=severity,
            provider_slug=slug,
            provider_title=prov_title,
            autofix=cid in autofixable,
        )
    return out


# --------------------------------------------------------------------------- #
# Per-standard hand-written prose (intro + optional footer notes). Everything
# else on the page is auto-generated from the Standard + rule index.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class _StandardConfig:
    """Per-standard knobs the data registry doesn't carry."""

    #: Markdown rendered immediately under the H1, before the auto-generated
    #: "At a glance" stats block. Holds the version line, URL, scope blurb,
    #: and the "why this standard" prose.
    intro: str
    #: Optional markdown appended after the auto-generated body. Used for
    #: "Not covered" / "Out of scope" notes that don't belong in a control
    #: section.
    footer: str = ""
    #: Optional one-line description for individual controls. Appears
    #: under the control's H3. Not every standard publishes a useful
    #: per-control narrative; for those, leave the dict empty and the
    #: control title alone carries the page.
    control_descriptions: dict[str, str] | None = None


# Description tables that supplement the one-line ``controls`` titles in the
# data files. Populated for the standards where the extra context noticeably
# helps the reader; the others fall back to the title alone, which is fine.
_OWASP_DESCRIPTIONS: dict[str, str] = {
    "CICD-SEC-1": (
        "Reviews, approvals, branch protection, and deployment gates are "
        "the brakes on the pipeline. Missing them lets a single commit, "
        "or a single API call, ship straight to production."
    ),
    "CICD-SEC-2": (
        "Long-lived static credentials, shared service accounts, and "
        "human identities reused for automation collapse the blast "
        "radius of a single compromise to the whole pipeline."
    ),
    "CICD-SEC-3": (
        "Floating tags, range constraints, and unverified registries let "
        "an upstream maintainer compromise (or a typosquat) execute in "
        "your build the next time the dependency resolves."
    ),
    "CICD-SEC-4": (
        "An attacker who can influence what a build runs, via a PR, an "
        "issue comment, or a tainted environment variable, executes "
        "with the build's secrets and write-access to your artifacts."
    ),
    "CICD-SEC-5": (
        "Build steps with deploy-class permissions, jobs sharing a single "
        "broad role, and missing environment gates each let a routine "
        "compromise escalate from build to production."
    ),
    "CICD-SEC-6": (
        "Plaintext secrets in YAML, env vars baked into image layers, or "
        "tokens echoed to logs all leak credentials before they're ever "
        "exploited; rotation only helps if the leak is detected."
    ),
    "CICD-SEC-7": (
        "Privileged containers, host mounts, root user, and disabled TLS "
        "turn a routine RCE in a build step into kernel-level access "
        "to the runner host."
    ),
    "CICD-SEC-8": (
        "Calls to external services, SaaS integrations, marketplace "
        "actions, package registries, expand the trust perimeter of "
        "the pipeline beyond what was reviewed and approved."
    ),
    "CICD-SEC-9": (
        "Without provenance, attestations, signatures, or SBOMs, "
        "consumers (including production) cannot verify that the "
        "artifact running in production is the one the pipeline built."
    ),
    "CICD-SEC-10": (
        "When the pipeline doesn't log its decisions, audits stall and "
        "incident response lacks the timeline needed to scope a "
        "compromise."
    ),
}

_SLSA_DESCRIPTIONS: dict[str, str] = {
    "Build.L1.Scripted": (
        "The build is fully scripted, no manual steps that produce "
        "artifacts. Required to make any further provenance claim "
        "meaningful."
    ),
    "Build.L1.Provenance": (
        "The build emits a signed statement describing how the artifact "
        "was produced (builder, source, parameters)."
    ),
    "Build.L2.Hosted": (
        "Builds run on a managed build platform, not a developer "
        "workstation, so build identity and configuration are platform-"
        "controlled rather than user-controlled."
    ),
    "Build.L2.Signed": (
        "Provenance is cryptographically signed by the build platform; "
        "tenants of the platform cannot forge it."
    ),
    "Build.L3.Isolated": (
        "Each build runs in a fresh environment without influence from "
        "concurrent or previous builds. No shared mutable state."
    ),
    "Build.L3.Ephemeral": (
        "Build environments are provisioned per run and torn down after, "
        "so a compromised build cannot persist into the next."
    ),
    "Build.L3.NonFalsifiable": (
        "The build platform's provenance signature is bound to inputs the "
        "tenant cannot influence (e.g. a backend-controlled identity), "
        "so a tenant-controlled compromise cannot mint forged provenance."
    ),
}


_STANDARDS: dict[str, _StandardConfig] = {
    "owasp_cicd_top_10": _StandardConfig(
        intro="""\
- **Version:** 2022
- **URL:** <https://owasp.org/www-project-top-10-ci-cd-security-risks/>
- **Source of truth:** `pipeline_check/core/standards/data/owasp_cicd_top_10.py`

The OWASP CI/CD Top 10 is the canonical risk taxonomy this scanner
organizes around. Every other compliance standard's check set is a
subset of OWASP's; the cross-standard integrity test in
`tests/test_standards.py` enforces it. If a check fails, it is
because at least one OWASP risk fires, the other 14 frameworks layer
their own labels on top of the same evidence.

Use this page when you want full coverage of the canonical CI/CD
risk model; pick a more specialized framework (NIST SSDF, SLSA, CIS
Kubernetes, …) when an audit asks for that framework's vocabulary.
""",
        control_descriptions=_OWASP_DESCRIPTIONS,
    ),
    "slsa": _StandardConfig(
        intro="""\
- **Version:** 1.0
- **URL:** <https://slsa.dev/spec/v1.0/>
- **Source of truth:** `pipeline_check/core/standards/data/slsa.py`

SLSA (Supply-chain Levels for Software Artifacts) is the framework
for measuring how trustworthy a build pipeline's outputs are. The
checks below evidence the **Build track** requirements (L1 -> L3),
which are the slice this scanner can reason about from pipeline
configuration alone.

Use this page when you need to defend "we ship SLSA L2" /
"we're working toward L3" with concrete control evidence rather than
narrative. Pair with [OpenSSF Scorecard](openssf_scorecard.md) for
project-health context and [SCM posture](../providers/scm.md) for
the source-control side of the chain.
""",
        footer="""\
## Not covered

- **Source track** (branch protection, two-reviewer enforcement,
  retained history). Scanned via the dedicated
  [SCM posture provider](../providers/scm.md) instead, which probes
  GitHub / GitLab / Bitbucket REST APIs.
- **Dependency track**. Requires package-manifest and lockfile
  analysis across the dependency graph; out of scope for a CI/CD
  configuration scan.
""",
        control_descriptions=_SLSA_DESCRIPTIONS,
    ),
    "nist_ssdf": _StandardConfig(
        intro="""\
- **Version:** SP 800-218 v1.1
- **URL:** <https://csrc.nist.gov/pubs/sp/800/218/final>
- **Source of truth:** `pipeline_check/core/standards/data/nist_ssdf.py`

NIST's Secure Software Development Framework is the federal SSDLC
reference. The scanner evidences tasks in the Prepare the Organization
(PO), Protect the Software (PS), Produce Well-Secured Software (PW),
and Respond to Vulnerabilities (RV) practice areas whose state can
be observed from CI/CD configuration.

Use this page if your compliance team or customer asks for SSDF
attestation evidence. The control IDs map straight onto SSDF's
practice notation; pair with the
[OWASP CI/CD Top 10](owasp_cicd_top_10.md) for the underlying
risk language.
""",
        footer="""\
## Not covered

Tasks requiring SCM-policy introspection (PO.1 governance, PO.2 role
assignment), human process (PW.7 code review), or incident-response
telemetry (RV.2, RV.3) sit outside what a CI/CD configuration scan
can witness.
""",
    ),
    "nist_800_53": _StandardConfig(
        intro="""\
- **Version:** Rev. 5
- **URL:** <https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final>
- **Source of truth:** `pipeline_check/core/standards/data/nist_800_53.py`

The federal control catalog. The scanner evidences the AC, AU, CM,
IA, SI, and SR family controls whose CI/CD-side state is visible
in pipeline configuration. Use this page when an authorization
package asks for 800-53 control evidence; pair with NIST SSDF for
SSDLC vocabulary.
""",
    ),
    "nist_csf_2": _StandardConfig(
        intro="""\
- **Version:** 2.0
- **URL:** <https://www.nist.gov/cyberframework>
- **Source of truth:** `pipeline_check/core/standards/data/nist_csf_2.py`

The NIST Cybersecurity Framework 2.0 organizes controls into six
functions (Govern, Identify, Protect, Detect, Respond, Recover).
This scanner evidences the Protect / Detect / Identify subset that
maps to CI/CD configuration; Govern, Respond, and Recover require
process telemetry the tool cannot witness.
""",
    ),
    "nist_800_190": _StandardConfig(
        intro="""\
- **Version:** Final
- **URL:** <https://csrc.nist.gov/pubs/sp/800/190/final>
- **Source of truth:** `pipeline_check/core/standards/data/nist_800_190.py`

NIST's Application Container Security Guide. Covers image, registry,
runtime, and host hardening for containerized workloads. The scanner
evidences the image-build and image-content half of the spec; the
runtime-host half (orchestrator hardening at the cluster level)
sits outside the scan surface.
""",
    ),
    "cis_aws_foundations": _StandardConfig(
        intro="""\
- **Version:** 5.0
- **URL:** <https://www.cisecurity.org/benchmark/amazon_web_services>
- **Source of truth:** `pipeline_check/core/standards/data/cis_aws_foundations.py`

CIS AWS Foundations Benchmark, CI/CD-relevant subset. IAM hardening,
S3 protection, KMS hygiene, and the CloudTrail / CloudWatch logging
controls the AWS provider scans against a live account.
""",
    ),
    "cis_github": _StandardConfig(
        intro="""\
- **Version:** 1.1.0
- **URL:** <https://benchmarks.cisecurity.org/cis-benchmarks>
- **Source of truth:** `pipeline_check/core/standards/data/cis_github.py`

CIS GitHub Benchmark, platform-side posture for a single GitHub
organization or repository. Sections 1.1 (Code Changes), 1.4
(Third-Party), and 1.5 (Code Risks) are evidenced directly by the
`SCM-*` rule pack, which reads the GitHub REST API; a representative
slice of `GHA-*` workflow rules anchors 1.5.2 (CI/CD pipeline
instructions).

Use this page alongside the
[CIS Software Supply Chain Guide](cis_supply_chain.md) when a GitHub
audit asks for both the platform settings and the build-chain
posture. Pair with [OpenSSF Scorecard](openssf_scorecard.md) and
[SCM provider docs](../providers/scm.md) for the underlying signals.
""",
        footer="""\
## Not covered

Org-admin controls that require account-level audit endpoints, MFA
enforcement (1.3.4), member inventories (1.3.1), installed-app lists
(1.4.2), and similar — are listed in the benchmark but not yet
evidenced by an `SCM-*` rule. Open an issue if your team would value
coverage; the GitHub Admin API surface is the next planned expansion
of the SCM provider.
""",
    ),
    "cis_kubernetes": _StandardConfig(
        intro="""\
- **Version:** 1.10
- **URL:** <https://www.cisecurity.org/benchmark/kubernetes>
- **Source of truth:** `pipeline_check/core/standards/data/cis_kubernetes.py`

CIS Kubernetes Benchmark, Section 5 (Policies). Workload security
context, RBAC blast radius, NetworkPolicy posture, Secret hygiene,
and namespace separation, anything the
[Kubernetes provider](../providers/kubernetes.md) can score from
manifests on disk. The Section 1-4 control plane / node / etcd
controls require live cluster access and are out of scope.
""",
    ),
    "cis_supply_chain": _StandardConfig(
        intro="""\
- **Version:** 1.0
- **URL:** <https://www.cisecurity.org/benchmark/software_supply_chain_security>
- **Source of truth:** `pipeline_check/core/standards/data/cis_supply_chain.py`

CIS Software Supply Chain Security Guide. Source, build, dependency,
and artifact controls covering the full pipeline trust chain.
""",
    ),
    "esf_supply_chain": _StandardConfig(
        intro="""\
- **Version:** 2022
- **URL:** <https://www.cisa.gov/sites/default/files/2023-08/ESF%20Securing%20the%20Software%20Supply%20Chain%20Recommended%20Practices%20for%20Software%20Bill%20of%20Materials%20Consumption.pdf>
- **Source of truth:** `pipeline_check/core/standards/data/esf_supply_chain.py`

NSA / CISA Enduring Security Framework, Securing the Software Supply
Chain. Three companion documents (developer, customer, supplier);
the scanner evidences controls that surface in CI/CD configuration.
""",
    ),
    "openssf_scorecard": _StandardConfig(
        intro="""\
- **Version:** 5
- **URL:** <https://github.com/ossf/scorecard/blob/main/docs/checks.md>
- **Source of truth:** `pipeline_check/core/standards/data/openssf_scorecard.py`

OpenSSF Scorecard is the open-source project health framework.
Pinned-deps, branch-protection, signing, dangerous workflows. The
scanner's checks evidence the workflow side; pair with the
[SCM posture provider](../providers/scm.md) for the repo-settings
side that Scorecard also covers.
""",
    ),
    "pci_dss_v4": _StandardConfig(
        intro="""\
- **Version:** 4.0
- **URL:** <https://www.pcisecuritystandards.org/document_library/?document=pci_dss>
- **Source of truth:** `pipeline_check/core/standards/data/pci_dss_v4.py`

Payment Card Industry Data Security Standard, CI/CD subset. Logging
discipline, secret management, change control. PCI DSS attestation
needs much more than CI/CD posture; this page is for the slice the
scanner can witness.
""",
    ),
    "s2c2f": _StandardConfig(
        intro="""\
- **Version:** 2024
- **URL:** <https://github.com/ossf/s2c2f>
- **Source of truth:** `pipeline_check/core/standards/data/s2c2f.py`

Microsoft / OpenSSF Secure Supply Chain Consumption Framework.
Ingest, inventory, scan, rebuild, fix, the consumer-side controls
for taking a third-party dependency safely.
""",
    ),
    "soc2": _StandardConfig(
        intro="""\
- **Version:** 2017 (revised 2022)
- **URL:** <https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022>
- **Source of truth:** `pipeline_check/core/standards/data/soc2.py`

SOC 2 Trust Services Criteria, CI/CD-relevant subset. Findings
evidence control gaps; they are not a substitute for an auditor's
opinion. Use this page to prepare CC6 / CC7 / CC8 evidence walks.
""",
    ),
}


# --------------------------------------------------------------------------- #
# Rendering helpers
# --------------------------------------------------------------------------- #
def _check_link(row: _CheckRow) -> str:
    """Markdown link for a check_id, anchored to the per-rule section if the
    provider doc carries pinned anchors, otherwise to the page top.

    Used in the bottom-of-page details block where the goal is to send the
    reader to the canonical provider doc for the rule's source. The
    in-page links from the per-control table go through
    :func:`_check_detail_link` instead so the reader stays on the standards
    page.
    """
    if row.provider_slug in _ANCHORED_PROVIDERS:
        anchor = row.check_id.lower()
        return f"[`{row.check_id}`](../providers/{row.provider_slug}.md#{anchor})"
    return f"[`{row.check_id}`](../providers/{row.provider_slug}.md)"


def _check_detail_link(row: _CheckRow) -> str:
    """Markdown link from a per-control row down to the bottom-of-page
    check details block. Keeps the reader on the standards page so they
    can scan the mechanism, recommendation, and incidents without
    bouncing through the provider doc."""
    anchor = _check_detail_anchor(row.check_id)
    return f"[`{row.check_id}`](#{anchor})"


def _severity_chip(severity: str) -> str:
    """Same chip CSS class as ``gen_provider_docs.py`` so the styling stays
    consistent across the Providers and Standards sections."""
    sev_lc = severity.lower()
    return f'<span class="pg-sev pg-sev--{sev_lc}">{severity}</span>'


def _autofix_chip(autofix: bool) -> str:
    if not autofix:
        return ""
    return (
        '<span class="pg-fix" title="`--fix` will patch this rule">'
        '🔧 fix</span>'
    )


def _control_anchor(control_id: str) -> str:
    """Stable in-page anchor for a control_id.

    The ``ctrl-`` prefix matters: python-markdown's ``attr_list`` extension
    rejects ID values that begin with a digit. PCI DSS controls like
    ``6.5.1`` and NIST 800-190 controls like ``4.1.1`` would otherwise
    produce anchors starting with a digit, which ``attr_list`` silently
    drops — links from the coverage-by-control table land at the page top
    instead of the matching section. Prefixing with a literal letter dodges
    the rejection entirely. Same shape as :func:`_check_detail_anchor` for
    symmetry; the prefix also disambiguates them from the auto-generated
    heading slugs the ``toc`` extension would otherwise emit.
    """
    return "ctrl-" + (
        control_id.lower()
        .replace(".", "-")
        .replace("/", "-")
        .replace(" ", "-")
    )


def _check_detail_anchor(check_id: str) -> str:
    """In-page anchor for the bottom-of-page check details block.

    ``detail-`` prefix avoids collisions with control anchors (some control
    IDs normalize into strings that look like check IDs) and dodges the
    same ``attr_list`` digit-prefix rejection that affects numeric control
    IDs."""
    return "detail-" + check_id.lower()


# Plain-English severity meanings. Identical wording across every standard
# page so the reader has one mental model regardless of which framework they
# landed on. Pinned here (not in a separate config) because the prose
# describes what the SCANNER intends by each level, which is a generator
# concern rather than a per-standard one.
_SEVERITY_GUIDE: tuple[tuple[str, str, str], ...] = (
    (
        "CRITICAL",
        "Active exploit primitive in the workflow as written. "
        "Treat as P0: a default scan path lands an attacker on a "
        "secret, an RCE, or production write access without further "
        "effort.",
        "Hardcoded credential literal, branch ref pointing at a known-"
        "compromised action, signed-into-an-unverified registry.",
    ),
    (
        "HIGH",
        "Production-impact gap that requires modest attacker effort or a "
        "second condition to weaponize. Remediate this sprint; the "
        "secondary condition is usually already present in real "
        "pipelines.",
        "Action pinned to a floating tag, sensitive permissions on a "
        "low-popularity action, mutable container tag in prod.",
    ),
    (
        "MEDIUM",
        "Significant defense-in-depth gap. Not directly exploitable on "
        "its own but disables a control whose absence widens the blast "
        "radius of a separate compromise. Backlog with a deadline.",
        "Missing branch protection, container without resource limits, "
        "freshly-published dependency consumed before the cooldown "
        "window.",
    ),
    (
        "LOW",
        "Hygiene / hardening issue. Not a vulnerability on its own but "
        "raises baseline posture and reduces audit friction.",
        "Missing CI logging retention, SBOM without supplier "
        "attribution, ECR repo without scan-on-push.",
    ),
    (
        "INFO",
        "Degraded-mode signal. The scanner couldn't reach an API or "
        "parse a config and surfaces the gap so the operator knows "
        "coverage was incomplete. No finding against the workload "
        "itself.",
        "``CB-000`` CodeBuild API access failed, ``IAM-000`` IAM "
        "enumeration failed.",
    ),
)


def _render_severity_guide() -> str:
    """One-line pointer to the canonical severity legend.

    The full ``CRITICAL/HIGH/MEDIUM/LOW/INFO`` table lives once in
    ``docs/standards/README.md`` so a reader clicking between
    standards pages doesn't see the same 60-line legend on every
    page. Generated pages emit only this pointer; the legend itself
    is hand-maintained in the README and ``test_severity_legend_in_sync``
    locks it against the ``_SEVERITY_GUIDE`` constants.
    """
    return (
        "_Severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / "
        "`INFO`) follow the same scale across every provider and "
        "standard. See [How to read severity](README.md#how-to-read-severity) "
        "on the standards overview for the definitions._\n\n"
    )


def _render_severity_guide_full() -> str:
    """Full markdown for the severity legend.

    Currently consumed only by the standards-overview generation, but
    the helper is kept here (next to ``_SEVERITY_GUIDE``) so the
    table's wording stays in lockstep with the constants. Add
    ``--write-overview-legend`` to write
    ``docs/standards/_severity_legend.md`` if a future generator wants
    a snippet to ``--8<--`` include.
    """
    out = ["| Level | What it means | Examples |\n"]
    out.append("|-------|---------------|----------|\n")
    for level, meaning, examples in _SEVERITY_GUIDE:
        out.append(
            f"| {_severity_chip(level)} | {meaning} | {examples} |\n"
        )
    return "".join(out)


# Severity ordering for the "severity mix" cell in the coverage summary.
_SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _severity_breakdown(rows: list[_CheckRow]) -> str:
    """Compact severity histogram inline in a table cell, e.g.
    ``2C · 5H · 3M``. Empty cell when ``rows`` is empty."""
    counts: dict[str, int] = {sev: 0 for sev in _SEV_ORDER}
    for r in rows:
        counts[r.severity] = counts.get(r.severity, 0) + 1
    parts: list[str] = []
    short = {"CRITICAL": "C", "HIGH": "H", "MEDIUM": "M", "LOW": "L", "INFO": "I"}
    for sev in _SEV_ORDER:
        if counts.get(sev):
            parts.append(f"{counts[sev]}{short[sev]}")
    return " · ".join(parts) or "—"


def _render_check_detail(
    row: _CheckRow, controls_evidenced: list[tuple[str, str]],
) -> str:
    """Markdown block for one check in the bottom-of-page details section.

    *controls_evidenced* is the list of ``(control_id, control_title)``
    pairs this check evidences within the standard being rendered. Used
    to surface backlinks ("this check fires under CICD-SEC-3 and
    CICD-SEC-8") so the reader can navigate the cross-control mesh
    without reading the whole page.

    Sections in render order:
      * H4 with check ID + title + severity chip + autofix chip
      * Backlinks to the evidenced controls
      * "How this is detected" (``docs_note``)
      * "Recommendation" (``recommendation``)
      * "Known false positives" (``known_fp``, if any)
      * "Seen in the wild" (``incident_refs``, if any)
      * "Proof of exploit" (``exploit_example``, if any)
      * Link to the provider doc for the raw rule source

    Empty / missing fields are skipped so a Rule that doesn't carry an
    ``incident_refs`` tuple doesn't render an empty section.
    """
    anchor = _check_detail_anchor(row.check_id)
    parts: list[str] = []
    parts.append(
        f"### `{row.check_id}`: {row.title} "
        f"{_severity_chip(row.severity)} "
        f"{_autofix_chip(row.autofix)}".rstrip()
        + f" {{ #{anchor} }}\n\n"
    )

    # Backlinks to the controls this check evidences within the standard.
    if controls_evidenced:
        backlinks = ", ".join(
            f"[`{cid}`](#{_control_anchor(cid)}) {ctitle}"
            for cid, ctitle in controls_evidenced
        )
        parts.append(f"**Evidences:** {backlinks}.\n\n")

    # Mechanism. For fallback entries (degraded-mode AWS findings, legacy
    # class-based checks) ``docs_note`` is empty; fall back to a short
    # stub pointing at the provider doc.
    parts.append("**How this is detected.** ")
    if row.docs_note:
        parts.append(row.docs_note.strip() + "\n\n")
    else:
        parts.append(
            f"See [`{row.provider_title}` provider documentation]"
            f"(../providers/{row.provider_slug}.md) for the rule's "
            f"detection mechanism.\n\n"
        )

    # Recommendation. Same fallback shape.
    parts.append("**Recommendation.** ")
    if row.recommendation:
        parts.append(row.recommendation.strip() + "\n\n")
    else:
        parts.append(
            f"See [`{row.provider_title}` provider documentation]"
            f"(../providers/{row.provider_slug}.md) for the recommended "
            f"remediation.\n\n"
        )

    # Autofix nudge — separate from the chip because the chip alone
    # doesn't explain what `--fix` will do, and readers landing here from
    # an audit context want the concrete command.
    if row.autofix:
        parts.append(
            "**Autofix.** "
            "`pipeline_check --fix` will patch this finding "
            "automatically. Review the diff before committing; the "
            "fixer applies the conservative remediation pattern (e.g. "
            "swap a floating tag for the digest it currently resolves "
            "to), not the most aggressive one.\n\n"
        )

    if row.known_fp:
        parts.append("**Known false positives.**\n\n")
        for fp in row.known_fp:
            parts.append(f"- {fp.strip()}\n")
        parts.append("\n")

    if row.incident_refs:
        parts.append("**Seen in the wild.**\n\n")
        for ref in row.incident_refs:
            parts.append(f"- {ref.strip()}\n")
        parts.append("\n")

    if row.exploit_example:
        # Wrap the raw example in a fenced code block so any
        # ``# Vulnerable: ...`` / ``# Safe: ...`` comment lines render
        # as code rather than getting parsed as Markdown headings
        # (which trip MD019 / MD022 / MD024 and break section depth).
        parts.append(
            "**Proof of exploit.**\n\n"
            "```\n"
            f"{row.exploit_example.rstrip()}\n"
            "```\n\n"
        )

    parts.append(
        f"**Source:** {_check_link(row)} in the "
        f"[{row.provider_title} provider]"
        f"(../providers/{row.provider_slug}.md).\n\n"
    )
    return "".join(parts)


def _render(name: str, standard: Standard, cfg: _StandardConfig,
            index: dict[str, _CheckRow]) -> str:
    parts: list[str] = [f"# {standard.title}\n\n"]
    parts.append(cfg.intro.rstrip() + "\n\n")

    # Group checks by control. Each check_id can map to multiple controls;
    # land in every bucket it lists.
    by_control: dict[str, list[_CheckRow]] = {cid: [] for cid in standard.controls}
    unknown_controls: dict[str, list[_CheckRow]] = {}
    missing_checks: list[str] = []
    for check_id, ctrls in standard.mappings.items():
        row = index.get(check_id)
        if row is None:
            missing_checks.append(check_id)
            continue
        for cid in ctrls:
            if cid in by_control:
                by_control[cid].append(row)
            else:
                unknown_controls.setdefault(cid, []).append(row)

    for ctrl_rows in by_control.values():
        ctrl_rows.sort(key=lambda r: r.check_id)

    # ── At a glance ──────────────────────────────────────────────────────
    n_controls = len(standard.controls)
    n_with_checks = sum(1 for rows in by_control.values() if rows)
    n_checks = len({c for c, _ in standard.mappings.items() if c in index})
    n_autofix = sum(
        1 for c, _ in standard.mappings.items()
        if c in index and index[c].autofix
    )
    parts.append("## At a glance\n\n")
    parts.append(
        f"- **Controls in this standard:** {n_controls}\n"
        f"- **Controls evidenced by at least one check:** "
        f"{n_with_checks} / {n_controls}\n"
        f"- **Distinct checks evidencing this standard:** {n_checks}\n"
        f"- **Of those, autofixable with `--fix`:** {n_autofix}\n\n"
    )

    # ── How to read severity ────────────────────────────────────────────
    parts.append(_render_severity_guide())

    # ── Coverage by control ──────────────────────────────────────────────
    parts.append("## Coverage by control\n\n")
    parts.append(
        "Click a control ID to jump to the per-control section with the "
        "full check list. The severity mix column shows the spread of "
        "evidencing checks by severity (`C`ritical / `H`igh / `M`edium "
        "/ `L`ow / `I`nfo).\n\n"
    )
    parts.append("| Control | Title | Checks | Severity mix |\n")
    parts.append("|---------|-------|-------:|--------------|\n")
    for cid, ctitle in standard.controls.items():
        anchor = _control_anchor(cid)
        ctrl_rows = by_control.get(cid, [])
        parts.append(
            f"| [`{cid}`](#{anchor}) | {ctitle} | "
            f"{len(ctrl_rows)} | {_severity_breakdown(ctrl_rows)} |\n"
        )
    parts.append("\n")

    # ── Filter at runtime ────────────────────────────────────────────────
    parts.append("## Filter at runtime\n\n")
    parts.append(
        f"Restrict a scan to checks that evidence this standard with "
        f"`--standard {name}`:\n\n"
    )
    parts.append("```bash\n")
    parts.append("# All providers, only checks tied to this standard\n")
    parts.append(f"pipeline_check --standard {name}\n\n")
    parts.append("# Compose with --pipeline to scope by provider\n")
    parts.append(f"pipeline_check --pipeline github --standard {name}\n\n")
    pair = "nist_ssdf" if name == "owasp_cicd_top_10" else "owasp_cicd_top_10"
    parts.append("# Compose with another standard to widen the lens\n")
    parts.append(
        f"pipeline_check --pipeline aws --standard {name} --standard {pair}\n"
    )
    parts.append("```\n\n")

    # ── Per-control sections ─────────────────────────────────────────────
    parts.append("## Controls in scope\n\n")
    descriptions = cfg.control_descriptions or {}
    for cid, ctitle in standard.controls.items():
        anchor = _control_anchor(cid)
        parts.append(f"### {cid}: {ctitle} {{ #{anchor} }}\n\n")
        if cid in descriptions:
            parts.append(descriptions[cid].strip() + "\n\n")
        ctrl_rows = by_control.get(cid, [])
        if not ctrl_rows:
            parts.append(
                "_No checks in this scanner currently evidence this "
                "control. Open an issue if your team would value "
                "coverage._\n\n"
            )
            continue
        # Group by provider so the table reads in coherent chunks.
        n_checks = len(ctrl_rows)
        providers = sorted({r.provider_title for r in ctrl_rows})
        provs_phrase = (
            f"{providers[0]}" if len(providers) == 1
            else f"{len(providers)} providers ({', '.join(providers)})"
        )
        suffix = "" if n_checks == 1 else "s"
        parts.append(
            f"**Evidenced by {n_checks} check{suffix}** across "
            f"{provs_phrase}.\n\n"
        )
        parts.append("| Check | Title | Severity | Provider | Fix |\n")
        parts.append("|-------|-------|----------|----------|-----|\n")
        for row in ctrl_rows:
            # The check-id cell jumps to the on-page details block;
            # the provider cell points at the provider doc for the
            # raw rule source. Two routes, two different reading goals.
            parts.append(
                f"| {_check_detail_link(row)} | {row.title} | "
                f"{_severity_chip(row.severity)} | "
                f"[{row.provider_title}](../providers/{row.provider_slug}.md) | "
                f"{_autofix_chip(row.autofix)} |\n"
            )
        parts.append("\n")

    # ── Check details ───────────────────────────────────────────────────
    # Reverse-index: for every distinct check that evidences a control on
    # this page, list the controls it evidences. Drives the backlinks at
    # the top of each check's detail block so the reader can navigate the
    # check <-> control mesh without scrolling the whole page.
    controls_by_check: dict[str, list[tuple[str, str]]] = {}
    for cid, ctitle in standard.controls.items():
        for row in by_control.get(cid, []):
            controls_by_check.setdefault(row.check_id, []).append((cid, ctitle))
    if controls_by_check:
        parts.append("## Check details\n\n")
        parts.append(
            "Every check that evidences this standard, rendered once "
            "with its detection mechanism, recommendation, and any "
            "known false-positive modes or real-world incident "
            "references. The per-control tables above link to the "
            "matching block here.\n\n"
        )
        for cid in sorted(controls_by_check.keys()):
            row = index[cid]
            parts.append(_render_check_detail(row, controls_by_check[cid]))

    # ── Mappings to controls outside this standard's catalog ─────────────
    if unknown_controls:
        parts.append("## Mappings to unrecognized controls\n\n")
        parts.append(
            "The standards mapping references control IDs that are not "
            "declared in this standard's `controls={…}` block. Usually a "
            "typo or a control that was renamed without updating the "
            "registry.\n\n"
        )
        for cid, rows in sorted(unknown_controls.items()):
            ids = ", ".join(f"`{r.check_id}`" for r in sorted(rows, key=lambda r: r.check_id))
            parts.append(f"- **`{cid}`**: {ids}\n")
        parts.append("\n")

    if missing_checks:
        parts.append("## Mapped check IDs not found in the rule registry\n\n")
        parts.append(
            "The standards data references check IDs the scanner does not "
            "ship. The mapping is preserved for forward-compat; once the "
            "rule lands the row will fill in automatically.\n\n"
        )
        for c in sorted(set(missing_checks)):
            parts.append(f"- `{c}`\n")
        parts.append("\n")

    if cfg.footer:
        parts.append(cfg.footer.rstrip() + "\n\n")

    parts.append("---\n\n")
    parts.append(
        "_This page is generated. Edit "
        f"`pipeline_check/core/standards/data/{name}.py` (mappings) or "
        "`scripts/gen_standards_docs.py` (intro / per-control prose) and "
        f"run `python scripts/gen_standards_docs.py {name}`._\n"
    )
    return "".join(parts)


def _standards_to_render(argv: Iterable[str]) -> list[str]:
    argv = list(argv)
    if not argv:
        return list(_STANDARDS.keys())
    for name in argv:
        if name not in _STANDARDS:
            raise SystemExit(
                f"Unknown standard {name!r}. "
                f"Supported: {', '.join(_STANDARDS.keys())}"
            )
    return argv


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if any standard doc would change. Useful in CI.",
    )
    parser.add_argument(
        "standards",
        nargs="*",
        help="Subset of standards to render (default: all).",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    targets = _standards_to_render(args.standards)
    index = _build_index()
    out_dir = _REPO_ROOT / "docs" / "standards"
    stale: list[str] = []
    for name in targets:
        cfg = _STANDARDS[name]
        mod = importlib.import_module(
            f"pipeline_check.core.standards.data.{name}"
        )
        body = _render(name, mod.STANDARD, cfg, index)
        out_path = out_dir / f"{name}.md"
        rel = out_path.relative_to(_REPO_ROOT)
        if args.check:
            current = out_path.read_text(encoding="utf-8") if out_path.exists() else ""
            if current != body:
                stale.append(str(rel))
                print(f"[gen-standards-docs] {rel}: out of sync", file=sys.stderr)
            else:
                print(f"[gen-standards-docs] {rel}: in sync")
            continue
        out_path.write_text(body, encoding="utf-8")
        print(
            f"[gen-standards-docs] wrote {rel} "
            f"({body.count(chr(10))} lines)"
        )

    if args.check and stale:
        print(
            f"[gen-standards-docs] {len(stale)} doc(s) out of sync. "
            f"Re-run scripts/gen_standards_docs.py to update.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
