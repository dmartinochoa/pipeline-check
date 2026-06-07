"""GHA-098. Deploy step has no upstream security scan in the job DAG."""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.deploy_names import DEPLOY_CMD_RE as _DEPLOY_CMD_RE
from ..._primitives.deploy_names import DEPLOY_RE as _DEPLOY_NAME_RE
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, job_location

RULE = Rule(
    id="GHA-098",
    title="Pipeline deploys without a security scan gate",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-CODE-INTEGRITY",),
    cwe=("CWE-693",),
    recommendation=(
        "Add a security scanning step (SAST, SCA, container scan, or "
        "secret scan) upstream of every deploy job. Either add the "
        "scan as an earlier step in the same job, or run it in a "
        "separate job and add the scan job to the deploy job's "
        "``needs:`` list. Recognized scanners include ``trivy``, "
        "``grype``, ``snyk test``, ``semgrep``, ``bandit``, "
        "``npm audit``, ``pip-audit``, ``gitleaks``, and their "
        "corresponding GitHub Actions."
    ),
    docs_note=(
        "Walks each workflow's job graph looking for jobs that contain "
        "deploy-shaped steps (``kubectl apply``, ``terraform apply``, "
        "``docker push``, ``helm upgrade``, ``aws ecs update-service``, "
        "``gcloud run deploy``, environment-gated jobs, or jobs whose "
        "name matches a deploy/release/publish pattern). For each "
        "deploy job, checks whether any predecessor in the ``needs:`` "
        "DAG or any earlier step in the same job invokes a recognized "
        "security scanner (SAST, SCA, container scan, or secret "
        "scan).\n\n"
        "Fires when a deploy job has zero security-scan predecessors. "
        "Severity is MEDIUM (advisory) because the scanner catalog is "
        "not exhaustive and some organizations run scans in separate "
        "pipelines."
    ),
    known_fp=(
        "Organizations that run security scans in a separate pipeline "
        "or CI system (e.g. a nightly scan job, a third-party SaaS "
        "scanner) will see this rule fire on deploy workflows that "
        "rely on external gating. Suppress with a rationale naming "
        "the external scanner.",
        "Test/staging deploy jobs that target ephemeral environments "
        "may not warrant a scan gate. Suppress per-job.",
    ),
)


_DEPLOY_ACTIONS = frozenset({
    "aws-actions/amazon-ecs-deploy-task-definition",
    "azure/webapps-deploy",
    "azure/functions-action",
    "google-github-actions/deploy-cloudrun",
    "google-github-actions/deploy-cloud-functions",
    "google-github-actions/deploy-appengine",
})

_SCAN_CMD_RE = re.compile(
    r"(?:trivy\b|grype\b|snyk\s+test\b|semgrep\b|bandit\b"
    r"|npm\s+audit\b|pip-audit\b|gitleaks\b|checkov\b"
    r"|safety\s+check\b|bearer\b|trufflehog\b|detect-secrets\b"
    r"|codeql\b|osv-scanner\b|govulncheck\b|cargo\s+audit\b"
    r"|audit-ci\b|yarn\s+audit\b)",
    re.IGNORECASE,
)

_SCAN_ACTIONS = frozenset({
    "aquasecurity/trivy-action",
    "anchore/scan-action",
    "snyk/actions",
    "github/codeql-action",
    "returntocorp/semgrep-action",
    "gitleaks/gitleaks-action",
    "trufflesecurity/trufflehog",
    "pypa/gh-action-pip-audit",
    "ossf/scorecard-action",
    # NB: step-security/harden-runner is deliberately NOT here. It's a
    # runtime egress monitor, not a SAST / SCA / secret scanner, so it
    # doesn't satisfy the "scan before deploy" gate this rule checks.
    # Its own configuration is covered by GHA-107 / GHA-108 / GHA-109.
})


def _action_slug(uses: str) -> str:
    slug = uses.split("@", 1)[0].strip().lower()
    parts = slug.split("/")
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return slug


def _is_deploy_job(job_id: str, job: dict[str, Any]) -> bool:
    if job.get("environment") is not None:
        return True
    if isinstance(job_id, str) and _DEPLOY_NAME_RE.search(job_id):
        return True
    name = job.get("name")
    if isinstance(name, str) and _DEPLOY_NAME_RE.search(name):
        return True
    for step in iter_steps(job):
        run = step.get("run")
        if isinstance(run, str) and _DEPLOY_CMD_RE.search(run):
            return True
        uses = step.get("uses")
        if isinstance(uses, str) and _action_slug(uses) in _DEPLOY_ACTIONS:
            return True
    return False


def _is_scan_step(step: dict[str, Any]) -> bool:
    run = step.get("run")
    if isinstance(run, str) and _SCAN_CMD_RE.search(run):
        return True
    uses = step.get("uses")
    if isinstance(uses, str) and _action_slug(uses) in _SCAN_ACTIONS:
        return True
    return False


def _job_has_scan_step(job: dict[str, Any]) -> bool:
    return any(_is_scan_step(step) for step in iter_steps(job))


def check(path: str, doc: dict[str, Any]) -> Finding:
    jobs_map: dict[str, dict[str, Any]] = {}
    for job_id, job in iter_jobs(doc):
        jobs_map[job_id] = job

    if not jobs_map:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path, description="Workflow has no jobs.",
            recommendation=RULE.recommendation, passed=True,
        )

    scan_jobs: set[str] = set()
    for job_id, job in jobs_map.items():
        if _job_has_scan_step(job):
            scan_jobs.add(job_id)

    deploy_jobs_without_scan: list[str] = []
    locations: list[Location] = []
    for job_id, job in jobs_map.items():
        if not _is_deploy_job(job_id, job):
            continue
        if job_id in scan_jobs:
            continue
        needs = job.get("needs") or []
        if isinstance(needs, str):
            needs = [needs]
        if not isinstance(needs, list):
            needs = []
        has_upstream_scan = any(n in scan_jobs for n in needs)
        if not has_upstream_scan:
            deploy_jobs_without_scan.append(job_id)
            locations.append(job_location(path, job))

    passed = not deploy_jobs_without_scan
    if passed:
        desc = (
            "Every deploy job has at least one security scan step "
            "upstream in the job DAG or within the same job."
        )
    else:
        desc = (
            f"{len(deploy_jobs_without_scan)} deploy job(s) have no "
            f"security scan predecessor: "
            f"{', '.join(deploy_jobs_without_scan[:5])}"
            f"{'...' if len(deploy_jobs_without_scan) > 5 else ''}. "
            f"Code reaching production without a security scan gate "
            f"means vulnerabilities, leaked secrets, and malicious "
            f"dependencies ship undetected."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
