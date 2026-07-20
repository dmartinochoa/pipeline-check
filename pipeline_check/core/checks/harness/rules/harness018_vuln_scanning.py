"""HARNESS-018. Pipeline should run a vulnerability scanner."""
from __future__ import annotations

from ...base import Finding, Severity, has_vuln_scanning
from ...rule import Rule
from ..base import HarnessPipeline, iter_steps

#: Harness Security Testing Orchestration (STO) scanner step types. An
#: STO step names its scanner as a bare scalar ``type: Grype`` (no
#: command text), which lowercases to ``grype`` with no trailing space,
#: so the shared space-delimited CLI catalog (``"grype "``) misses it.
#: Matched against the step's ``type`` field exactly, so short names
#: (``zap`` / ``owasp``) can't false-fire off unrelated prose the way a
#: bare blob substring would.
_STO_SCANNER_TYPES: frozenset[str] = frozenset({
    "aquatrivy", "anchore", "anchoreenterprise", "bandit", "blackduck",
    "blackduckhub", "brakeman", "burp", "checkmarx", "checkmarxone",
    "clair", "coverity", "fortify", "fortifyondemand", "gitleaks",
    "grype", "mend", "metasploit", "nessus", "nexusiq", "nikto", "nmap",
    "owasp", "prismacloud", "qualys", "reapsaw", "semgrep", "snyk",
    "snykcode", "sonarqube", "sysdig", "tenable", "veracode", "wiz",
    "zap",
})


def _has_sto_scanner_step(pipeline: HarnessPipeline) -> bool:
    """True when any step is a native STO scanner (``type: Grype`` ...)."""
    for _stage, step in iter_steps(pipeline):
        step_type = step.get("type")
        if isinstance(step_type, str) and step_type.strip().lower() in _STO_SCANNER_TYPES:
            return True
    return False

RULE = Rule(
    id="HARNESS-018",
    title="No vulnerability-scan step (trivy / grype / snyk)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-VULN-SCAN",),
    cwe=("CWE-1104",),
    recommendation=(
        "Add a vulnerability-scan step to the build: ``trivy``, ``grype``, "
        "``snyk``, ``npm audit``, or ``pip-audit`` over the image or "
        "dependency tree (or a Harness Security Testing Orchestration "
        "step), and fail the build on findings above your threshold so "
        "known CVEs don't ship to production silently."
    ),
    docs_note=(
        "Detection mirrors GHA-020 / BK-012 / CC-020 / TKN-012 / DR-022, "
        "the shared scanner-token catalog (trivy, grype, snyk, clair, npm "
        "audit, pip-audit, etc.) is searched across every string in the "
        "pipeline document. It additionally recognizes Harness's native "
        "Security Testing Orchestration steps by their ``type`` slug "
        "(``Grype`` / ``Snyk`` / ``Checkmarx`` / ``Owasp`` / ``Zap`` / "
        "...), which carry no command text for the CLI catalog to match. "
        "Fires on any pipeline that runs no scanner (the build ships "
        "without a CVE signal). The Harness analog of BK-012 / TKN-012."
    ),
)


def check(pipeline: HarnessPipeline) -> Finding:
    passed = has_vuln_scanning(pipeline.data) or _has_sto_scanner_step(pipeline)
    desc = (
        "Pipeline runs a vulnerability scanner (trivy / grype / snyk / ...)."
        if passed else
        "Pipeline does not invoke any vulnerability scanner; known CVEs in "
        "dependencies or container layers ship to production without a "
        "build-time signal. Add trivy, grype, snyk, npm audit, or "
        "pip-audit to the build."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
