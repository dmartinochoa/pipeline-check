"""GL-043. A GitLab native security scanner is explicitly disabled."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

# CI/CD variables that switch off a GitLab-managed security scanner.
_SCANNER_DISABLE_VARS: dict[str, str] = {
    "SAST_DISABLED": "SAST",
    "SECRET_DETECTION_DISABLED": "Secret Detection",
    "DEPENDENCY_SCANNING_DISABLED": "Dependency Scanning",
    "CONTAINER_SCANNING_DISABLED": "Container Scanning",
    "DAST_DISABLED": "DAST",
}
#: Values that leave the scanner ENABLED. Everything else disables it:
#: legacy GitLab templates (pre-15.4) switch a scanner off on ANY
#: non-empty ``*_DISABLED`` value (``except: variables: [$X_DISABLED]``),
#: and the pipeline file doesn't record the GitLab version, so
#: over-approximate to the legacy semantics rather than only honoring
#: ``true`` / ``1``.
_NOT_DISABLING = {"", "false", "0", "no"}

RULE = Rule(
    id="GL-043",
    title="GitLab native security scanner explicitly disabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-S-VULN-MGMT",),
    cwe=("CWE-693",),
    recommendation=(
        "Remove the `*_DISABLED: \"true\"` CI/CD variable so GitLab's "
        "managed scanner runs again, or scope the opt-out narrowly with "
        "`rules:` instead of disabling it pipeline-wide. Each of "
        "`SAST_DISABLED`, `SECRET_DETECTION_DISABLED`, "
        "`DEPENDENCY_SCANNING_DISABLED`, `CONTAINER_SCANNING_DISABLED`, "
        "and `DAST_DISABLED` turns off a security control that would "
        "otherwise gate the pipeline. If a scanner is noisy, tune it "
        "(`SAST_EXCLUDED_PATHS`, ruleset overrides) rather than "
        "switching it off, and keep the opt-out in code review via the "
        "pipeline file rather than a hidden project variable."
    ),
    docs_note=(
        "Fires when a `*_DISABLED` variable for a GitLab-managed scanner "
        "(SAST, Secret Detection, Dependency Scanning, Container "
        "Scanning, DAST) is set to any value other than an explicit "
        "falsy literal (`\"false\"` / `\"0\"` / `\"no\"` / empty) at the "
        "top level or on a job. Legacy GitLab templates disable the "
        "scanner on any non-empty value, so the rule over-approximates "
        "to that rather than only matching `\"true\"` / `\"1\"`. Both the "
        "plain scalar and the typed `{value:, description:}` variable "
        "form are read. "
        "Disabling a scanner pipeline-wide silently drops the finding "
        "stream the rest of your supply-chain controls assume exists."
    ),
    known_fp=(
        "A pipeline that runs the scanner through a dedicated security "
        "pipeline (e.g. a scheduled `secret_detection` job) and disables "
        "the auto-included template here to avoid a duplicate run. "
        "Suppress with a rationale that names the other pipeline.",
    ),
    exploit_example=(
        "# Vulnerable: secret detection switched off pipeline-wide.\n"
        "variables:\n"
        "  SECRET_DETECTION_DISABLED: \"true\"\n"
        "  DEPENDENCY_SCANNING_DISABLED: \"true\"\n"
        "\n"
        "# A committed credential or a known-vulnerable dependency now\n"
        "# ships with no pipeline gate to catch it.\n"
        "\n"
        "# Safe: leave the scanners on; tune noise instead of disabling.\n"
        "variables:\n"
        "  SAST_EXCLUDED_PATHS: \"spec, test, tmp\""
    ),
)


def _scalar(raw: Any) -> Any:
    """Unwrap GitLab's typed ``{value:, description:}`` variable form."""
    if isinstance(raw, dict):
        return raw.get("value")
    return raw


def _disabled_scanners(variables: Any) -> list[str]:
    if not isinstance(variables, dict):
        return []
    out: list[str] = []
    for var, label in _SCANNER_DISABLE_VARS.items():
        val = _scalar(variables.get(var))
        if val is None:
            continue
        if str(val).strip().lower() not in _NOT_DISABLING:
            out.append(label)
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    disabled: set[str] = set(_disabled_scanners(doc.get("variables")))
    for _name, job in iter_jobs(doc):
        disabled.update(_disabled_scanners(job.get("variables")))
    passed = not disabled
    desc = (
        "No GitLab-managed security scanner is explicitly disabled."
        if passed else
        f"{len(disabled)} GitLab security scanner(s) disabled via "
        f"``*_DISABLED`` variable(s): {', '.join(sorted(disabled))}. "
        f"Each turns off a control the pipeline would otherwise enforce."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
