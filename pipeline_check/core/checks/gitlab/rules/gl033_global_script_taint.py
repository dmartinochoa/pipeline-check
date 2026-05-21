"""GL-033. Global ``before_script`` / ``after_script`` injects into every job."""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.tainted_variables import has_direct_taint
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ._helpers import UNTRUSTED_VAR_RE

RULE = Rule(
    id="GL-033",
    title="Global before_script / after_script propagates taint to every job",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-1"),
    esf=("ESF-D-INJECTION", "ESF-D-CODE-INTEGRITY"),
    cwe=("CWE-78", "CWE-1357"),
    recommendation=(
        "Move any setup logic that touches commit / MR metadata "
        "out of the document-root ``before_script:`` (and "
        "``default.before_script:`` / ``default.after_script:``) "
        "and into a dedicated job that opts in via ``extends:`` "
        "or that runs on a known-safe trigger only. The global "
        "before-script runs verbatim before every job in the "
        "pipeline (including child pipelines launched by ``trigger:"
        "include:``); a single unquoted ``$CI_COMMIT_TITLE`` "
        "interpolation there is, in effect, that injection in N "
        "jobs at once. Quote the value defensively (``branch=\""
        "$CI_COMMIT_REF_NAME\"``) and copy it into a job-local "
        "variable before any further use."
    ),
    docs_note=(
        "GL-002 catches injection in **per-job** "
        "``before_script:`` / ``script:`` / ``after_script:``, "
        "but its scanner walks ``iter_jobs`` which deliberately "
        "skips top-level keywords (``before_script``, "
        "``after_script``, ``default``, ``image``, ``services``, "
        "``variables``, ``stages``, ``workflow``, ``include``, "
        "...). That means a tainted ``$CI_COMMIT_TITLE`` "
        "interpolation in a document-root ``before_script:`` or "
        "``default.before_script:`` evades GL-002 entirely, even "
        "though it propagates to every job in the pipeline.\n\n"
        "GL-033 closes that gap. It scans:\n\n"
        "- ``before_script:`` at document root\n"
        "- ``after_script:`` at document root\n"
        "- ``default.before_script:`` (the modern form)\n"
        "- ``default.after_script:``\n\n"
        "for direct interpolation of the same attacker-"
        "controllable predefined variables tracked by GL-002 "
        "(``CI_COMMIT_TITLE`` / ``CI_COMMIT_MESSAGE`` / "
        "``CI_COMMIT_REF_NAME`` / ``CI_MERGE_REQUEST_TITLE`` / "
        "``CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`` / etc.). The "
        "detection mirrors GL-002's ``has_direct_taint`` helper "
        "so the quote-aware semantics are identical."
    ),
    known_fp=(
        "Some self-hosted GitLab installations build a "
        "diagnostic banner into the global ``before_script`` "
        "that ``echo``s commit metadata for log-correlation "
        "purposes. Suppress per pipeline file rather than "
        "globally, the rule is checking propagation reach, not "
        "intent.",
    ),
    exploit_example=(
        "# Vulnerable: a global ``before_script:`` (or\n"
        "# ``after_script:``) interpolates an untrusted CI\n"
        "# variable. The injected metacharacters then execute\n"
        "# in every job that inherits the global block, which\n"
        "# usually means every job in the pipeline.\n"
        "before_script:\n"
        "  - echo \"Building $CI_COMMIT_MESSAGE\"   # message is attacker-controllable\n"
        "build:\n"
        "  script: [make build]\n"
        "test:\n"
        "  script: [make test]\n"
        "\n"
        "# Safe: assign the untrusted source to a local variable\n"
        "# and quote on every use. Pulling the value into a\n"
        "# variable AT MOST ONCE per job keeps the injection\n"
        "# surface to a single quoted reference.\n"
        "before_script:\n"
        "  - MSG=\"$CI_COMMIT_MESSAGE\"\n"
        "  - echo \"Building $MSG\"\n"
        "build:\n"
        "  script: [make build]"
    ),
)


def _gather_lines(value: Any) -> list[str]:
    """Flatten a ``before_script:`` / ``after_script:`` value to lines."""
    out: list[str] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                out.append(item)
    elif isinstance(value, str):
        out.append(value)
    return out


def _scan_block(block: Any, breadcrumb: str) -> list[str]:
    """Return offender labels for a tainted ``before_script`` block."""
    lines = _gather_lines(block)
    if not lines:
        return []
    if has_direct_taint(lines, UNTRUSTED_VAR_RE):
        # Pull the first offending variable name into the
        # description so the user sees which token tripped the
        # rule.
        var = ""
        for line in lines:
            m = UNTRUSTED_VAR_RE.search(line)
            if m:
                var = re.sub(r"[${}]", "", m.group(0))
                break
        return [f"{breadcrumb}: ${var}" if var else breadcrumb]
    return []


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    # Document-root before/after_script.
    for key in ("before_script", "after_script"):
        block = doc.get(key)
        hits = _scan_block(block, breadcrumb=key)
        if hits:
            offenders.extend(hits)
            line = _line_of(block) if isinstance(block, dict) else 1
            locations.append(Location(
                path=path, start_line=line, end_line=line,
            ))
    # ``default:`` block (modern form).
    default = doc.get("default")
    if isinstance(default, dict):
        for key in ("before_script", "after_script"):
            block = default.get(key)
            hits = _scan_block(block, breadcrumb=f"default.{key}")
            if hits:
                offenders.extend(hits)
                line = _line_of(default)
                locations.append(Location(
                    path=path, start_line=line, end_line=line,
                ))
    passed = not offenders
    desc = (
        "No global ``before_script`` / ``after_script`` "
        "interpolates attacker-controllable commit / MR metadata."
        if passed else
        f"{len(offenders)} global script block(s) interpolate "
        f"untrusted CI variables: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The injection "
        f"propagates to every job in the pipeline."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
