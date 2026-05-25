"""PYPI-009, PyPI package has a known OSV advisory."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PypiContext, RequirementsFile

RULE = Rule(
    id="PYPI-009",
    title="PyPI package has a known OSV advisory",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-506"),
    recommendation=(
        "Upgrade to a patched version or remove the affected package. "
        "Consult the advisory URL for remediation guidance."
    ),
    docs_note=(
        "Network-dependent: needs ``--resolve-remote`` to query the "
        "OSV advisory database (``api.osv.dev``). Passes silently "
        "when the flag is off. Complements PYPI-006 (curated offline "
        "registry) with the full OSV/GHSA long-tail."
    ),
)

# Match an exact-version PyPI requirement: ``name==version`` with
# optional ``[extras]`` and an optional ``; markers`` suffix that
# we strip before extracting.
_EXACT_RE = re.compile(r"^([A-Za-z0-9._-]+)==(\S+)")


def check(
    reqfile: RequirementsFile, ctx: PypiContext | None = None,
) -> Finding:
    if ctx is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=reqfile.path,
            description=(
                "No OSV advisory data available (re-run with "
                "``--resolve-remote`` to enable advisory lookups)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    osv: dict[tuple[str, str], list[Any]] = getattr(
        ctx, "osv_advisories", {},
    )
    if not osv:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=reqfile.path,
            description=(
                "No OSV advisory data available (re-run with "
                "``--resolve-remote`` to enable advisory lookups)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    offenders: list[str] = []
    advisory_ids: set[str] = set()
    locations: list[Location] = []
    for line in reqfile.lines:
        m = _EXACT_RE.match(line.body)
        if m is None:
            continue
        name = m.group(1)
        version = m.group(2)
        # Strip trailing environment markers (``; python_version...``)
        # and surrounding whitespace from the version.
        if ";" in version:
            version = version.split(";", 1)[0].strip()
        name_lower = name.lower()
        advisories = osv.get((name_lower, version))
        if not advisories:
            continue
        ids = [
            a.get("id", "unknown") if isinstance(a, dict) else str(a)
            for a in advisories
        ]
        advisory_ids.update(ids)
        offenders.append(
            f"{name}=={version} ({', '.join(ids)})"
        )
        locations.append(Location(
            path=reqfile.path,
            start_line=line.line_no, end_line=line.line_no,
        ))

    passed = not offenders
    if passed:
        desc = (
            "No requirement matches a known OSV advisory."
        )
    else:
        ref_summary = ", ".join(offenders[:5])
        if len(offenders) > 5:
            ref_summary += f" (+{len(offenders) - 5} more)"
        desc = (
            f"{len(offenders)} requirement(s) have known OSV "
            f"advisories: {ref_summary}. Consult the advisory URLs "
            f"for remediation guidance."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=reqfile.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
