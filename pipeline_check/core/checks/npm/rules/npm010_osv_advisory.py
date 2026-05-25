"""NPM-010, npm package has a known OSV advisory."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmContext, NpmManifest, iter_manifest_dependencies

RULE = Rule(
    id="NPM-010",
    title="npm package has a known OSV advisory",
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
        "when the flag is off. Complements NPM-006 (curated offline "
        "registry) with the full OSV/GHSA long-tail."
    ),
)

# Accept ``1.2.3``, ``=1.2.3``, ``v1.2.3`` but NOT ``^1.2.3``,
# ``~1.2.3``, ``>=1.0.0``, ``*``, dist-tags, or source specs.
_EXACT_VERSION_RE = re.compile(r"^=?v?(\d+\.\d+\.\d+(?:[\w.+-]*)?)$")


def check(
    manifest: NpmManifest, ctx: NpmContext | None = None,
) -> Finding:
    if ctx is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
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
            resource=manifest.path,
            description=(
                "No OSV advisory data available (re-run with "
                "``--resolve-remote`` to enable advisory lookups)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    offenders: list[str] = []
    advisory_ids: set[str] = set()
    locations: list[Location] = []
    for section, name, spec in iter_manifest_dependencies(manifest):
        m = _EXACT_VERSION_RE.match(spec.strip())
        if m is None:
            continue
        version = m.group(1)
        advisories = osv.get((name, version))
        if not advisories:
            continue
        ids = [
            a.get("id", "unknown") if isinstance(a, dict) else str(a)
            for a in advisories
        ]
        advisory_ids.update(ids)
        offenders.append(
            f"{section}.{name}@{version} ({', '.join(ids)})"
        )
        idx = manifest.text.find(f'"{name}"')
        line_no = manifest.text[:idx].count("\n") + 1 if idx >= 0 else 1
        locations.append(Location(
            path=manifest.path, start_line=line_no, end_line=line_no,
        ))

    passed = not offenders
    if passed:
        desc = (
            "No direct dependency matches a known OSV advisory."
        )
    else:
        ref_summary = ", ".join(offenders[:5])
        if len(offenders) > 5:
            ref_summary += f" (+{len(offenders) - 5} more)"
        desc = (
            f"{len(offenders)} direct dependency / dependencies have "
            f"known OSV advisories: {ref_summary}. Consult the advisory "
            f"URLs for remediation guidance."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
