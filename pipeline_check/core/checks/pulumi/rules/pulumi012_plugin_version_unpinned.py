"""PULUMI-012. Plugin version unpinned or floating."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PulumiContext, PulumiProject

RULE = Rule(
    id="PULUMI-012",
    title="Pulumi plugin version unpinned or floating",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-4"),
    esf=("ESF-S-PROVENANCE",),
    cwe=("CWE-1104", "CWE-829"),
    recommendation=(
        "Pin every plugin entry to an exact version (for example "
        "``version: 6.18.0``). A provider / analyzer plugin is "
        "native code the Pulumi engine runs at deploy time; an "
        "absent or range-pinned ``version:`` lets that binary change "
        "between deploys with no code review and no diff.\n\n"
        "Bump the pin through a reviewed commit when you want a new "
        "release, so the binary that runs in CI always matches what "
        "a human approved. Treat the pin like a lockfile entry, not "
        "a hint."
    ),
    docs_note=(
        "Walks the ``plugins:`` block of every ``Pulumi.yaml`` and "
        "fires on any entry under ``providers`` / ``analyzers`` / "
        "``languages`` whose ``version:`` is absent or uses a "
        "range / floating spec (a leading ``^`` / ``~`` / ``>`` / "
        "``<`` / ``=`` comparator, a ``*`` or ``x`` wildcard, or "
        "the literal ``latest``).\n\n"
        "Entries that point at a local build via ``path:`` are "
        "skipped: a path plugin carries no registry version to "
        "pin, so a missing ``version:`` there is expected. An exact "
        "version (``6.18.0``) passes. The rule reads the "
        "already-parsed ``project.data['plugins']`` structure and "
        "does not contact the registry."
    ),
    known_fp=(
        "Locally built plugins referenced by ``path:`` are not "
        "flagged. A repo that deliberately tracks the latest "
        "provider in a sandbox stack trips this rule by shape; "
        "suppress per project with a one-line rationale naming the "
        "sandbox and the gate that keeps the floating pin out of "
        "production.",
    ),
    incident_refs=(
        "Maps to the unpinned-dependency class: a deploy that "
        "resolves a plugin version at run time silently picks up a "
        "new (or hijacked) release. The Pulumi engine executes "
        "provider plugins in-process with the deploy identity, so a "
        "drifted binary runs with full deploy access, the same "
        "fresh-carrier-version risk the npm / PyPI cooldown rules "
        "address on the registry side.",
    ),
)

# Plugin kinds Pulumi recognizes under the top-level ``plugins:``
# block. Each maps to a list of plugin entry dicts.
_PLUGIN_KINDS = ("providers", "analyzers", "languages")

# A floating / range version spec rather than one exact release:
# a comparator or wildcard anywhere, or the literal ``latest``.
_FLOATING_RE = re.compile(r"[\^~><=*]|\bx\b|\blatest\b", re.IGNORECASE)


def _plugin_entries(project: PulumiProject) -> list[dict[str, Any]]:
    """Flatten every plugin entry across the recognized plugin kinds.

    Non-dict entries and missing kinds are skipped so a malformed
    manifest yields nothing rather than raising."""
    plugins = project.data.get("plugins")
    if not isinstance(plugins, dict):
        return []
    out: list[dict[str, Any]] = []
    for kind in _PLUGIN_KINDS:
        items = plugins.get(kind)
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                out.append(item)
    return out


def _weak_version(entry: dict[str, Any]) -> str | None:
    """Return a short label when the entry's ``version:`` is weak,
    else ``None``. A local ``path:`` plugin has no registry version
    and is treated as out of scope."""
    path_val = entry.get("path")
    if isinstance(path_val, str) and path_val.strip():
        return None
    version = entry.get("version")
    if version is None:
        return "no version"
    version_str = str(version)
    if _FLOATING_RE.search(version_str):
        return version_str
    return None


def _line_of(text: str, needle: str) -> int:
    """Best-effort 1-based line number for the first occurrence of
    ``needle`` in ``text``. Falls back to line 1."""
    idx = text.find(needle)
    if idx < 0:
        return 1
    return text[:idx].count("\n") + 1


def check(ctx: PulumiContext) -> Finding:
    if not ctx.projects:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="Pulumi.yaml",
            description="No Pulumi.yaml in the scan path.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for project in ctx.projects:
        for entry in _plugin_entries(project):
            label = _weak_version(entry)
            if label is None:
                continue
            name = entry.get("name")
            name_str = name if isinstance(name, str) else "?"
            offenders.append(f"{name_str} ({label})")
            anchor = name_str if name_str != "?" else "plugins"
            locations.append(Location(
                path=project.path,
                start_line=_line_of(project.text, anchor),
                end_line=_line_of(project.text, anchor),
            ))
    passed = not offenders
    desc = (
        "Every Pulumi plugin entry is pinned to an exact version."
        if passed else
        f"{len(offenders)} plugin entr(y/ies) are unpinned or "
        f"floating: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The deploy-time "
        f"binary can change without a code change."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=(
            locations[0].path if locations else ctx.projects[0].path
        ),
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
