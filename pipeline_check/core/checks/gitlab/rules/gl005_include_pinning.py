"""GL-005 — `include:` must pin a project ref or skip remote URLs."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GL-005",
    title="include: pulls remote / project without pinned ref",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-TRUSTED-REG"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin `include: project:` entries with `ref:` set to a tag or "
        "commit SHA. Avoid `include: remote:` for untrusted URLs; "
        "mirror the content into a trusted project and pin it."
    ),
    docs_note=(
        "Cross-project and remote includes can be silently re-pointed. "
        "Branch-name refs (`main`/`master`/`develop`/`head`) are "
        "treated as unpinned; tag and SHA refs are considered safe."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    includes = doc.get("include")
    if includes is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Pipeline has no `include:` directive.",
            recommendation="No action required.", passed=True,
        )
    items = includes if isinstance(includes, list) else [includes]
    unpinned: list[str] = []
    for entry in items:
        if isinstance(entry, str):
            if entry.startswith(("http://", "https://")):
                unpinned.append(f"remote: {entry}")
            continue
        if not isinstance(entry, dict):
            continue
        if "project" in entry and not entry.get("ref"):
            unpinned.append(f"project: {entry.get('project')} (no ref)")
        elif "project" in entry:
            ref = str(entry.get("ref"))
            if ref.lower() in {"main", "master", "develop", "head"}:
                unpinned.append(f"project: {entry.get('project')} @{ref}")
        if "remote" in entry:
            unpinned.append(f"remote: {entry.get('remote')}")
    passed = not unpinned
    desc = (
        "All `include:` entries reference a pinned ref."
        if passed else
        f"{len(unpinned)} `include:` entr(ies) pull from a remote or "
        f"upstream project without a pinned ref: "
        f"{', '.join(unpinned[:5])}{'…' if len(unpinned) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
