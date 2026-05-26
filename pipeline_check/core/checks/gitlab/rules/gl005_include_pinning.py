"""GL-005, `include:` must pin a project ref or skip remote URLs."""
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
        "Branch-name refs (`main`/`master`/`develop`/`head`/`trunk`) are "
        "treated as unpinned; tag and SHA refs are considered safe."
    ),
    exploit_example=(
        "# Vulnerable: ``include:`` pulls a remote project without\n"
        "# a pinned ref. ``ref:`` defaults to ``HEAD`` of the\n"
        "# default branch; whoever can push to that branch on\n"
        "# the templates project ships pipeline code into every\n"
        "# consumer.\n"
        "include:\n"
        "  - project: 'ci/templates'\n"
        "    file: '/build.yml'\n"
        "    # no ref: — resolves to HEAD\n"
        "\n"
        "# Safe: pin ``ref:`` to a tag (with tag-protect enforced\n"
        "# on the templates project) or a 40-char commit SHA.\n"
        "# Renovate's gitlabci-include ecosystem updater bumps\n"
        "# these in reviewable MRs.\n"
        "include:\n"
        "  - project: 'ci/templates'\n"
        "    file: '/build.yml'\n"
        "    ref: 0123456789abcdef0123456789abcdef01234567   # v1.4.2"
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
            if ref.lower() in {"main", "master", "develop", "head", "trunk"}:
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
