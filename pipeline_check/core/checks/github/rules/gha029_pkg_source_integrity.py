"""GHA-029, package install from git URL / local path / tarball URL.

GHA-021 catches install commands that skip the lockfile flag. This
rule catches the adjacent class: installs that do run a resolver
but aim it at a source the lockfile cannot protect, unpinned git
URLs (``git+https://…`` without a commit SHA), local paths
(``./dir``, ``file:…``, absolute paths), and direct tarball
downloads.
"""
from __future__ import annotations

from typing import Any

from ..._primitives import lockfile_integrity
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-029",
    title="Package install bypasses registry integrity (git / path / tarball source)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin git dependencies to a commit SHA "
        "(``pip install git+https://…/repo@<sha>``, "
        "``cargo install --git … --rev <sha>``). Publish private "
        "packages to an internal registry instead of installing "
        "from a filesystem path or tarball URL."
    ),
    docs_note=(
        "Package installs that pull from ``git+…`` without a pinned "
        "commit, from a local path (``./dir``, ``file:…``, absolute "
        "paths), or from a direct tarball URL are invisible to the "
        "normal lockfile integrity controls. A moving branch head, "
        "a sibling checkout the build assumes exists, or a tarball "
        "whose hash isn't verified all give an attacker who controls "
        "any of those surfaces the ability to substitute code into "
        "the build."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    hits: list[lockfile_integrity.LockfileIssue] = []
    # Preserve insertion order so the anchor set is reproducible across
    # runs. AC-008 intersects this with GHA-021's anchors to confirm
    # the integrity bypass AND the lockfile miss share a job, the
    # tight dependency-confusion / typosquatting reachability.
    anchor_jobs: dict[str, None] = {}
    for job_id, job in iter_jobs(doc):
        for step in iter_steps(job):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            found = lockfile_integrity.scan(run.lower())
            if found:
                hits.extend(found)
                anchor_jobs[job_id] = None
    passed = not hits
    kinds = sorted({h.kind for h in hits})
    desc = (
        "No integrity-bypassing package installs detected in this workflow."
        if passed else
        f"{len(hits)} integrity-bypassing package install(s) detected "
        f"({', '.join(kinds)}): "
        f"{'; '.join(sorted({h.snippet for h in hits})[:3])}"
        f"{'…' if len({h.snippet for h in hits}) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        job_anchors=tuple(anchor_jobs),
    )
