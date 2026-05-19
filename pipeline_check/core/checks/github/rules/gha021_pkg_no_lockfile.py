"""GHA-021, package install without lockfile enforcement."""
from __future__ import annotations

from typing import Any

from ...base import PKG_NO_LOCKFILE_RE, Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-021",
    title="Package install without lockfile enforcement",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Use lockfile-enforcing install commands: `npm ci` instead of "
        "`npm install`, `pip install --require-hashes -r requirements.txt`, "
        "`yarn install --frozen-lockfile`, `bundle install --frozen`, "
        "and `go install tool@v1.2.3`."
    ),
    docs_note=(
        "Detects package-manager install commands that do not enforce a "
        "lockfile or hash verification. Without lockfile enforcement the "
        "resolver pulls whatever version is currently latest, exactly "
        "the window a supply-chain attacker exploits."
    ),
)

def check(path: str, doc: dict[str, Any]) -> Finding:
    matches: list[str] = []
    # Preserve insertion order so the anchor set is reproducible across
    # runs; a job with multiple offending install lines contributes
    # once. AC-008 intersects this with GHA-029's anchors to confirm
    # the install AND the integrity bypass land in the same job (the
    # dependency-confusion / typosquatting window).
    anchor_jobs: dict[str, None] = {}
    for job_id, job in iter_jobs(doc):
        for step in iter_steps(job):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            for m in PKG_NO_LOCKFILE_RE.findall(run.lower()):
                matches.append(m)
                anchor_jobs[job_id] = None
    passed = not matches
    desc = (
        "All package install commands enforce lockfile integrity."
        if passed else
        f"Package install without lockfile enforcement detected: "
        f"{', '.join(m.strip() for m in matches[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        job_anchors=tuple(anchor_jobs),
    )
