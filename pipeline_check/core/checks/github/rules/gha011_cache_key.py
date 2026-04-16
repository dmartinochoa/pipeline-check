"""GHA-011 — cache key must not derive from attacker-controllable input."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps
from ._helpers import CACHE_TAINT_RE

RULE = Rule(
    id="GHA-011",
    title="Cache key derives from attacker-controllable input",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    recommendation=(
        "Build the cache key from values the attacker can't control: "
        "`${{ runner.os }}`, `${{ hashFiles('**/*.lock') }}` (only "
        "when the lockfile is enforced by branch protection), and "
        "the workflow file path. Never include `github.event.*` "
        "PR/issue fields, `github.head_ref`, or `inputs.*` in the "
        "key namespace."
    ),
    docs_note=(
        "`actions/cache` restores by key (and falls through "
        "`restore-keys` on miss). When the key includes a value the "
        "attacker controls (PR title, head ref, workflow_dispatch "
        "input), an attacker can plant a poisoned cache entry that a "
        "later default-branch run restores and treats as a clean "
        "build cache."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            uses = step.get("uses") or ""
            if not isinstance(uses, str) or "actions/cache@" not in uses:
                continue
            with_block = step.get("with") or {}
            if not isinstance(with_block, dict):
                continue
            for key_name in ("key", "restore-keys"):
                raw = with_block.get(key_name)
                if raw is None:
                    continue
                text = raw if isinstance(raw, str) else "\n".join(str(v) for v in raw)
                if CACHE_TAINT_RE.search(text):
                    offenders.append(f"{job_id}[{idx}].{key_name}")
    passed = not offenders
    desc = (
        "No actions/cache key derives from attacker-controllable input."
        if passed else
        f"actions/cache key/restore-keys derive from attacker-"
        f"controllable values in: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A PR can seed a "
        f"poisoned cache entry that a later default-branch run "
        f"restores and treats as a clean build cache."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
