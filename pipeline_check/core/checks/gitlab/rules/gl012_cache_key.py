"""GL-012 — cache key must not derive from MR-controlled CI variables."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from ._helpers import CACHE_TAINT_RE


RULE = Rule(
    id="GL-012",
    title="Cache key derives from MR-controlled CI variable",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    recommendation=(
        "Build the cache key from values the MR can't control: "
        "lockfile contents (`files: [Cargo.lock]`), the job name, "
        "and `$CI_PROJECT_NAMESPACE`. Never reference "
        "`$CI_MERGE_REQUEST_*` or `$CI_COMMIT_BRANCH` from a cache "
        "key namespace."
    ),
    docs_note=(
        "GitLab caches restore by key prefix. When the key includes "
        "an MR-controlled variable, an attacker can poison a cache "
        "entry that a later default-branch pipeline restores."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []

    def _scan_cache(cache: Any, where: str) -> None:
        if not isinstance(cache, dict):
            return
        key = cache.get("key")
        if isinstance(key, str):
            if CACHE_TAINT_RE.search(key):
                offenders.append(f"{where}.cache.key")
        elif isinstance(key, dict):
            prefix = key.get("prefix")
            if isinstance(prefix, str) and CACHE_TAINT_RE.search(prefix):
                offenders.append(f"{where}.cache.key.prefix")

    _scan_cache(doc.get("cache"), "<top>")
    for name, job in iter_jobs(doc):
        _scan_cache(job.get("cache"), name)
    passed = not offenders
    desc = (
        "No cache key derives from MR-controlled CI variables."
        if passed else
        f"Cache key/prefix derives from MR-controlled variable(s) "
        f"in: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. An MR can seed a "
        f"poisoned cache entry that a later default-branch pipeline "
        f"restores and treats as clean."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
