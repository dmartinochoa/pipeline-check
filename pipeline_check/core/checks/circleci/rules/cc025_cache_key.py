"""CC-025 — CircleCI cache key must not derive from attacker-controllable input."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ._helpers import CACHE_TAINT_RE

RULE = Rule(
    id="CC-025",
    title="Cache key derives from attacker-controllable input",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-345",),
    recommendation=(
        "Derive ``save_cache`` and ``restore_cache`` keys from values "
        "the attacker can't control — the lockfile checksum "
        "(``{{ checksum \"package-lock.json\" }}``) and the build "
        "variant, not ``{{ .Branch }}`` or ``${CIRCLE_PR_NUMBER}``. "
        "A PR-scoped branch can seed a poisoned cache entry that a "
        "later main-branch run restores as trusted."
    ),
    docs_note=(
        "CircleCI's ``restore_cache`` falls through each listed key "
        "until it finds a hit. When one of those keys is derived from "
        "``CIRCLE_BRANCH``, ``CIRCLE_TAG``, or ``CIRCLE_PR_*`` — "
        "values an attacker can set by opening a PR — the attacker "
        "can plant a cache entry that a protected job later uses. "
        "Uses checksum-of-lockfile or a static version label instead."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    jobs = doc.get("jobs") or {}
    if not isinstance(jobs, dict):
        return _passed(path)
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for idx, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            for step_type in ("save_cache", "restore_cache"):
                block = step.get(step_type)
                if not isinstance(block, dict):
                    continue
                # ``save_cache`` uses ``key``; ``restore_cache`` uses
                # ``keys`` (list) or ``key`` (single).
                raw_keys: list[str] = []
                if isinstance(block.get("key"), str):
                    raw_keys.append(block["key"])
                if isinstance(block.get("keys"), list):
                    raw_keys.extend(k for k in block["keys"] if isinstance(k, str))
                for k in raw_keys:
                    if CACHE_TAINT_RE.search(k):
                        offenders.append(f"{job_name}[{idx}].{step_type}")
                        break
    passed = not offenders
    desc = (
        "No save_cache/restore_cache key derives from attacker-controllable input."
        if passed else
        f"Cache key(s) derive from attacker-controllable values in: "
        f"{', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}. A PR can seed a "
        "poisoned cache entry that a protected job later restores."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )


def _passed(path: str) -> Finding:
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description="No jobs use cache steps.",
        recommendation="No action required.", passed=True,
    )
