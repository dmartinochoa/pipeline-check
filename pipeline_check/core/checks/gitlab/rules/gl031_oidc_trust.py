"""GL-031 — `id_tokens:` block missing audience pin or environment binding."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs


def _id_tokens_block(job: dict[str, Any]) -> dict[str, Any] | None:
    """Return the job's ``id_tokens`` mapping, or None if absent.

    GitLab uses ``id_tokens:`` (a mapping of token-name → spec) at the
    job level to request JWTs for OIDC federation. An empty value or
    a non-dict shape is treated as absent — no token actually issues.
    """
    block = job.get("id_tokens")
    if isinstance(block, dict) and block:
        return block
    return None


def _aud_pinned(token_spec: Any) -> bool:
    """Return True if *token_spec* pins ``aud:`` to a non-wildcard value.

    A missing ``aud:``, an empty string, or a literal ``"*"`` defeats
    the audience-binding contract — the token is acceptable to any
    consumer that trusts GitLab's OIDC issuer.
    """
    if not isinstance(token_spec, dict):
        return False
    aud = token_spec.get("aud")
    if isinstance(aud, str):
        return bool(aud.strip()) and aud.strip() != "*"
    if isinstance(aud, list):
        # Multiple audiences are allowed; every entry must be a
        # non-wildcard non-empty string.
        return bool(aud) and all(
            isinstance(a, str) and a.strip() and a.strip() != "*"
            for a in aud
        )
    return False


RULE = Rule(
    id="GL-031",
    title="id_tokens: missing audience pin or environment binding",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-284",),
    recommendation=(
        "For every job that declares an ``id_tokens:`` block, pin a "
        "non-wildcard ``aud:`` (a literal string the consumer trusts) "
        "AND bind the job to a protected ``environment:``. Audience "
        "pinning prevents token replay against unintended consumers; "
        "the environment binding gates which refs can drive the "
        "assume-role on the consumer side."
    ),
    docs_note=(
        "Pairs with IAM-008 — IAM-008 verifies the cloud-side trust "
        "policy pins audience + subject; this rule verifies the "
        "GitLab-side workflow can't request a token without an "
        "audience claim or without a deployment gate."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        block = _id_tokens_block(job)
        if block is None:
            continue
        for token_name, spec in block.items():
            if not _aud_pinned(spec):
                offenders.append(f"{job_id}.id_tokens.{token_name}: missing/wildcard aud")
        if "environment" not in job:
            offenders.append(f"{job_id}: id_tokens declared without environment")
    passed = not offenders
    desc = (
        "Every job with ``id_tokens:`` pins a non-wildcard audience "
        "and binds to a protected environment."
        if passed else
        f"OIDC trust scoping is incomplete: {'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Without an audience "
        f"pin and environment gate, any branch push can drive a "
        f"federated assume-role on the consumer side."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
