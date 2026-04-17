"""BB-025 — pipeline contains evidence of malicious activity."""
from __future__ import annotations

from typing import Any

from ..._malicious import find_malicious_patterns
from ...base import Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="BB-025",
    title="Pipeline contains indicators of malicious activity",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4", "CICD-SEC-7"),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-506", "CWE-913"),
    recommendation=(
        "Treat as a potential compromise. Identify the PR that added "
        "the matching step(s), rotate any credentials referenced from "
        "the pipeline's variable groups, and audit recent builds."
    ),
    docs_note=(
        "Specific indicators only (reverse shells, base64-decoded "
        "execution, miner binaries, Discord/Telegram webhooks, "
        "credential-dump pipes, audit-erasure commands). Does not "
        "replace BB-014 (TLS bypass) or BB-013 (Docker insecure) — "
        "those are hygiene; this is evidence."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    hits = find_malicious_patterns(blob_lower(doc))
    if not hits:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No indicators of malicious activity detected.",
            recommendation="No action required.", passed=True,
        )
    categories = sorted({c for c, _n, _e in hits})
    summary = "; ".join(
        f"{name} ({excerpt!r})" for _cat, name, excerpt in hits[:3]
    )
    desc = (
        f"{len(hits)} indicator(s) of malicious activity "
        f"({', '.join(categories)}). Examples: {summary}"
        f"{'...' if len(hits) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
