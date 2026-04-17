"""GHA-027 — workflow contains evidence of malicious activity."""
from __future__ import annotations

from typing import Any

from ..._malicious import find_malicious_patterns
from ...base import Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="GHA-027",
    title="Workflow contains indicators of malicious activity",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4", "CICD-SEC-7"),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-506", "CWE-913"),
    recommendation=(
        "Treat this as a potential pipeline compromise. Inspect the "
        "matching step(s), identify the author and the PR that "
        "introduced them, rotate any credentials the workflow has "
        "access to, and audit CloudTrail/AuditLogs for exfil. If the "
        "match is a legitimate red-team exercise, whitelist via "
        "``.pipelinecheckignore`` with an ``expires:`` date — never a "
        "permanent suppression."
    ),
    docs_note=(
        "Distinct from the hygiene checks. GHA-016 flags ``curl | "
        "bash`` as a risky default; this rule fires only on concrete "
        "indicators — reverse shells, base64-decoded execution, known "
        "miner binaries or pool URLs, exfil-channel domains, "
        "credential-dump pipes, history-erasure commands. Categories "
        "reported: ``obfuscated-exec``, ``reverse-shell``, "
        "``crypto-miner``, ``exfil-channel``, ``credential-exfil``, "
        "``audit-erasure``."
    ),
    known_fp=(
        "Security-training repositories, CTF challenges, and red-team "
        "exercise workflows legitimately contain reverse-shell strings "
        "or exfil domains as literals. Matches inside YAML keys / HCL "
        "attributes whose names contain ``example``, ``fixture``, "
        "``sample``, ``demo``, or ``test`` are auto-suppressed; bare "
        "lines in a production workflow still fire.",
        "Defaults to LOW confidence. Filter with ``--min-confidence "
        "MEDIUM`` to ignore all matches; the rule still surfaces the "
        "hit for teams that want to spot-check.",
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
