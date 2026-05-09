"""GL-025, pipeline contains evidence of malicious activity."""
from __future__ import annotations

from typing import Any

from ..._malicious import find_malicious_patterns
from ...base import Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="GL-025",
    title="Pipeline contains indicators of malicious activity",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4", "CICD-SEC-7"),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-506", "CWE-913"),
    recommendation=(
        "Treat as a potential compromise. Identify the MR that added "
        "the matching job(s), rotate any credentials the pipeline can "
        "reach, and audit recent runs for outbound traffic to the "
        "matched hosts. A legitimate red-team exercise should be "
        "time-bounded via ``.pipelinecheckignore`` with ``expires:``."
    ),
    docs_note=(
        "Fires on concrete indicators (reverse shells, base64-decoded "
        "execution, miner binaries, Discord/Telegram webhooks, "
        "``webhook.site`` callbacks, ``env | curl`` credential dumps, "
        "``history -c`` audit erasure). Orthogonal to GL-003 (curl "
        "pipe) and GL-017 (Docker insecure flags). Those flag risky "
        "defaults; this flags evidence."
    ),
    known_fp=(
        "Security-training repositories, CTF challenges, and red-team "
        "exercise pipelines legitimately contain reverse-shell strings "
        "or exfil domains as literals. Matches inside YAML keys / HCL "
        "attributes whose names contain ``example``, ``fixture``, "
        "``sample``, ``demo``, or ``test`` are auto-suppressed; bare "
        "lines in a production pipeline still fire.",
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
