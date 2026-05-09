"""JF-029. Jenkinsfile contains evidence of malicious activity."""
from __future__ import annotations

from ..._malicious import find_malicious_patterns
from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-029",
    title="Jenkinsfile contains indicators of malicious activity",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4", "CICD-SEC-7"),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-506", "CWE-913"),
    recommendation=(
        "Treat as a potential compromise. Identify the commit that "
        "introduced the matching stage(s), rotate Jenkins credentials "
        "the job can reach, review controller/agent audit logs for "
        "outbound traffic to the matched hosts, and re-image the agent "
        "pool if the compromise may have persisted."
    ),
    docs_note=(
        "Distinct from JF-016 (curl pipe) and JF-019 (Groovy sandbox "
        "escape). Those flag risky defaults; this flags concrete "
        "evidence, reverse shells, base64-decoded execution, miner "
        "binaries, exfil channels, credential-dump pipes, shell-"
        "history erasure. Runs on the comment-stripped Groovy text so "
        "``// cosign verify … // webhook.site`` in a legitimate "
        "annotation doesn't false-positive."
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


def check(jf: Jenkinsfile) -> Finding:
    # Use the comment-stripped text so annotations like
    # ``// TODO: remove webhook.site test`` don't trigger.
    text = (jf.text_no_comments or jf.text).lower()
    hits = find_malicious_patterns(text)
    if not hits:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=jf.path,
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
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
