"""TKN-008, ``curl ... | sh`` and TLS bypass in step scripts."""
from __future__ import annotations

from ...base import CURL_PIPE_RE, TLS_BYPASS_RE, Finding, Severity
from ...rule import Rule
from ..base import TektonContext, iter_step_scripts

RULE = Rule(
    id="TKN-008",
    title="Tekton step script pipes remote install or disables TLS",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS", "ESF-D-COMMS-INTEGRITY"),
    cwe=("CWE-494", "CWE-829", "CWE-295"),
    recommendation=(
        "Replace ``curl ... | sh`` with a download-then-verify-then-"
        "execute pattern. Drop TLS-bypass flags (``curl -k``, ``git "
        "config http.sslverify false``); install the missing CA into "
        "the step image instead. Both forms let an attacker "
        "controlling DNS / a transparent proxy substitute the script "
        "the step runs."
    ),
    docs_note=(
        "Uses the cross-provider ``CURL_PIPE_RE`` and ``TLS_BYPASS_RE`` "
        "regexes so detection is consistent with the GHA / GitLab / "
        "CircleCI / Cloud Build providers."
    ),
)


def check(ctx: TektonContext) -> Finding:
    offenders: list[str] = []
    examined = 0
    for doc in ctx.docs:
        if doc.kind not in ("Task", "ClusterTask"):
            continue
        examined += 1
        for sname, script in iter_step_scripts(doc):
            if CURL_PIPE_RE.search(script):
                offenders.append(
                    f"{doc.kind}/{doc.name} {sname}: curl-pipe-shell"
                )
                continue
            if TLS_BYPASS_RE.search(script):
                offenders.append(
                    f"{doc.kind}/{doc.name} {sname}: TLS bypass"
                )
    if examined == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description="No Task / ClusterTask documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No curl-pipe-shell or TLS bypass in step scripts."
        if passed else
        f"{len(offenders)} unsafe install / TLS pattern(s): "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
