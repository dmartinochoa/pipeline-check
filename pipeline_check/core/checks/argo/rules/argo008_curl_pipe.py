"""ARGO-008 — ``curl ... | sh`` and TLS bypass in script sources."""
from __future__ import annotations

from typing import Any

from ...base import CURL_PIPE_RE, TLS_BYPASS_RE, Finding, Severity
from ...rule import Rule
from ..base import ArgoContext, iter_containers, iter_templates, template_name

RULE = Rule(
    id="ARGO-008",
    title="Argo script source pipes remote install or disables TLS",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS", "ESF-D-COMMS-INTEGRITY"),
    cwe=("CWE-494", "CWE-829", "CWE-295"),
    recommendation=(
        "Replace ``curl ... | sh`` with a download-then-verify-then-"
        "execute pattern. Drop TLS-bypass flags (``curl -k``, ``git "
        "config http.sslverify false``); install the missing CA into "
        "the template image instead. Both forms let an attacker "
        "controlling DNS / a transparent proxy substitute the script "
        "the workflow runs."
    ),
    docs_note=(
        "Walks ``script.source`` and joined ``container.args`` text "
        "with the cross-provider ``CURL_PIPE_RE`` and "
        "``TLS_BYPASS_RE`` regexes."
    ),
)


def _container_text(container: dict[str, Any]) -> str:
    parts: list[str] = []
    src = container.get("source")
    if isinstance(src, str):
        parts.append(src)
    for key in ("command", "args"):
        v = container.get(key)
        if isinstance(v, list):
            parts.extend(s for s in v if isinstance(s, str))
        elif isinstance(v, str):
            parts.append(v)
    return "\n".join(parts)


def check(ctx: ArgoContext) -> Finding:
    offenders: list[str] = []
    for doc in ctx.docs:
        for idx, tmpl in enumerate(iter_templates(doc)):
            for container in iter_containers(tmpl):
                blob = _container_text(container)
                if not blob:
                    continue
                if CURL_PIPE_RE.search(blob):
                    offenders.append(
                        f"{doc.kind}/{doc.name} "
                        f"{template_name(tmpl, idx)}: curl-pipe-shell"
                    )
                    continue
                if TLS_BYPASS_RE.search(blob):
                    offenders.append(
                        f"{doc.kind}/{doc.name} "
                        f"{template_name(tmpl, idx)}: TLS bypass"
                    )
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Argo documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No curl-pipe-shell or TLS bypass in template scripts."
        if passed else
        f"{len(offenders)} unsafe install / TLS pattern(s): "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
