"""ARGO-005 — ``{{inputs.parameters.X}}`` interpolated unsafely."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoContext, iter_containers, iter_templates, template_name

RULE = Rule(
    id="ARGO-005",
    title="Argo input parameter interpolated unsafely in script / args",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4", "CICD-SEC-1"),
    esf=("ESF-D-CODE-INTEGRITY",),
    cwe=("CWE-78",),
    recommendation=(
        "Don't interpolate ``{{inputs.parameters.<name>}}`` directly "
        "into ``script.source`` or ``container.args``. Argo "
        "substitutes the value before the shell parses it, so a "
        "parameter containing ``; rm -rf /`` runs as shell. Pass "
        "the parameter via ``env:`` "
        "(``value: '{{inputs.parameters.<name>}}'``) and reference "
        "the env var quoted in the script (``\"$NAME\"``); or use "
        "``inputs.artifacts`` for file payloads."
    ),
    docs_note=(
        "Fires on any ``{{inputs.parameters.X}}``, "
        "``{{workflow.parameters.X}}``, or ``{{item.X}}`` token "
        "inside a ``script.source`` body or a ``container.args`` "
        "string that isn't already wrapped in quotes. Doesn't fire "
        "on the env-var indirection pattern, which is safe."
    ),
)

_UNSAFE_PARAM_RE = re.compile(
    r"(?<!['\"])\{\{(?:inputs|workflow|item)\.parameters?\.[A-Za-z0-9_-]+\}\}"
    r"|(?<!['\"])\{\{item\.[A-Za-z0-9_-]+\}\}"
    r"|(?<!['\"])\{\{item\}\}"
)


def _scan_text(text: str) -> list[str]:
    hits = []
    for m in _UNSAFE_PARAM_RE.finditer(text):
        hits.append(m.group(0))
    return hits


def check(ctx: ArgoContext) -> Finding:
    offenders: list[str] = []
    for doc in ctx.docs:
        for idx, tmpl in enumerate(iter_templates(doc)):
            for container in iter_containers(tmpl):
                src = container.get("source")
                if isinstance(src, str):
                    hits = _scan_text(src)
                    if hits:
                        offenders.append(
                            f"{doc.kind}/{doc.name} "
                            f"{template_name(tmpl, idx)} script: {hits[0]}"
                        )
                        continue
                args = container.get("args")
                if isinstance(args, list):
                    found = False
                    for a in args:
                        if isinstance(a, str):
                            hits = _scan_text(a)
                            if hits:
                                offenders.append(
                                    f"{doc.kind}/{doc.name} "
                                    f"{template_name(tmpl, idx)} args: {hits[0]}"
                                )
                                found = True
                                break
                    if found:
                        continue
                cmd = container.get("command")
                if isinstance(cmd, list):
                    for c in cmd:
                        if isinstance(c, str):
                            hits = _scan_text(c)
                            if hits:
                                offenders.append(
                                    f"{doc.kind}/{doc.name} "
                                    f"{template_name(tmpl, idx)} command: {hits[0]}"
                                )
                                break
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Argo documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No unsafe parameter interpolation in scripts / args."
        if passed else
        f"{len(offenders)} template(s) interpolate parameters "
        f"unquoted: {'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
