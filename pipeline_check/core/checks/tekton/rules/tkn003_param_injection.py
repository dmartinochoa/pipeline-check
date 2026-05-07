"""TKN-003 — Param interpolation in step ``script:`` is unsafe."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TektonContext, iter_step_scripts

RULE = Rule(
    id="TKN-003",
    title="Tekton param interpolated unsafely in step script",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4", "CICD-SEC-1"),
    esf=("ESF-D-CODE-INTEGRITY",),
    cwe=("CWE-78",),
    recommendation=(
        "Don't interpolate ``$(params.<name>)`` directly into the step "
        "``script:``. Tekton substitutes the value before the shell "
        "parses it, so a parameter containing ``; rm -rf /`` runs as "
        "shell. Receive the parameter through ``env:`` "
        "(``valueFrom: ...`` or ``value: $(params.<name>)``) and "
        "reference the env var quoted in the script "
        "(``\"$NAME\"``); or pass it as a positional argument to a "
        "shell function."
    ),
    docs_note=(
        "Fires on any ``$(params.X)`` or ``$(workspaces.X.path)`` "
        "token inside a ``script:`` body that isn't already wrapped "
        "in double quotes (`\"$(params.X)\"`). Doesn't fire on the "
        "env-var indirection pattern, which is safe."
    ),
)

_UNSAFE_PARAM_RE = re.compile(
    r"(?<!\")\$\(params\.[A-Za-z0-9_-]+\)"
    r"|(?<!\")\$\(workspaces\.[A-Za-z0-9_-]+\.path\)"
)
# ``eval`` (and other shell-eval contexts) re-parses its argument as
# shell, so even quoted ``"$(params.X)"`` is unsafe inside eval. Match
# eval invocations regardless of quoting around the substitution.
_EVAL_PARAM_RE = re.compile(
    r"\beval\b[^\n]*?\$\(params\.[A-Za-z0-9_-]+\)"
    r"|\beval\b[^\n]*?\$\(workspaces\.[A-Za-z0-9_-]+\.path\)"
)


def check(ctx: TektonContext) -> Finding:
    offenders: list[str] = []
    examined = 0
    for doc in ctx.docs:
        if doc.kind not in ("Task", "ClusterTask"):
            continue
        examined += 1
        for sname, script in iter_step_scripts(doc):
            m = _UNSAFE_PARAM_RE.search(script) or _EVAL_PARAM_RE.search(script)
            if m is not None:
                offenders.append(
                    f"{doc.kind}/{doc.name} {sname}: {m.group(0)}"
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
        "No unsafe param interpolation in step scripts."
        if passed else
        f"{len(offenders)} step script(s) interpolate params unquoted: "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
