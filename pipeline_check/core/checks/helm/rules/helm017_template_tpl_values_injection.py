"""HELM-017. Template renders an untrusted value through ``tpl``."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import HelmContext

RULE = Rule(
    id="HELM-017",
    title="Template renders an untrusted value through tpl",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1336", "CWE-94"),
    recommendation=(
        "Don't pass a ``.Values``-derived string through ``tpl``. "
        "``{{ tpl .Values.x . }}`` re-evaluates the value as a Go "
        "template with the full chart context, so any operator (or "
        "anyone who can influence the values supplied at install "
        "time) who sets ``x`` to a template expression gets it "
        "executed: a server-side template-injection sink that can "
        "read other ``.Values`` (including rendered secrets), call "
        "template functions, and shape arbitrary manifest output. "
        "Render the value as plain data instead (``{{ .Values.x }}`` "
        "with the appropriate quoting / ``toYaml``), or, if dynamic "
        "templating is genuinely required, restrict it to a "
        "chart-internal constant string, never a user-supplied "
        "value."
    ),
    docs_note=(
        "Scans each chart's ``templates/`` files for a Go-template "
        "action that calls ``tpl`` on a ``.Values`` expression "
        "(``{{ tpl .Values.x . }}``, ``{{ tpl (printf ... "
        ".Values.x) . }}``, etc.). ``tpl`` of a constant string "
        "literal or a non-``.Values`` expression is not flagged.\n\n"
        "A chart SSTI sink the K8s render pass can't see: by the "
        "time ``helm template`` has run, the injection has already "
        "been evaluated, so the risk is only visible in the "
        "unrendered template source this rule reads."
    ),
    known_fp=(
        "A chart that uses ``tpl`` on a value it fully controls "
        "(a constant default the operator is not expected to "
        "override) is lower risk. The rule still flags it because "
        "the ``.Values`` indirection makes the value override-able; "
        "suppress per template with a rationale once you've "
        "confirmed the value can't carry attacker input.",
    ),
    incident_refs=(
        "Helm chart SSTI class: passing operator-supplied values "
        "through ``tpl`` lets a values override inject template "
        "logic that exfiltrates other rendered values (including "
        "secrets) or reshapes the manifest, the chart-template "
        "analog of server-side template injection.",
    ),
    exploit_example=(
        "# Vulnerable template: tpl on a user-supplied value.\n"
        "# templates/configmap.yaml\n"
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata:\n"
        "  name: app-config\n"
        "data:\n"
        "  greeting: {{ tpl .Values.greeting . }}\n"
        "\n"
        "# Attack: an operator (or a compromised values source) sets\n"
        "#   greeting: '{{ .Values.dbPassword }}'\n"
        "# tpl re-evaluates it with the full context, so the rendered\n"
        "# ConfigMap now leaks the DB password into plain data.\n"
        "\n"
        "# Safe: render as data, no re-evaluation.\n"
        "  greeting: {{ .Values.greeting | quote }}\n"
    ),
)


# A Go-template action that calls ``tpl`` and references ``.Values``
# in the same action. Single-action (no embedded ``}}``); the common
# real-world shape. ``[^{}]`` avoids spanning across action boundaries.
_TPL_VALUES_RE = re.compile(
    r"\{\{-?[^{}]*\btpl\b[^{}]*\.Values[^{}]*-?\}\}",
)


def check(ctx: HelmContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for chart in ctx.charts:
        for tpath, text in chart.templates:
            for m in _TPL_VALUES_RE.finditer(text):
                line_no = text[: m.start()].count("\n") + 1
                offenders.append(f"{chart.name}: {tpath}:{line_no}")
                locations.append(Location(
                    path=tpath, start_line=line_no, end_line=line_no,
                ))
    passed = not offenders
    desc = (
        "No template renders a .Values value through tpl."
        if passed else
        f"{len(offenders)} template(s) pass a .Values value to "
        f"``tpl``: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. ``tpl`` re-evaluates "
        f"the value as a Go template, a server-side "
        f"template-injection sink for operator-supplied input."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="helm/charts", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
