"""ARGO-019. Dangerous shell idiom (eval, sh -c variable, backtick exec)."""
from __future__ import annotations

from ..._primitives import shell_eval
from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoContext, iter_containers, iter_templates, template_name

RULE = Rule(
    id="ARGO-019",
    title="Dangerous shell idiom (eval, sh -c variable, backtick exec)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-95",),
    recommendation=(
        "Replace ``eval \"$VAR\"`` / ``sh -c \"$VAR\"`` / backtick exec "
        "with direct command invocation. Validate or allow-list any value "
        "that must feed a dynamic command at the boundary."
    ),
    docs_note=(
        "Complements ARGO-005 (untrusted ``inputs.parameters.*`` "
        "interpolated into a template script / args). This rule fires on "
        "intrinsically risky idioms, ``eval``, ``sh -c \"$X\"``, backtick "
        "exec, regardless of whether the input source is currently trusted, "
        "because the idiom hands a value full shell-grammar reach. Uses the "
        "shared ``_primitives.shell_eval`` detector over each template "
        "``script.source`` and ``container.args``. The Argo analog of "
        "GHA-028 / GL-026 / BB-026 / ADO-027 / CC-027 / BK-016 / DR-017."
    ),
    known_fp=(
        "``eval \"$(ssh-agent -s)\"`` and similar ``eval "
        "\"$(<literal-tool>)\"`` bootstrap idioms are intentionally NOT "
        "flagged, the substituted command is literal, only its output is "
        "eval'd.",
    ),
)


def check(ctx: ArgoContext) -> Finding:
    offenders: list[str] = []
    for doc in ctx.docs:
        for idx, tmpl in enumerate(iter_templates(doc)):
            tname = template_name(tmpl, idx)
            for container in iter_containers(tmpl):
                texts: list[str] = []
                src = container.get("source")
                if isinstance(src, str):
                    texts.append(src)
                # ``command: ["sh","-c","<script>"]`` puts the shell body
                # in ``command``; scan both ``command`` and ``args``.
                for field in ("command", "args"):
                    value = container.get(field)
                    if isinstance(value, list):
                        texts += [a for a in value if isinstance(a, str)]
                for text in texts:
                    for h in shell_eval.scan(text):
                        offenders.append(
                            f"{doc.kind}/{doc.name} {tname}: {h.snippet}"
                        )
    passed = not offenders
    desc = (
        "No template script uses a dangerous shell idiom."
        if passed else
        f"{len(offenders)} template script(s) use a dangerous shell idiom: "
        f"{'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
