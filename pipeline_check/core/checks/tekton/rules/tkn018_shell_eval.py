"""TKN-018. Dangerous shell idiom (eval, sh -c variable, backtick exec)."""
from __future__ import annotations

from ..._primitives import shell_eval
from ...base import Finding, Severity
from ...rule import Rule
from ..base import TektonContext, iter_step_scripts

RULE = Rule(
    id="TKN-018",
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
        "Complements TKN-003 (untrusted ``$(params.*)`` interpolated into a "
        "step script). This rule fires on intrinsically risky idioms, "
        "``eval``, ``sh -c \"$X\"``, backtick exec, regardless of whether "
        "the input source is currently trusted, because the idiom hands a "
        "value full shell-grammar reach. Uses the shared "
        "``_primitives.shell_eval`` detector over each Task / ClusterTask "
        "step ``script``. The Tekton analog of GHA-028 / GL-026 / BB-026 / "
        "ADO-027 / CC-027 / BK-016 / DR-017."
    ),
    known_fp=(
        "``eval \"$(ssh-agent -s)\"`` and similar ``eval "
        "\"$(<literal-tool>)\"`` bootstrap idioms are intentionally NOT "
        "flagged, the substituted command is literal, only its output is "
        "eval'd.",
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
            for h in shell_eval.scan(script):
                offenders.append(f"{doc.kind}/{doc.name} {sname}: {h.snippet}")
    if examined == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description="No Task / ClusterTask documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No step script uses a dangerous shell idiom."
        if passed else
        f"{len(offenders)} step script(s) use a dangerous shell idiom: "
        f"{'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
