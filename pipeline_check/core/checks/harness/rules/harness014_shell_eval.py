"""HARNESS-014. Dangerous shell idiom (eval, sh -c variable, backtick exec)."""
from __future__ import annotations

from ..._primitives import shell_eval
from ...base import Finding, Severity
from ...rule import Rule
from ..base import HarnessPipeline, iter_steps, step_command_text, step_label

RULE = Rule(
    id="HARNESS-014",
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
        "Complements HARNESS-002 (untrusted ``<+codebase.*>`` / "
        "``<+trigger.*>`` expression in a step command). This rule fires on "
        "intrinsically risky idioms, ``eval``, ``sh -c \"$X\"``, backtick "
        "exec, regardless of whether the input source is currently trusted, "
        "because the idiom hands a value full shell-grammar reach. Uses the "
        "shared ``_primitives.shell_eval`` detector over each step "
        "``command``. The Harness analog of GHA-028 / GL-026 / BB-026 / "
        "ADO-027 / CC-027 / BK-016 / DR-017."
    ),
    known_fp=(
        "``eval \"$(ssh-agent -s)\"`` and similar ``eval "
        "\"$(<literal-tool>)\"`` bootstrap idioms are intentionally NOT "
        "flagged, the substituted command is literal, only its output is "
        "eval'd.",
    ),
)


def check(pipeline: HarnessPipeline) -> Finding:
    offenders: list[str] = []
    for stage_id, step in iter_steps(pipeline):
        text = step_command_text(step)
        if not text:
            continue
        for h in shell_eval.scan(text):
            offenders.append(f"{step_label(stage_id, step)}: {h.snippet}")
    passed = not offenders
    desc = (
        "No step command uses a dangerous shell idiom."
        if passed else
        f"{len(offenders)} step command(s) use a dangerous shell idiom: "
        f"{'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
