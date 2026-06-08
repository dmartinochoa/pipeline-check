"""DR-017. Dangerous shell idioms in Drone step commands."""
from __future__ import annotations

from ..._primitives import shell_eval
from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    Pipeline,
    is_container_pipeline,
    iter_steps,
    step_commands,
    step_label,
)

RULE = Rule(
    id="DR-017",
    title="Dangerous shell idiom (eval, sh -c variable, backtick exec)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-95",),
    recommendation=(
        "Replace ``eval \"$VAR\"`` / ``sh -c \"$VAR\"`` / backtick "
        "exec with direct command invocation. Validate or allow-list "
        "any value that must feed a dynamic command at the boundary."
    ),
    docs_note=(
        "Complements DR-003 (untrusted ``${DRONE_*}`` variable in a "
        "command). This rule fires on intrinsically risky idioms, "
        "``eval``, ``sh -c \"$X\"``, backtick exec, regardless of "
        "whether the input source is currently trusted, because the "
        "idiom hands a value full shell-grammar reach. Uses the shared "
        "``_primitives.shell_eval`` detector and scans every "
        "``commands:`` entry on every step. The Drone analog of "
        "GHA-028 / GL-026 / BB-026 / ADO-027 / CC-027 / BK-016."
    ),
    known_fp=(
        "``eval \"$(ssh-agent -s)\"`` and similar "
        "``eval \"$(<literal-tool>)\"`` bootstrap idioms are "
        "intentionally NOT flagged, the substituted command is "
        "literal, only its output is eval'd.",
    ),
    exploit_example=(
        "# Vulnerable: ``eval`` on a variable that came from step\n"
        "# environment / build metadata gives that value full\n"
        "# shell-grammar reach. ``sh -c $RAW`` on an unquoted\n"
        "# variable is the same shape.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "steps:\n"
        "  - name: build\n"
        "    image: alpine:3.19@sha256:abc123...\n"
        "    commands:\n"
        "      - eval \"$BUILD_CMD\"\n"
        "      - sh -c $RAW_HOOK\n"
        "\n"
        "# Safe: invoke a script you own with the value as a quoted\n"
        "# argument; let the script validate against an allow-list.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "steps:\n"
        "  - name: build\n"
        "    image: alpine:3.19@sha256:abc123...\n"
        "    commands:\n"
        "      - ./scripts/dispatch.sh \"$BUILD_CMD\""
    ),
)


def check(pipeline: Pipeline) -> Finding:
    if not is_container_pipeline(pipeline):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path,
            description=(
                "Pipeline type is not container-flavored, no "
                "shell command surface to scan."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for idx, step in iter_steps(pipeline):
        for cmd in step_commands(step):
            hits = shell_eval.scan(cmd)
            if hits:
                offenders.append(
                    f"steps.{step_label(step, idx)}: "
                    f"{hits[0].snippet[:80]}"
                )
                break
    passed = not offenders
    desc = (
        "No step uses a dangerous shell idiom."
        if passed else
        f"{len(offenders)} step(s) use a dangerous shell idiom: "
        f"{'; '.join(offenders[:3])}"
        f"{'...' if len(offenders) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
