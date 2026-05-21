"""TKN-015. Workspace ``subPath`` interpolates a Task parameter."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TektonContext, step_name, task_steps

RULE = Rule(
    id="TKN-015",
    title="Workspace subPath interpolates a Task parameter (path traversal)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-5"),
    esf=("ESF-D-CODE-INTEGRITY", "ESF-D-RUNTIME-HARDENING"),
    cwe=("CWE-22", "CWE-73"),
    recommendation=(
        "Pin every workspace ``subPath:`` to a static literal that "
        "your team controls. ``subPath: build/output`` is fine; "
        "``subPath: $(params.target_dir)`` is not, because a "
        "parameter-driven sub-path lets an attacker break out of "
        "the workspace and write into a sibling directory of the "
        "shared volume. Tekton resolves ``$(params.x)`` substitution "
        "in workspace bindings before the volume mount happens, so "
        "``../../../etc`` lands as a real path. If you genuinely "
        "need a runtime-chosen sub-path, sanitise the parameter "
        "with a step-level pre-check (``case`` against an allow-"
        "list, reject anything containing ``..``) and pass the "
        "validated value through a result rather than the raw "
        "parameter."
    ),
    docs_note=(
        "Tekton's ``$(params.x)`` substitution is performed on "
        "every string field of the resolved ``TaskRun`` body, "
        "including a step-level workspace binding's ``subPath``. "
        "TKN-003 catches the same parameter being interpolated "
        "into a step's script body; TKN-015 catches the "
        "complementary file-system breakout vector that script-"
        "only detection misses, the value never appears in a "
        "shell command, only in the volume-mount config.\n\n"
        "The detection scans the step-level ``workspaces:`` list "
        "(``spec.steps[*].workspaces[*].subPath``) for any "
        "``$(params.<name>)`` reference. ``$(workspaces.x.path)`` "
        "expansions are unaffected because those are not pusher-"
        "controlled."
    ),
    known_fp=(
        "Some teams use a parameter to select between a small "
        "set of allowed sub-paths and rely on a step pre-check "
        "to reject anything off-list. The rule has no way to "
        "see that pre-check; suppress on the specific step name "
        "when this is the deliberate shape.",
    ),
    exploit_example=(
        "# Vulnerable: ``$(params.target)`` is substituted into\n"
        "# the workspace ``subPath`` literally. A PipelineRun with\n"
        "# ``target: ../../../etc/secrets`` (or similar traversal)\n"
        "# escapes the intended workspace directory and reads /\n"
        "# writes outside it.\n"
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "spec:\n"
        "  params:\n"
        "    - name: target\n"
        "  workspaces:\n"
        "    - name: shared\n"
        "      subPath: $(params.target)\n"
        "  steps:\n"
        "    - name: write\n"
        "      image: alpine@sha256:abc123...\n"
        "      script: |\n"
        "        echo data > /workspace/shared/out\n"
        "\n"
        "# Safe: pin the subPath to a static literal or validate\n"
        "# the param shape upstream (in the Pipeline) against an\n"
        "# allowlist of expected names. Tekton has no built-in\n"
        "# path-canonicalisation for subPath, so the gate is on\n"
        "# the producer of the param.\n"
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "spec:\n"
        "  workspaces:\n"
        "    - name: shared\n"
        "      subPath: artifacts\n"
        "  steps:\n"
        "    - name: write\n"
        "      image: alpine@sha256:abc123...\n"
        "      script: |\n"
        "        echo data > /workspace/shared/out"
    ),
)


# ``$(params.<name>)`` is the canonical Tekton substitution form;
# the legacy single-paren ``$params.name`` is no longer accepted by
# Tekton 0.30+, so we match only the documented shape.
_PARAM_RE = re.compile(r"\$\(params\.([A-Za-z_][A-Za-z0-9_-]*)\)")


def _step_workspaces(step: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    ws = step.get("workspaces")
    if isinstance(ws, list):
        out.extend(w for w in ws if isinstance(w, dict))
    return out


def check(ctx: TektonContext) -> Finding:
    offenders: list[str] = []
    examined = 0
    for doc in ctx.docs:
        if doc.kind not in ("Task", "ClusterTask"):
            continue
        examined += 1
        for idx, step in enumerate(task_steps(doc)):
            for ws in _step_workspaces(step):
                sub = ws.get("subPath")
                if not isinstance(sub, str):
                    continue
                refs = sorted({m.group(1) for m in _PARAM_RE.finditer(sub)})
                if refs:
                    offenders.append(
                        f"{doc.kind}/{doc.name} {step_name(step, idx)} "
                        f"workspace.{ws.get('name', '?')}.subPath: "
                        f"params.{', params.'.join(refs[:3])}"
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
        "No workspace ``subPath`` interpolates a Task parameter."
        if passed else
        f"{len(offenders)} workspace subPath(s) interpolate Task "
        f"parameter(s): {'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A parameter-driven "
        f"sub-path lets an attacker traverse outside the workspace."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
