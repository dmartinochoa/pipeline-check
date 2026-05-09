"""TKN-002. Steps must not run privileged or as UID 0."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TektonContext, step_name, task_steps

RULE = Rule(
    id="TKN-002",
    title="Tekton step runs privileged or as root",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5",),
    esf=("ESF-D-RUNTIME-HARDENING",),
    cwe=("CWE-269", "CWE-250"),
    recommendation=(
        "Set ``securityContext.privileged: false``, "
        "``runAsNonRoot: true``, and ``allowPrivilegeEscalation: "
        "false`` on every step. A privileged step shares the node's "
        "kernel namespaces; a malicious or compromised step image then "
        "has root on the build node, breaking the boundary between "
        "build and cluster."
    ),
    docs_note=(
        "Detection fires on a step with ``securityContext.privileged: "
        "true``, ``securityContext.runAsUser: 0``, "
        "``securityContext.runAsNonRoot: false``, "
        "``securityContext.allowPrivilegeEscalation: true``, or no "
        "``securityContext`` block at all."
    ),
)


def _step_offends(sc: Any) -> list[str]:
    if not isinstance(sc, dict):
        return ["no securityContext"]
    issues: list[str] = []
    if sc.get("privileged") is True:
        issues.append("privileged: true")
    if sc.get("allowPrivilegeEscalation") is True:
        issues.append("allowPrivilegeEscalation: true")
    if sc.get("runAsUser") == 0:
        issues.append("runAsUser: 0")
    if sc.get("runAsNonRoot") is False:
        issues.append("runAsNonRoot: false")
    if sc.get("runAsNonRoot") is None and not issues:
        issues.append("runAsNonRoot not set")
    return issues


def check(ctx: TektonContext) -> Finding:
    offenders: list[str] = []
    examined = 0
    for doc in ctx.docs:
        if doc.kind not in ("Task", "ClusterTask"):
            continue
        examined += 1
        for idx, step in enumerate(task_steps(doc)):
            issues = _step_offends(step.get("securityContext"))
            if issues:
                offenders.append(
                    f"{doc.kind}/{doc.name} {step_name(step, idx)}: "
                    f"{', '.join(issues)}"
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
        "Every step has a hardened securityContext."
        if passed else
        f"{len(offenders)} step(s) run privileged / as root: "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
