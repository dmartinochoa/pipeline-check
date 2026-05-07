"""ARGO-002 — Template containers must not run privileged or as root."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoContext, iter_containers, iter_templates, template_name, workflow_spec

RULE = Rule(
    id="ARGO-002",
    title="Argo template container runs privileged or as root",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5",),
    esf=("ESF-D-RUNTIME-HARDENING",),
    cwe=("CWE-269", "CWE-250"),
    recommendation=(
        "Set ``securityContext.privileged: false``, "
        "``runAsNonRoot: true``, and ``allowPrivilegeEscalation: "
        "false`` on every template container / script. A privileged "
        "container shares the node's kernel namespaces; a malicious "
        "image then has root on the build node and breaks the "
        "boundary between workflow and cluster."
    ),
    docs_note=(
        "Detection fires on ``securityContext.privileged: true``, "
        "``runAsUser: 0``, ``runAsNonRoot: false``, "
        "``allowPrivilegeEscalation: true``, or no ``securityContext`` "
        "block at all. Also walks ``spec.podSpecPatch`` (raw YAML) "
        "for an explicit ``privileged: true`` token."
    ),
)


def _container_offenders(sc: Any) -> list[str]:
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


_PRIV_TRUE_RE = re.compile(r'["\']?privileged["\']?\s*:\s*true\b', re.IGNORECASE)


def _pod_spec_patch_grants_priv(spec: dict[str, Any]) -> bool:
    psp = spec.get("podSpecPatch")
    if isinstance(psp, str) and _PRIV_TRUE_RE.search(psp):
        return True
    return False


def check(ctx: ArgoContext) -> Finding:
    offenders: list[str] = []
    for doc in ctx.docs:
        for idx, tmpl in enumerate(iter_templates(doc)):
            for container in iter_containers(tmpl):
                issues = _container_offenders(container.get("securityContext"))
                if issues:
                    offenders.append(
                        f"{doc.kind}/{doc.name} "
                        f"{template_name(tmpl, idx)}: {', '.join(issues)}"
                    )
        spec = workflow_spec(doc)
        if _pod_spec_patch_grants_priv(spec):
            offenders.append(
                f"{doc.kind}/{doc.name}: spec.podSpecPatch grants "
                f"privileged: true"
            )
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Argo documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "Every template container has a hardened securityContext."
        if passed else
        f"{len(offenders)} container(s) run privileged / as root: "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
