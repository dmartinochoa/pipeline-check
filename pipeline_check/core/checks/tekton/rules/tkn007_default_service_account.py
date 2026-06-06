"""TKN-007, ``TaskRun`` / ``PipelineRun`` runs as the default ServiceAccount."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import TektonContext, doc_location

RULE = Rule(
    id="TKN-007",
    title="Tekton run uses the default ServiceAccount",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    esf=("ESF-D-IAM",),
    cwe=("CWE-250", "CWE-732"),
    recommendation=(
        "Set ``spec.serviceAccountName`` on every ``TaskRun`` and "
        "``PipelineRun`` to a least-privilege ServiceAccount that "
        "carries only the secrets and RBAC the run actually needs. "
        "Falling back to the namespace's ``default`` SA grants "
        "access to whatever cluster-admin or wildcard role someone "
        "later binds to ``default``, a privilege-escalation surface "
        "that should never be load-bearing for build pods."
    ),
    docs_note=(
        "An explicit ``serviceAccountName: default`` setting is "
        "treated the same as omission."
    ),
    exploit_example=(
        "# Vulnerable: a PipelineRun with no serviceAccountName.\n"
        "apiVersion: tekton.dev/v1\n"
        "kind: PipelineRun\n"
        "metadata:\n"
        "  name: release\n"
        "spec:\n"
        "  pipelineRef:\n"
        "    name: build-and-deploy\n"
        "\n"
        "# Attack: with no serviceAccountName the run's pods get the\n"
        "# namespace's `default` ServiceAccount and its mounted API\n"
        "# token. Any step (including injected or third-party task code)\n"
        "# uses that token to call the Kubernetes API with whatever RBAC\n"
        "# is bound to `default`, which in many clusters drifts to far\n"
        "# more than a build needs. A compromised step escalates to\n"
        "# cluster resources.\n"
        "\n"
        "# Safe: bind a least-privilege SA created for this pipeline.\n"
        "spec:\n"
        "  serviceAccountName: release-ci\n"
        "  pipelineRef:\n"
        "    name: build-and-deploy"
    ),
)


def _missing_or_default(spec: dict[str, Any]) -> bool:
    sa = spec.get("serviceAccountName")
    if sa is None:
        return True
    if not isinstance(sa, str):
        return True
    return sa.strip().lower() in {"", "default"}


def check(ctx: TektonContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    examined = 0
    for doc in ctx.docs:
        if doc.kind not in ("TaskRun", "PipelineRun"):
            continue
        examined += 1
        spec = doc.data.get("spec") or {}
        if not isinstance(spec, dict):
            spec = {}
        if _missing_or_default(spec):
            offenders.append(f"{doc.kind}/{doc.name}")
            locations.append(doc_location(doc))
    if examined == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description="No TaskRun / PipelineRun documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "Every Run sets a non-default serviceAccountName."
        if passed else
        f"{len(offenders)} run(s) use the default ServiceAccount: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Bind a least-privilege "
        f"SA created for this pipeline."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
