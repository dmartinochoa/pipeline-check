"""ARGO-016. Workflow bound to a cluster-admin / over-privileged ServiceAccount."""
from __future__ import annotations

from typing import Any

from ...base import Confidence, Finding, Severity
from ...rule import Rule
from ..base import ArgoContext, workflow_spec

# ServiceAccount names that signal a cluster-wide admin binding. The
# privilege itself lives in RBAC (a ClusterRoleBinding to ``cluster-admin``),
# which isn't in the Workflow, but binding a workflow to an SA named for a
# cluster-admin / superuser role is the common "run as cluster-admin" shape:
# any step's automounted token then acts cluster-wide (read every secret,
# create privileged pods on any node, bind more roles) -> cluster takeover.
_ADMIN_SA_NAMES = frozenset({"cluster-admin", "admin", "root", "superuser"})


def _is_admin_sa(sa: Any) -> bool:
    if not isinstance(sa, str):
        return False
    name = sa.strip().lower()
    return name in _ADMIN_SA_NAMES or "cluster-admin" in name


RULE = Rule(
    id="ARGO-016",
    title="Workflow bound to a cluster-admin / over-privileged ServiceAccount",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-2",),
    esf=("ESF-D-IAM",),
    cwe=("CWE-269", "CWE-250"),
    recommendation=(
        "Don't run a Workflow as a cluster-admin / superuser "
        "ServiceAccount. Create a dedicated SA scoped to the workflow's "
        "namespace and bind it (via a namespaced ``Role`` / "
        "``RoleBinding``) to only the verbs and resources the workflow "
        "needs. A workflow running as ``cluster-admin`` lets any step, "
        "or any code injected into a step, use the automounted token to "
        "act cluster-wide: read every secret, schedule privileged pods "
        "on any node, and grant itself more roles."
    ),
    docs_note=(
        "Fires when a Workflow / CronWorkflow sets "
        "``spec.serviceAccountName`` to a name that signals a "
        "cluster-wide admin binding (``cluster-admin``, or a name "
        "containing ``cluster-admin``, ``admin``, ``root``, "
        "``superuser``). The actual privilege lives in the RBAC "
        "``ClusterRoleBinding``, which isn't visible in the Workflow, so "
        "this is a name-based heuristic (MEDIUM confidence) for the "
        "common copy-paste shape; the broader case (an innocuously-named "
        "SA bound to cluster-admin) needs the RBAC manifest. Distinct "
        "from ARGO-003, which flags the *default* SA."
    ),
    exploit_example=(
        "# Vulnerable: the workflow runs as the cluster-admin SA.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Workflow\n"
        "spec:\n"
        "  serviceAccountName: cluster-admin\n"
        "  templates:\n"
        "    - name: main\n"
        "      container:\n"
        "        image: kubectl@sha256:abc123...\n"
        "        args: [\"kubectl get secrets -A\"]\n"
        "\n"
        "# Attack: any step (or code injected into one) reads the\n"
        "# automounted token at /var/run/secrets/... and acts as\n"
        "# cluster-admin: dumps every namespace's secrets, schedules a\n"
        "# privileged pod on any node, binds itself more roles.\n"
        "\n"
        "# Safe: a dedicated namespaced SA with least-privilege RBAC.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Workflow\n"
        "spec:\n"
        "  serviceAccountName: ci-deploy-sa\n"
        "  templates:\n"
        "    - name: main\n"
        "      container:\n"
        "        image: kubectl@sha256:abc123...\n"
        "        args: [\"kubectl -n app rollout restart deploy/web\"]"
    ),
)


def check(ctx: ArgoContext) -> Finding:
    offenders: list[str] = []
    examined = 0
    for doc in ctx.docs:
        if doc.kind not in ("Workflow", "CronWorkflow"):
            continue
        examined += 1
        sa = workflow_spec(doc).get("serviceAccountName")
        if _is_admin_sa(sa):
            offenders.append(f"{doc.kind}/{doc.name}: {sa}")
    if examined == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Workflow / CronWorkflow documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No Workflow runs as a cluster-admin / over-privileged ServiceAccount."
        if passed else
        f"{len(offenders)} workflow(s) run as a cluster-admin / "
        f"over-privileged ServiceAccount: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Bind a least-privilege, "
        f"namespaced SA instead."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        confidence=Confidence.HIGH if passed else Confidence.MEDIUM,
    )
