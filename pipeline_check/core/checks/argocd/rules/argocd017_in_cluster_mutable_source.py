"""ARGOCD-017. In-cluster Application deploys from a mutable source."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoCDContext, iter_applications
from .argocd010_application_mutable_targetrevision import (
    _is_immutable_revision,
    _iter_sources,
)

RULE = Rule(
    id="ARGOCD-017",
    title="Argo CD in-cluster Application deploys from a mutable source",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-PIN-DEPS", "ESF-C-LEAST-PRIV"),
    cwe=("CWE-1357", "CWE-829"),
    recommendation=(
        "Pin ``targetRevision`` to an immutable ref (a 40-character "
        "commit SHA or a signed, immutability-enforced tag) for any "
        "Application that targets the in-cluster API "
        "(``spec.destination.server: https://kubernetes.default.svc``). "
        "That destination is where Argo CD itself runs, so a push to "
        "a tracked branch can reshape the control-plane namespace "
        "with no manifest change and no Argo CD-side review. If the "
        "workload does not need to live next to Argo CD, move it to a "
        "dedicated remote cluster instead."
    ),
    docs_note=(
        "Fires when an Application's ``spec.destination.server`` is "
        "the canonical in-cluster value "
        "``https://kubernetes.default.svc`` AND a source "
        "``targetRevision`` is mutable (a branch, ``HEAD``, or any "
        "non-SHA non-SemVer string). Reuses ARGOCD-010's immutable-ref "
        "helper, so 40-character commit SHAs and SemVer literals pass. "
        "Both single-source (``spec.source``) and multi-source "
        "(``spec.sources[]``) forms are checked. This is the "
        "in-cluster intersection of ARGOCD-010: ARGOCD-010 flags any "
        "mutable source, this rule raises the bar for the "
        "control-plane destination specifically."
    ),
    known_fp=(
        "Bootstrap or app-of-apps Applications that intentionally "
        "manage the local cluster from a branch behind required-review "
        "branch protection may accept branch tracking. The rule still "
        "fires; suppress per Application with a rationale naming the "
        "branch-protection control.",
    ),
    exploit_example=(
        "# Vulnerable: the Application deploys to the in-cluster API\n"
        "# (where Argo CD runs) and tracks a branch tip.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Application\n"
        "metadata: { name: platform, namespace: argocd }\n"
        "spec:\n"
        "  source:\n"
        "    repoURL: https://github.com/example/platform-manifests\n"
        "    targetRevision: main\n"
        "    path: cluster\n"
        "  destination:\n"
        "    server: https://kubernetes.default.svc\n"
        "    namespace: argocd\n"
        "  syncPolicy: { automated: { selfHeal: true } }\n"
        "\n"
        "# Attack: an attacker with push access to the branch lands a\n"
        "# manifest granting their service account cluster-admin (a\n"
        "# ClusterRoleBinding). Argo CD's next reconcile applies it in\n"
        "# the same cluster it runs in, escalating control-plane-wide.\n"
        "\n"
        "# Safe: pin to a commit SHA for the in-cluster destination.\n"
        "spec:\n"
        "  source:\n"
        "    repoURL: https://github.com/example/platform-manifests\n"
        "    targetRevision: 7b83187abc456def012345abcdef0123456789ab\n"
        "    path: cluster"
    ),
)


_IN_CLUSTER_SERVER = "https://kubernetes.default.svc"


def _targets_in_cluster(spec: dict[str, Any]) -> bool:
    destination = spec.get("destination")
    if not isinstance(destination, dict):
        return False
    server = destination.get("server")
    return isinstance(server, str) and server.strip() == _IN_CLUSTER_SERVER


def check(ctx: ArgoCDContext) -> Finding:
    apps = list(iter_applications(ctx))
    if not apps:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="(no Applications)",
            description=(
                "No Argo CD Application documents in scope; "
                "nothing to audit."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    in_cluster_apps = 0
    for app in apps:
        spec = app.data.get("spec")
        if not isinstance(spec, dict):
            continue
        if not _targets_in_cluster(spec):
            continue
        in_cluster_apps += 1
        for label, rev in _iter_sources(spec):
            if rev is None:
                offenders.append(
                    f"{app.display}: {label}.targetRevision missing "
                    f"(defaults to HEAD)"
                )
                continue
            if not isinstance(rev, str):
                continue
            if _is_immutable_revision(rev):
                continue
            offenders.append(
                f"{app.display}: {label}.targetRevision is mutable ({rev!r})"
            )
    if in_cluster_apps == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=apps[0].display,
            description=(
                "No Application targets the in-cluster API; "
                "nothing to audit."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    passed = not offenders
    desc = (
        "Every in-cluster Application pins to an immutable ref "
        "(commit SHA or SemVer)."
        if passed else
        f"{len(offenders)} in-cluster Application source(s) track "
        f"mutable refs: {'; '.join(offenders[:3])}"
        f"{' ...' if len(offenders) > 3 else ''}. A push to the "
        f"tracked ref reshapes the control-plane cluster on the next "
        f"reconcile."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=apps[0].display,
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
