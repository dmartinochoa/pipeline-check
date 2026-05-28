"""ARGOCD-010. Application targetRevision uses a mutable ref."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoCDContext, iter_applications

RULE = Rule(
    id="ARGOCD-010",
    title="Argo CD Application targetRevision uses a mutable ref",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-1357", "CWE-829"),
    recommendation=(
        "Pin every Application source to an immutable ref. Three "
        "stable shapes:\n\n"
        "* ``targetRevision: <40-char-commit-sha>`` for git sources. "
        "The SHA binds to specific content; force-push and tag-move "
        "can't redirect the deploy.\n"
        "* ``targetRevision: v1.2.3`` for git sources where signed "
        "tags are the org's release convention AND the repo enforces "
        "tag-immutability (signed tags + branch protection denying "
        "tag-rewrite). Without the protection, treat tags as "
        "mutable and pin the SHA instead.\n"
        "* ``targetRevision: 1.2.3`` for Helm chart references where "
        "the chart repo enforces version-immutability (chart museum "
        "default, OCI registry default). SemVer pins to a published "
        "chart digest.\n\n"
        "Branch refs (``main`` / ``master`` / ``HEAD``) follow the "
        "branch tip on every reconcile; whoever has push access to "
        "the branch controls what Argo CD deploys. This is the "
        "GitOps analog of ``GHA-001 actions/checkout@v4`` and "
        "carries the same exposure window."
    ),
    docs_note=(
        "Reads ``spec.source.targetRevision`` (or each entry in "
        "``spec.sources[].targetRevision`` for multi-source apps) "
        "and fires when the value matches a mutable-ref shape: "
        "``HEAD``, branch-name literals (``main`` / ``master`` / "
        "``develop`` / ``release-*``), or any non-SHA non-SemVer "
        "string. Immutable shapes that pass:\n\n"
        "* 40-character hex commit SHA\n"
        "* SemVer literal (``1.2.3``, ``1.2.3-rc.1``)\n"
        "* ``v``-prefixed SemVer (``v1.2.3``)\n\n"
        "Helm chart sources (``spec.source.chart`` set) follow the "
        "same rule: ``targetRevision`` should be a SemVer literal, "
        "not a range or branch."
    ),
    known_fp=(
        "Some staging environments deliberately track ``main`` for "
        "fast iteration on dev workloads. The rule still fires; "
        "suppress per Application with a one-line rationale naming "
        "the environment's intentional drift posture. Production "
        "environments should not be suppressed.",
    ),
    incident_refs=(
        "Long-running pattern of Argo CD deployments tracking "
        "``HEAD`` on the default branch and silently picking up "
        "every push to that branch. Force-pushes to the branch "
        "(intentional or via maintainer-account compromise) "
        "redirect the deploy without any Argo CD-side review; "
        "SHA-pinned deployments survive the same incident because "
        "the ref content is content-addressed.",
    ),
    exploit_example=(
        "# Vulnerable: targetRevision tracks the branch tip.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Application\n"
        "metadata: { name: payments, namespace: argocd }\n"
        "spec:\n"
        "  source:\n"
        "    repoURL: https://github.com/example/payments-manifests\n"
        "    targetRevision: main\n"
        "    path: overlays/prod\n"
        "  destination: { server: https://kubernetes.default.svc, namespace: prod }\n"
        "  syncPolicy: { automated: { prune: true, selfHeal: true } }\n"
        "\n"
        "# Attack: a compromised maintainer pushes a malicious\n"
        "# commit to the default branch. Argo CD's next reconcile\n"
        "# (every 3 minutes by default) detects the new HEAD,\n"
        "# automated sync applies the manifests, the compromised\n"
        "# pods land. No human in the loop.\n"
        "\n"
        "# Safe: pin to a commit SHA.\n"
        "spec:\n"
        "  source:\n"
        "    repoURL: https://github.com/example/payments-manifests\n"
        "    targetRevision: 7b83187abc456def012345abcdef0123456789ab\n"
        "    path: overlays/prod"
    ),
)


# Immutable-ref shapes that pass the rule.
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_SEMVER_RE = re.compile(
    r"^v?\d+\.\d+\.\d+(?:[-+][\w.\-]+)?$"
)
# Mutable-ref literals we explicitly call out in the description.
_MUTABLE_LITERALS: frozenset[str] = frozenset({
    "HEAD", "head", "main", "master", "develop", "trunk",
})


def _is_immutable_revision(rev: str) -> bool:
    r = rev.strip()
    if not r:
        return False  # empty value = default HEAD = mutable
    if _SHA_RE.match(r):
        return True
    if _SEMVER_RE.match(r):
        return True
    return False


def _iter_sources(spec: dict[str, Any]):
    """Yield (path-label, targetRevision-or-None) tuples for each
    Application source. Handles both single ``source`` and the
    multi-source ``sources: []`` form."""
    single = spec.get("source")
    if isinstance(single, dict):
        yield "source", single.get("targetRevision")
    multi = spec.get("sources")
    if isinstance(multi, list):
        for idx, src in enumerate(multi):
            if isinstance(src, dict):
                yield f"sources[{idx}]", src.get("targetRevision")


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
    for app in apps:
        spec = app.data.get("spec")
        if not isinstance(spec, dict):
            continue
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
            shape = (
                "branch / HEAD" if rev in _MUTABLE_LITERALS
                else f"mutable ref ({rev!r})"
            )
            offenders.append(
                f"{app.display}: {label}.targetRevision is {shape}"
            )
    passed = not offenders
    desc = (
        "Every Application source pins to an immutable ref "
        "(commit SHA or SemVer)."
        if passed else
        f"{len(offenders)} Application source(s) track mutable "
        f"refs: {'; '.join(offenders[:3])}"
        f"{' …' if len(offenders) > 3 else ''}. Each reconcile "
        f"picks up whatever the branch tip points at."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=apps[0].display,
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
