"""ARGOCD-016. Application Helm valueFiles fetched from a remote URL."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ArgoCDContext, application_sources, iter_applications, iter_applicationsets

RULE = Rule(
    id="ARGOCD-016",
    title="Application Helm valueFiles fetched from a remote URL",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-3"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-494"),
    recommendation=(
        "Don't point ``spec.source.helm.valueFiles`` at an "
        "``http(s)://`` URL. A remote values file is fetched at "
        "render time from a host outside the chart's own repo, with "
        "no revision pin and no integrity check, so whoever controls "
        "that URL (or its DNS / TLS, or just the file behind it) can "
        "rewrite the values Argo CD renders the chart with, flipping "
        "image tags, injecting init containers, mounting secrets, or "
        "widening RBAC. Keep value files inside the chart's own "
        "Git-tracked source (a path in the same repo, pinned by the "
        "Application's ``targetRevision``), or use the multi-source "
        "``$ref`` form pointed at a revision-pinned repo you control. "
        "Argo CD's ``helm.valuesFileSchemes`` setting can hard-block "
        "remote schemes instance-wide."
    ),
    docs_note=(
        "Walks every ``Application`` / ``ApplicationSet`` source and "
        "flags a ``helm.valueFiles`` entry whose value is an "
        "``http://`` or ``https://`` URL. Path-form entries (a file "
        "inside the chart repo) and the multi-source ``$ref/path`` "
        "form are not flagged: those resolve against a "
        "revision-pinned Git source. Inline ``helm.values`` / "
        "``valuesObject`` are also out of scope (they're committed "
        "with the Application).\n\n"
        "A remote values file is an unpinned, unverified input to "
        "the Helm render, distinct from HELM-003 (the chart "
        "*repository* transport) and ARGOCD-007 (Helm *parameter* "
        "interpolation): this is the values *file* pulled from an "
        "arbitrary host."
    ),
    known_fp=(
        "An internal, access-controlled values server that publishes "
        "immutable, content-addressed files may be used deliberately. "
        "Suppress per Application with a rationale; the durable fix "
        "is to track the values file in the chart's Git source or a "
        "revision-pinned ``$ref`` repo.",
    ),
    incident_refs=(
        "Unpinned-remote-input class: a render-time values file "
        "fetched over the network can be swapped to change what the "
        "chart deploys, the GitOps analog of pulling a build script "
        "from an attacker-controlled URL.",
    ),
    exploit_example=(
        "# Vulnerable: valueFiles fetched from a remote URL.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Application\n"
        "spec:\n"
        "  source:\n"
        "    repoURL: https://github.com/org/charts\n"
        "    targetRevision: abc123\n"
        "    path: charts/app\n"
        "    helm:\n"
        "      valueFiles:\n"
        "        - https://values.example.test/prod.yaml\n"
        "\n"
        "# Attack: whoever controls values.example.test serves a\n"
        "# prod.yaml that flips the image to a backdoored tag (or\n"
        "# mounts the cluster's secrets into an exfil sidecar). Argo\n"
        "# re-renders on every sync; nothing pins or verifies the\n"
        "# fetched file.\n"
        "\n"
        "# Safe: a value file tracked in the chart's pinned repo.\n"
        "      valueFiles:\n"
        "        - values-prod.yaml\n"
    ),
)


_REMOTE_SCHEMES = ("http://", "https://")


def _remote_value_files(source: dict[str, Any]) -> list[str]:
    helm = source.get("helm")
    if not isinstance(helm, dict):
        return []
    vf = helm.get("valueFiles")
    if not isinstance(vf, list):
        return []
    return [
        v for v in vf
        if isinstance(v, str) and v.strip().lower().startswith(_REMOTE_SCHEMES)
    ]


def check(ctx: ArgoCDContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    apps = list(iter_applications(ctx)) + list(iter_applicationsets(ctx))
    for app in apps:
        for source in application_sources(app):
            for url in _remote_value_files(source):
                offenders.append(f"{app.name}: {url}")
                locations.append(Location(
                    path=app.path, doc_index=app.doc_index,
                ))
    passed = not offenders
    desc = (
        "No Application Helm source fetches valueFiles from a remote URL."
        if passed else
        f"{len(offenders)} Helm valueFiles fetched from a remote URL: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A remote values file is "
        f"an unpinned, unverified render input; whoever controls the "
        f"URL can rewrite what the chart deploys."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argocd", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
