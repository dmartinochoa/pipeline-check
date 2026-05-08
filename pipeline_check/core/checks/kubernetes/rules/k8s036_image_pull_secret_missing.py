"""K8S-036 — ServiceAccount references an imagePullSecret that doesn't exist."""
from __future__ import annotations

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext

RULE = Rule(
    id="K8S-036",
    title="ServiceAccount imagePullSecrets references missing Secret",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-D-CODE-INTEGRITY",),
    cwe=("CWE-1188",),
    recommendation=(
        "Create the missing ``Kind: Secret`` of ``type: "
        "kubernetes.io/dockerconfigjson`` (or ``dockercfg``) in the "
        "same namespace before applying the ServiceAccount, or fix "
        "the ``imagePullSecrets`` reference name. A dangling "
        "reference doesn't fail apply — kubelet silently falls back "
        "to anonymous registry pulls on every image fetch. Workloads "
        "either pull a different image than the operator intended "
        "or fail at runtime with ``ImagePullBackOff`` after the "
        "registry rate-limits the unauthenticated client."
    ),
    docs_note=(
        "Cross-doc correlation: walks every ServiceAccount's "
        "``imagePullSecrets`` and confirms the named Secret exists "
        "in the same namespace within the manifest set. Misses two "
        "cases: secrets created out-of-band (Sealed Secrets, "
        "External Secrets, or operator-applied ones) and SAs whose "
        "namespace is implicit / not declared in the manifest set. "
        "For those, the rule passes — false-negative-friendly."
    ),
    known_fp=(
        "Manifests rendered for partial deployment where the secret "
        "lives in a parallel manifest set the scanner doesn't see "
        "(separate ArgoCD application, Vault-injected, ESO-synced). "
        "Add ``# pipeline-check: ignore K8S-036`` or ignore the "
        "specific SA name to silence.",
    ),
)


def check(ctx: KubernetesContext) -> Finding:
    # Build (namespace, secret_name) -> Manifest index. Use "" as the
    # implicit-namespace key — declared SAs without a namespace match
    # declared Secrets without one too.
    secrets: set[tuple[str, str]] = set()
    for m in ctx.manifests:
        if m.kind != "Secret":
            continue
        secrets.add((m.namespace, m.name))

    offenders: list[str] = []
    locations: list[Location] = []
    for m in ctx.manifests:
        if m.kind != "ServiceAccount":
            continue
        ips = m.data.get("imagePullSecrets")
        if not isinstance(ips, list):
            continue
        for entry in ips:
            if not isinstance(entry, dict):
                continue
            sec_name = entry.get("name")
            if not isinstance(sec_name, str) or not sec_name.strip():
                continue
            if (m.namespace, sec_name) in secrets:
                continue
            offenders.append(
                f"ServiceAccount/{m.name} -> Secret/{sec_name} "
                f"(namespace: {m.namespace or '<default>'})"
            )
            line = _line_of(ips) or _line_of(m.data)
            locations.append(Location(
                path=m.path, start_line=line, end_line=line,
                doc_index=m.doc_index,
            ))
    passed = not offenders
    desc = (
        "Every ServiceAccount imagePullSecrets reference resolves to "
        "a Secret in the same namespace."
        if passed else
        f"{len(offenders)} ServiceAccount imagePullSecrets reference(s) "
        f"point to missing Secret(s): {'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
