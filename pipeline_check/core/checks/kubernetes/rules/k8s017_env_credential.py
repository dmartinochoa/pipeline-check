"""K8S-017 — Container ``env[].value`` carries a credential-shaped literal."""
from __future__ import annotations

from typing import Any

from ..._primitives.secret_shapes import AWS_KEY_RE, SECRETISH_KEY_RE
from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    KubernetesContext,
    container_name,
    iter_containers,
    iter_workload_pod_specs,
)

RULE = Rule(
    id="K8S-017",
    title="Container env value carries a credential-shaped literal",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Replace literal ``env[].value`` entries that hold "
        "credentials with ``env[].valueFrom.secretKeyRef`` or "
        "``envFrom.secretRef``. A literal env value lives in the "
        "manifest YAML — it gets committed to git, surfaced by "
        "``kubectl get pod -o yaml``, and embedded in audit logs. "
        "Externalising into a Secret (and ideally a SealedSecret / "
        "ExternalSecret / SOPS-encrypted source) keeps the value "
        "out of the manifest."
    ),
    docs_note=(
        "Reuses ``_primitives/secret_shapes`` — flags AKIA-prefixed "
        "AWS access keys outright, plus credential-named keys "
        "(``API_KEY``, ``DB_PASSWORD``, ``SECRET_TOKEN``) when the "
        "value is a non-empty literal. ``valueFrom`` entries are "
        "always safe (no inline value)."
    ),
)


def _looks_literal(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if not value:
        return False
    # ``$(VAR)`` is K8s downward-API substitution — not a literal.
    if value.startswith("$(") and value.endswith(")"):
        return False
    return True


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m, ps in iter_workload_pod_specs(ctx):
        for kind, c in iter_containers(ps):
            envs = c.get("env")
            if not isinstance(envs, list):
                continue
            for entry in envs:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                value = entry.get("value")
                if not isinstance(name, str):
                    continue
                if AWS_KEY_RE.search(value if isinstance(value, str) else ""):
                    offenders.append(
                        f"{m.kind}/{m.name} {kind}={container_name(c)} "
                        f"env={name} (AKIA-shaped value)"
                    )
                    continue
                if SECRETISH_KEY_RE.search(name) and _looks_literal(value):
                    offenders.append(
                        f"{m.kind}/{m.name} {kind}={container_name(c)} "
                        f"env={name} (literal credential-shaped name)"
                    )
    passed = not offenders
    desc = (
        "No container env entry carries a credential-shaped literal."
        if passed else
        f"{len(offenders)} env entr(ies) carry literal credentials: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
