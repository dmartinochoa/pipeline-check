"""K8S-027 — Ingress accepts traffic without a TLS configuration."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import KubernetesContext

RULE = Rule(
    id="K8S-027",
    title="Ingress has no TLS configuration",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-NETWORK-SEG", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-319",),
    recommendation=(
        "Add a ``spec.tls`` block to every Ingress that fronts an "
        "HTTP backend. Each entry pairs one or more hostnames with "
        "a Secret holding the certificate / key — the canonical "
        "pattern is to provision the Secret via cert-manager and a "
        "ClusterIssuer pointing at Let's Encrypt or an internal CA. "
        "Plaintext-only Ingress lets a network attacker downgrade "
        "the connection and read or rewrite request bodies, which "
        "matters for any path carrying credentials, session cookies, "
        "or PII."
    ),
    docs_note=(
        "An Ingress with no ``spec.tls`` (or an empty list) terminates "
        "HTTP at the load balancer and proxies plaintext upstream. "
        "Ingress controllers will respect ``ssl-redirect`` "
        "annotations, but those are advisory until ``tls:`` is "
        "populated. If the Ingress is intentionally HTTP-only (e.g. "
        "an ACME challenge endpoint or an internal-only path served "
        "behind a network policy), suppress via ``.pipelinecheckignore`` "
        "with a short rationale rather than leaving it open."
    ),
)


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m in ctx.manifests:
        if m.kind != "Ingress":
            continue
        spec = m.data.get("spec")
        if not isinstance(spec, dict):
            continue
        tls: Any = spec.get("tls")
        if isinstance(tls, list) and tls:
            continue
        offenders.append(f"Ingress/{m.name}")
    passed = not offenders
    desc = (
        "Every Ingress declares a non-empty `spec.tls` block."
        if passed else
        f"{len(offenders)} Ingress(es) accept plaintext HTTP only: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
