"""K8S-043. Ingress rule with catch-all / wildcard host."""
from __future__ import annotations

from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext

RULE = Rule(
    id="K8S-043",
    title="Ingress rule has wildcard or missing host (catch-all)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-NETWORK-SEG",),
    cwe=("CWE-441",),
    recommendation=(
        "Pin every Ingress rule to an explicit hostname. ``host: "
        "api.example.com`` (not ``host: '*'``, ``host: '*.example."
        "com'``, and not an omitted ``host:``). A catch-all host "
        "binding means any request to the ingress controller's "
        "external address, regardless of HTTP Host header, can route "
        "to this backend; an attacker with control over an arbitrary "
        "hostname pointing at the same controller (a parked domain, "
        "a typo'd CNAME, a cluster-internal name on a shared "
        "controller) reaches paths that should have been "
        "host-scoped."
    ),
    docs_note=(
        "An Ingress rule with no ``host:`` matches every Host header "
        "the controller receives; a rule with ``host: '*'`` is the "
        "explicit form of the same behavior. Both shape choices "
        "collapse the controller's hostname-based routing into a "
        "pure path-based match, which means anyone who can present "
        "any hostname (HTTP/1.1 Host header rewrite, malicious "
        "CNAME, controller hairpin) reaches this backend. The rule "
        "also fires on apex wildcards like ``host: '*.example.com'`` "
        "since they accept subdomains the cluster operator never "
        "intended to register. A backend that's intentionally "
        "wildcard-routed (a tenant-per-subdomain SaaS) should "
        "suppress with a rationale rather than disabling the check."
    ),
    known_fp=(
        "TLS terminators that intentionally use a single Ingress "
        "with a wildcard host to front many tenant subdomains are "
        "legitimate; suppress the finding for that Ingress "
        "specifically rather than disabling the rule.",
    ),
)


def _classify(host: Any) -> str | None:
    """Return a short tag describing why *host* is catch-all, or None."""
    if host is None:
        return "missing"
    if not isinstance(host, str):
        return None
    h = host.strip()
    if not h:
        return "empty"
    if h == "*":
        return "wildcard '*'"
    if h.startswith("*."):
        return f"wildcard '{h}'"
    return None


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m in ctx.manifests:
        if m.kind != "Ingress":
            continue
        spec = m.data.get("spec")
        if not isinstance(spec, dict):
            continue
        rules = spec.get("rules")
        if not isinstance(rules, list):
            continue
        for idx, r in enumerate(rules):
            if not isinstance(r, dict):
                continue
            # An Ingress rule without a ``host`` key is the YAML
            # equivalent of a wildcard match. Differentiate it from
            # an explicit ``host: '*'`` for the user.
            host_set = "host" in r
            tag = _classify(r.get("host") if host_set else None)
            if tag is None:
                continue
            offenders.append(f"Ingress/{m.name} rules[{idx}] {tag}")
            line = _line_of(r)
            locations.append(Location(
                path=m.path, start_line=line, end_line=line,
                doc_index=m.doc_index,
            ))
    passed = not offenders
    desc = (
        "Every Ingress rule pins an explicit hostname."
        if passed else
        f"{len(offenders)} Ingress rule(s) match every hostname: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Catch-all hosts route "
        f"to this backend regardless of the Host header."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
