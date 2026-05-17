"""K8S-041. Service declares non-empty ``externalIPs`` (CVE-2020-8554 surface)."""
from __future__ import annotations

from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext

RULE = Rule(
    id="K8S-041",
    title="Service.externalIPs allows traffic interception (CVE-2020-8554)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-NETWORK-SEG", "ESF-D-LEAST-PRIV"),
    cwe=("CWE-668",),
    recommendation=(
        "Remove ``spec.externalIPs`` from the Service. The field has "
        "no legitimate use in most clusters and any namespace user "
        "with ``services.create`` can claim any IP, including the "
        "cluster's own kube-apiserver, metrics-server, or an external "
        "service IP, and the kube-proxy iptables rules will redirect "
        "matching traffic to their pods. Enforce the absence cluster-"
        "wide with an admission policy (Gatekeeper / Kyverno / "
        "ValidatingAdmissionPolicy) that rejects Services with a "
        "non-empty ``externalIPs`` list."
    ),
    docs_note=(
        "CVE-2020-8554 is a design-level Kubernetes weakness rather "
        "than a code bug: any namespace user with ``services`` create "
        "permission can declare ``spec.externalIPs: [<arbitrary IP>]`` "
        "on a Service, and kube-proxy installs DNAT rules that "
        "intercept traffic destined for that IP on every node. The "
        "attacker primitive is to MITM in-cluster traffic to public "
        "endpoints, metadata services, or other tenants' workloads. "
        "Kubernetes upstream's remediation is admission-time enforcement "
        "(see the ``DenyServiceExternalIPs`` admission plugin and the "
        "RBAC pattern in the official guidance) rather than a runtime "
        "fix. This rule flags any non-empty ``externalIPs`` list so "
        "the team can confirm the field is gone from manifests before "
        "the admission policy is rolled out."
    ),
    incident_refs=(
        "CVE-2020-8554 (Kubernetes, 2020): documented MITM-via-"
        "externalIPs design flaw. Kubernetes' upstream advisory "
        "recommends restricting externalIPs via admission control.",
    ),
)


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m in ctx.manifests:
        if m.kind != "Service":
            continue
        spec = m.data.get("spec")
        if not isinstance(spec, dict):
            continue
        ext_ips: Any = spec.get("externalIPs")
        if not isinstance(ext_ips, list) or not ext_ips:
            continue
        sample = ", ".join(
            ip for ip in ext_ips[:3] if isinstance(ip, str)
        ) or "(non-string entries)"
        offenders.append(f"Service/{m.name} externalIPs=[{sample}]")
        line = _line_of(ext_ips) or _line_of(spec)
        locations.append(Location(
            path=m.path, start_line=line, end_line=line,
            doc_index=m.doc_index,
        ))
    passed = not offenders
    desc = (
        "No Service declares a non-empty externalIPs list."
        if passed else
        f"{len(offenders)} Service(s) declare externalIPs (CVE-2020-"
        f"8554 surface): {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Any namespace user "
        f"with services/create can claim cluster-internal IPs the "
        f"same way."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
