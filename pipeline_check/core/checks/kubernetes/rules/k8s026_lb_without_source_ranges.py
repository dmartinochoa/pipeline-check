"""K8S-026 — Service type LoadBalancer without loadBalancerSourceRanges."""
from __future__ import annotations

from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext

RULE = Rule(
    id="K8S-026",
    title="LoadBalancer Service has no loadBalancerSourceRanges",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-NETWORK-SEG",),
    cwe=("CWE-284",),
    recommendation=(
        "Restrict every ``Service`` of ``type: LoadBalancer`` with "
        "``spec.loadBalancerSourceRanges``. The default behavior is "
        "to provision an internet-facing load balancer that accepts "
        "traffic from 0.0.0.0/0, which exposes whatever the Service "
        "fronts to the entire internet. A short list of CIDRs scoped "
        "to known clients (office IPs, a NAT gateway, peered VPCs) "
        "removes the pre-auth attack surface entirely."
    ),
    docs_note=(
        "Internal-only services should use ``type: ClusterIP`` (and "
        "an Ingress for HTTP) or set the cloud-provider-specific "
        "internal-LB annotation. ``loadBalancerSourceRanges`` is the "
        "Kubernetes-native, cloud-portable way to scope an external "
        "LB; cloud-specific firewalls (AWS security groups, GCP "
        "firewall rules) are equivalent at the L4 level but invisible "
        "to a manifest scanner."
    ),
)


def _ports_summary(spec: dict[str, Any]) -> str:
    ports = spec.get("ports")
    if not isinstance(ports, list):
        return ""
    nums: list[str] = []
    for p in ports:
        if isinstance(p, dict):
            n = p.get("port")
            if isinstance(n, int):
                nums.append(str(n))
    return ",".join(nums)


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m in ctx.manifests:
        if m.kind != "Service":
            continue
        spec = m.data.get("spec")
        if not isinstance(spec, dict):
            continue
        if spec.get("type") != "LoadBalancer":
            continue
        ranges = spec.get("loadBalancerSourceRanges")
        if isinstance(ranges, list) and ranges:
            continue
        ports = _ports_summary(spec)
        ports_str = f" ports=[{ports}]" if ports else ""
        offenders.append(f"Service/{m.name}{ports_str}")
        # Anchor on the Service's spec block — that's where the
        # missing ``loadBalancerSourceRanges`` would be added.
        line = _line_of(spec)
        locations.append(Location(
            path=m.path, start_line=line, end_line=line,
            doc_index=m.doc_index,
        ))
    passed = not offenders
    desc = (
        "No LoadBalancer Service is open to the entire internet."
        if passed else
        f"{len(offenders)} LoadBalancer Service(s) accept traffic "
        f"from 0.0.0.0/0: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
