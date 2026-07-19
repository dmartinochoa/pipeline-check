"""K8S-026. Service type LoadBalancer without loadBalancerSourceRanges."""
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
    exploit_example=(
        "# Vulnerable: a LoadBalancer Service has no\n"
        "# ``loadBalancerSourceRanges``. The cloud provider\n"
        "# provisions a LB with a public IP open to 0.0.0.0/0.\n"
        "# An internal service that was never meant to be\n"
        "# internet-facing (admin UI, debug endpoint, internal\n"
        "# API) is exposed.\n"
        "apiVersion: v1\n"
        "kind: Service\n"
        "metadata: { name: app, namespace: prod }\n"
        "spec:\n"
        "  type: LoadBalancer\n"
        "  ports: [{ port: 8080, targetPort: 8080 }]\n"
        "  selector: { app: app }\n"
        "\n"
        "# Safe: declare ``loadBalancerSourceRanges`` with the\n"
        "# CIDR allow-list. The cloud provider configures the\n"
        "# LB's security group / firewall to drop traffic from\n"
        "# anywhere outside the allow-list.\n"
        "apiVersion: v1\n"
        "kind: Service\n"
        "metadata: { name: app, namespace: prod }\n"
        "spec:\n"
        "  type: LoadBalancer\n"
        "  loadBalancerSourceRanges:\n"
        "    - 10.0.0.0/8        # internal corporate network\n"
        "    - 192.168.0.0/16    # VPN range\n"
        "  ports: [{ port: 8080, targetPort: 8080 }]\n"
        "  selector: { app: app }"
    ),
)


#: Cloud annotations whose mere presence (with a non-``false`` value)
#: marks a private, VPC-internal load balancer.
_INTERNAL_LB_FLAG_ANNOTATIONS = (
    "service.beta.kubernetes.io/aws-load-balancer-internal",
    "service.beta.kubernetes.io/azure-load-balancer-internal",
)
#: Cloud annotations that select an internal LB via a specific value.
_INTERNAL_LB_VALUE_ANNOTATIONS = {
    "service.beta.kubernetes.io/aws-load-balancer-scheme": "internal",
    "networking.gke.io/load-balancer-type": "internal",
    "cloud.google.com/load-balancer-type": "internal",
}


def _is_internal_lb(metadata: Any) -> bool:
    """Whether the Service carries a recognized internal-LB annotation.

    Internal load balancers (AWS ``aws-load-balancer-internal`` /
    ``scheme: internal``, GKE ``load-balancer-type: Internal``, Azure
    ``azure-load-balancer-internal``) get a private, VPC-only address and
    never accept 0.0.0.0/0, so the missing ``loadBalancerSourceRanges``
    is not an internet-exposure finding.
    """
    anns = metadata.get("annotations") if isinstance(metadata, dict) else None
    if not isinstance(anns, dict):
        return False
    for key in _INTERNAL_LB_FLAG_ANNOTATIONS:
        v = anns.get(key)
        if v is not None and str(v).strip().lower() not in ("", "false"):
            return True
    for key, want in _INTERNAL_LB_VALUE_ANNOTATIONS.items():
        v = anns.get(key)
        if isinstance(v, str) and v.strip().lower() == want:
            return True
    return False


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
        # An internal load balancer is private-network-only; a missing
        # source-range list doesn't expose it to the internet.
        if _is_internal_lb(m.data.get("metadata")):
            continue
        ranges = spec.get("loadBalancerSourceRanges")
        if isinstance(ranges, list) and ranges:
            continue
        ports = _ports_summary(spec)
        ports_str = f" ports=[{ports}]" if ports else ""
        offenders.append(f"Service/{m.name}{ports_str}")
        # Anchor on the Service's spec block, that's where the
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
