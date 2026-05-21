"""K8S-005. Container ``securityContext.privileged: true``."""
from __future__ import annotations

from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import (
    KubernetesContext,
    container_name,
    iter_containers,
    iter_workload_pod_specs,
)


def _sec_ctx(c: dict[str, Any]) -> dict[str, Any]:
    sc = c.get("securityContext")
    return sc if isinstance(sc, dict) else {}


RULE = Rule(
    id="K8S-005",
    title="Container securityContext.privileged: true",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-250",),
    recommendation=(
        "Remove ``securityContext.privileged: true`` from every "
        "container. A privileged container has full access to the "
        "host's devices and capabilities, escape to the node is "
        "trivial. If the workload genuinely needs a kernel "
        "capability, grant only that capability via "
        "``capabilities.add`` rather than enabling privileged mode."
    ),
    docs_note=(
        "``privileged: true`` is the strongest possible escalation in "
        "Kubernetes. It overrides every other securityContext setting "
        "and is the single largest cluster-takeover vector after RBAC "
        "misconfiguration."
    ),
    exploit_example=(
        "# Vulnerable: ``privileged: true`` gives the container the\n"
        "# equivalent of root on the node — full ``/dev`` access,\n"
        "# every Linux capability, and the ability to bypass\n"
        "# namespace isolation. A workload compromise (poisoned\n"
        "# image, RCE in app code, malicious chart) becomes a\n"
        "# node-level shell, and from there pivots to every other\n"
        "# pod on the node via the kubelet's credentials.\n"
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata: { name: app }\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: app\n"
        "          image: app:1.2.3\n"
        "          securityContext:\n"
        "            privileged: true\n"
        "\n"
        "# Safe: drop all caps; if the app genuinely needs ONE\n"
        "# capability (e.g. ``NET_BIND_SERVICE`` to listen on port\n"
        "# 80), add it back explicitly. ``runAsNonRoot`` +\n"
        "# ``readOnlyRootFilesystem`` close the remaining escape\n"
        "# routes that ``privileged: false`` alone doesn't.\n"
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata: { name: app }\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: app\n"
        "          image: app@sha256:abc123...\n"
        "          securityContext:\n"
        "            privileged: false\n"
        "            allowPrivilegeEscalation: false\n"
        "            runAsNonRoot: true\n"
        "            readOnlyRootFilesystem: true\n"
        "            capabilities:\n"
        "              drop: [\"ALL\"]"
    ),
)


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m, ps in iter_workload_pod_specs(ctx):
        for kind, c in iter_containers(ps):
            sc = _sec_ctx(c)
            if sc.get("privileged") is True:
                offenders.append(
                    f"{m.kind}/{m.name} {kind}={container_name(c)}"
                )
                # Anchor the line on the securityContext block itself
                # so the user lands on the offending field, not the
                # container's name. Falls back to the container line
                # when securityContext is inlined / missing line marks.
                line = _line_of(sc) or _line_of(c)
                locations.append(Location(
                    path=m.path, start_line=line, end_line=line,
                    doc_index=m.doc_index,
                ))
    passed = not offenders
    desc = (
        "No container runs with ``privileged: true``."
        if passed else
        f"{len(offenders)} container(s) run privileged: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
