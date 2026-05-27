"""GCRUN-003. Cloud Run service has zero minimum instances."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCRUN-003",
    title="Cloud Run service has zero minimum instances",
    severity=Severity.LOW,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-400",),
    recommendation=(
        "Set min_instance_count to at least 1 for latency-sensitive "
        "services. Zero minimum instances cause cold starts on the "
        "first request after an idle period."
    ),
    docs_note=(
        "A minimum instance count of zero means the service scales to "
        "zero when idle. The first request after idle incurs a cold "
        "start delay. For security-sensitive services (auth endpoints, "
        "webhook receivers), cold starts can cause timeouts that mask "
        "availability."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for svc in catalog.cloud_run_services():
        name = svc.get("name", "<unnamed>")
        template = svc.get("template", {})
        scaling = template.get("scaling", {})
        min_count = scaling.get("min_instance_count", 0)
        if min_count == 0:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Cloud Run service '{name}' has "
                    "min_instance_count=0. It will scale to zero "
                    "and incur cold starts."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
        else:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Cloud Run service '{name}' has "
                    f"min_instance_count={min_count}."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    return findings
