"""HELM-006, ``Chart.yaml`` declares no ``kubeVersion`` compat range.

``kubeVersion:`` is the SemVer range of Kubernetes API versions the
chart is known to render against. Helm refuses ``helm install``
when the cluster's reported version is outside the range, which is
the only static guard against rendering against an unsupported API
shape (a removed apiVersion, a renamed RBAC verb, an alpha feature
the chart still uses). Charts shipped without ``kubeVersion`` will
``helm install`` against any cluster, including one that quietly
drops the ``policy/v1beta1`` PSP the chart still emits, silent
breakage instead of a clear pre-flight rejection.
"""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import HelmContext

RULE = Rule(
    id="HELM-006",
    title="Chart.yaml does not declare a kubeVersion compatibility range",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-D-COMPAT",),
    cwe=("CWE-1357",),
    recommendation=(
        "Add a ``kubeVersion:`` SemVer range to ``Chart.yaml`` "
        "covering the Kubernetes versions you've actually rendered "
        "and tested the chart against. ``>= 1.25.0 < 1.32.0`` is the "
        "common shape for a chart maintained against the upstream "
        "support window. Helm will refuse ``helm install`` against "
        "a cluster whose ``kubectl version`` falls outside the "
        "range, catching silent-breakage surprises (removed "
        "apiVersions, renamed RBAC verbs, alpha features) at "
        "pre-flight rather than at runtime."
    ),
    docs_note=(
        "The field is a string carrying a Helm-flavored SemVer "
        "range. Empty / missing fails the rule. Whitespace-only "
        "values fail too, an obviously-blank key should not "
        "satisfy a posture check."
    ),
    known_fp=(
        "Library charts (``Chart.yaml`` ``type: library``) that "
        "wrap version-agnostic helpers often legitimately ship "
        "without ``kubeVersion``. Suppress with ``--ignore-file`` "
        "when the chart genuinely targets every supported "
        "Kubernetes minor.",
    ),
)


def check(ctx: HelmContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for chart in ctx.charts:
        kv = chart.chart_yaml.get("kubeVersion")
        if not isinstance(kv, str) or not kv.strip():
            offenders.append(f"{chart.name} ({chart.chart_yaml_path})")
            locations.append(Location(path=chart.chart_yaml_path))
    passed = not offenders
    desc = (
        "Every chart declares a ``kubeVersion`` compatibility range."
        if passed else
        f"{len(offenders)} chart(s) ship without ``kubeVersion``: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="helm/charts",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
