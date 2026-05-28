"""HELM-012. Chart marked deprecated without naming a successor."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import HelmContext

RULE = Rule(
    id="HELM-012",
    title="Chart marked deprecated without naming a successor",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1104", "CWE-1357"),
    recommendation=(
        "When marking a chart ``deprecated: true``, point consumers "
        "at the replacement. The two stable patterns are:\n\n"
        "* Set ``sources:`` to the successor repo URL and update "
        "``home:`` to point at the migration guide:\n\n"
        "    deprecated: true\n"
        "    sources:\n"
        "      - https://github.com/example/myapp-chart-v2\n"
        "    home: https://example.com/docs/myapp-chart-migration\n\n"
        "* Add an explicit migration annotation:\n\n"
        "    annotations:\n"
        "      \"helm.sh/migration-guide\": "
        "\"https://example.com/myapp-v2-migration\"\n"
        "      \"helm.sh/replacement\": \"corp-charts/myapp-v2\"\n\n"
        "A deprecation flag without a successor strands every "
        "consumer at the deprecated version. Without active "
        "maintenance, security patches don't roll out; consumers "
        "either get stuck running known-vulnerable software or "
        "have to discover the replacement chart through ad-hoc "
        "channels (Slack, GitHub issues, internal wikis) that "
        "scale poorly across teams."
    ),
    docs_note=(
        "Reads ``Chart.yaml`` and fires on charts where "
        "``deprecated: true`` is set AND none of the following "
        "successor-signal fields are populated:\n\n"
        "* ``home:`` (non-empty URL)\n"
        "* ``sources:`` (non-empty list of URLs)\n"
        "* annotations matching keys ``deprecation-guide``, "
        "``migration-guide``, ``replacement``, ``successor``, "
        "``replaced-by`` (case-insensitive substring match)\n\n"
        "Charts that are deprecated but still maintained (a "
        "security-fix-only mode) should populate ``home:`` with "
        "the maintenance policy URL so the rule passes."
    ),
    known_fp=(
        "Internal libraries that go through a 'soft-deprecation' "
        "phase before the successor lands sometimes mark "
        "``deprecated: true`` without a successor name in the "
        "interim. The rule still fires; suppress per chart with a "
        "one-line rationale and a TODO to add the successor "
        "annotation when the replacement is ready.",
    ),
    incident_refs=(
        "Long-running pattern in the Bitnami / community-charts "
        "ecosystem: a chart is marked deprecated, the maintainer "
        "moves on, consumers continue installing the deprecated "
        "version for years without knowing the replacement "
        "exists. The successor annotation (or a populated "
        "``home:`` URL) closes the discovery gap.",
    ),
    exploit_example=(
        "# Vulnerable: deprecated without successor.\n"
        "# Chart.yaml\n"
        "apiVersion: v2\n"
        "name: myapp\n"
        "version: 1.0.0\n"
        "deprecated: true\n"
        "\n"
        "# Risk: consumers see the deprecation warning at install\n"
        "# time but have no path forward. Security advisories\n"
        "# against the chart's images don't get patched; pinning\n"
        "# to a SemVer range that the deprecated maintainer\n"
        "# never updates locks the consumer into the\n"
        "# vulnerability indefinitely.\n"
        "\n"
        "# Safe: name the successor.\n"
        "# Chart.yaml\n"
        "apiVersion: v2\n"
        "name: myapp\n"
        "version: 1.0.0\n"
        "deprecated: true\n"
        "sources:\n"
        "  - https://github.com/example/myapp-v2-chart\n"
        "home: https://docs.example.com/myapp-migration\n"
        "annotations:\n"
        "  \"helm.sh/replacement\": \"corp-charts/myapp-v2\""
    ),
)


_SUCCESSOR_ANNOTATIONS: tuple[str, ...] = (
    "deprecation-guide",
    "migration-guide",
    "replacement",
    "successor",
    "replaced-by",
)


def _has_successor_signal(chart_yaml: dict[str, Any]) -> bool:
    home = chart_yaml.get("home")
    if isinstance(home, str) and home.strip():
        return True
    sources = chart_yaml.get("sources")
    if isinstance(sources, list) and any(
        isinstance(s, str) and s.strip() for s in sources
    ):
        return True
    annotations = chart_yaml.get("annotations")
    if isinstance(annotations, dict):
        for key in annotations:
            if not isinstance(key, str):
                continue
            kl = key.lower()
            if any(token in kl for token in _SUCCESSOR_ANNOTATIONS):
                return True
    return False


def check(ctx: HelmContext) -> Finding:
    if not ctx.charts:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="(no charts)",
            description="No Helm charts in scope; nothing to audit.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for chart in ctx.charts:
        if not bool(chart.chart_yaml.get("deprecated")):
            continue
        if _has_successor_signal(chart.chart_yaml):
            continue
        offenders.append(chart.name)
    passed = not offenders
    desc = (
        "No deprecated charts ship without a successor signal."
        if passed else
        f"{len(offenders)} deprecated chart(s) have no successor "
        f"signal (home / sources / replacement annotation): "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Consumers see the "
        f"warning but have no migration path."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=ctx.charts[0].chart_yaml_path,
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
