"""HELM-014. Chart dependency matches a known-compromised chart registry."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from .._compromised_charts import lookup
from ..base import HelmContext

RULE = Rule(
    id="HELM-014",
    title="Chart dependency matches a known-compromised chart registry",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357", "CWE-829"),
    recommendation=(
        "Bump the offending dependency to a patched version named "
        "in the cited advisory and run ``helm dependency update`` "
        "to refresh ``Chart.lock`` with the new digests. If the "
        "advisory has no patched release, pin to the last "
        "known-good version and add a follow-up TODO so the "
        "dependency is replaced or removed in the next maintenance "
        "cycle. After the bump, re-run the scan; HELM-014 should "
        "clear. If the rule still fires, an indirect subchart "
        "is pulling the bad version back in; inspect "
        "``Chart.lock`` for the dependency path."
    ),
    docs_note=(
        "Reads the curated registry under "
        "``pipeline_check.core.checks.helm._compromised_charts`` "
        "(table of ``(chart_name, malicious_versions, advisory)`` "
        "entries) and fires when any ``Chart.yaml`` dependency "
        "matches. Registry is hand-curated and append-only; "
        "adding an entry is a one-line table edit plus the citing "
        "advisory in the commit message.\n\n"
        "Mirrors NPM-006 / PYPI-006 / MVN-006 / NUGET-005 / "
        "GOMOD-006 / CARGO-006: the rule fires on exact-version "
        "equality (with optional regex-fallback patterns shared "
        "via ``_primitives/compromised.py``). Coverage is "
        "necessarily incomplete; the value is the audit-trail-"
        "locked post-incident detection of a published advisory."
    ),
    known_fp=(
        "Patched fork-and-pin remediation paths sometimes "
        "legitimately leave the original chart name pinned at an "
        "affected version (with the actual install pointing at a "
        "fork). The rule still fires on the Chart.yaml entry; "
        "suppress per dependency with a one-line rationale "
        "naming the fork and the advisory the patch covers.",
    ),
    incident_refs=(
        "Future entries follow the same shape as the seeded "
        "examples: append ``(chart_name, version, advisory)`` to "
        "_compromised_charts.py with the citing advisory in the "
        "commit message. Real entries land when public Helm-chart "
        "advisories surface.",
    ),
    exploit_example=(
        "# Vulnerable: dependency pinned at a version named in a\n"
        "# published advisory.\n"
        "# Chart.yaml\n"
        "apiVersion: v2\n"
        "name: my-umbrella\n"
        "version: 1.0.0\n"
        "dependencies:\n"
        "  - name: example-known-bad\n"
        "    version: 1.0.0\n"
        "    repository: https://charts.example.com\n"
        "\n"
        "# Attack: the published advisory enumerates the affected\n"
        "# versions; downstream consumers triggering the\n"
        "# vulnerable code path face the leak surface the advisory\n"
        "# documents.\n"
        "\n"
        "# Safe: bump to the patched release named in the advisory.\n"
        "dependencies:\n"
        "  - name: example-known-bad\n"
        "    version: 1.0.2\n"
        "    repository: https://charts.example.com\n"
        "\n"
        "# Then ``helm dependency update`` to refresh Chart.lock."
    ),
)


def check(ctx: HelmContext) -> Finding:
    if not ctx.charts:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="(no charts)",
            description="No Helm charts in scope; nothing to audit.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for chart in ctx.charts:
        for dep in chart.dependencies:
            name = dep.get("name")
            version = dep.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            entry = lookup(name, version)
            if entry is None:
                continue
            offenders.append(
                f"{chart.name}: {name}@{version} ({entry.advisory})"
            )
            locations.append(Location(
                path=chart.chart_yaml_path,
                start_line=1, end_line=1,
            ))
    passed = not offenders
    desc = (
        "No chart dependency matches the curated compromised-"
        "chart registry."
        if passed else
        f"{len(offenders)} chart dependency / dependencies match "
        f"a known-compromised registry entry: "
        f"{'; '.join(offenders[:3])}"
        f"{' …' if len(offenders) > 3 else ''}. Bump to a patched "
        f"version named in the cited advisory and refresh "
        f"Chart.lock."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=ctx.charts[0].chart_yaml_path,
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
