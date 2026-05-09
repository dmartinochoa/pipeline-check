"""HELM-005, ``Chart.yaml`` ships no usable ``maintainers:`` block.

``maintainers:`` is the chart's chain-of-custody field. Without at
least one entry that carries a ``name`` and either an ``email`` or
``url``, downstream consumers have no way to confirm the chart's
provenance, a forked chart published under a familiar name passes
``helm install`` indistinguishably from the original. The Helm chart
spec calls this field optional but every reference chart in
``artifacthub.io`` populates it; production charts shipped without
it are usually a copy-paste-from-template oversight.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import HelmContext

RULE = Rule(
    id="HELM-005",
    title="Chart maintainers field empty or missing chain-of-custody info",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PROV-INTEGRITY",),
    cwe=("CWE-1059",),
    recommendation=(
        "Populate ``maintainers:`` in ``Chart.yaml`` with at least "
        "one entry carrying a ``name`` plus either an ``email`` or a "
        "``url``. The ``name`` is the human a downstream consumer "
        "files an issue against; the contact field is the channel "
        "they reach. Charts published to ArtifactHub or an internal "
        "registry without this field are silently anonymous, fine "
        "for a personal scratch chart, not for one your CI pipeline "
        "will deploy to production."
    ),
    docs_note=(
        "An ``maintainers:`` entry is considered usable when the "
        "value is a YAML mapping with ``name:`` set to a non-empty "
        "string and at least one of ``email:`` / ``url:`` populated. "
        "Entries that look like ``- name: TODO`` or carry blank "
        "contact fields fail the rule the same way a missing block "
        "does, the field exists but doesn't carry a real "
        "chain-of-custody signal."
    ),
    known_fp=(
        "Library charts (``Chart.yaml`` ``type: library``) often "
        "ship without maintainers when distributed inside a single "
        "team's monorepo where the org-level CODEOWNERS already "
        "names the contact. Suppress with ``--ignore-file`` when "
        "this matches your situation.",
    ),
)


def check(ctx: HelmContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for chart in ctx.charts:
        ms = chart.chart_yaml.get("maintainers")
        if not _has_usable_maintainer(ms):
            offenders.append(f"{chart.name} ({chart.chart_yaml_path})")
            locations.append(Location(path=chart.chart_yaml_path))
    passed = not offenders
    desc = (
        "Every chart declares at least one usable maintainer."
        if passed else
        f"{len(offenders)} chart(s) ship without a usable "
        f"``maintainers:`` block: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="helm/charts",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )


def _has_usable_maintainer(value: Any) -> bool:
    if not isinstance(value, list):
        return False
    for entry in value:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        email = entry.get("email")
        url = entry.get("url")
        if not isinstance(name, str) or not name.strip():
            continue
        if isinstance(email, str) and email.strip():
            return True
        if isinstance(url, str) and url.strip():
            return True
    return False
