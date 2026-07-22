"""HELM-013. Chart.yaml ``type`` field is missing or invalid."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import HelmContext

RULE = Rule(
    id="HELM-013",
    title="Chart.yaml type field set to an invalid value",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Set ``type:`` to either ``application`` (the default for "
        "deployable charts) or ``library`` (for charts shipped as "
        "named templates other charts ``import``). Helm 3 treats "
        "missing ``type`` as ``application``, which is permissive "
        "but leaves the chart's purpose ambiguous at audit time. "
        "An explicit declaration:\n\n"
        "* Makes ``helm install`` reject library charts at install "
        "time (they have no templates that produce manifests).\n"
        "* Documents the chart's role for consumers reviewing "
        "``helm search`` output.\n"
        "* Catches accidental templates added to a library chart "
        "during refactor (the install-time rejection surfaces the "
        "mistake).\n\n"
        "Example:\n\n"
        "    apiVersion: v2\n"
        "    name: myapp\n"
        "    version: 1.0.0\n"
        "    type: application   # or 'library' for template-only\n"
    ),
    docs_note=(
        "Reads ``Chart.yaml`` ``type:`` and fires when the field "
        "is present but set to a value other than ``application`` / "
        "``library`` (the two values defined by the Helm 3 chart "
        "schema; any other value is ignored by Helm at install time, "
        "the silent-failure mode the rule catches). A *missing* "
        "``type:`` passes: Helm 3 defaults it to ``application``, so "
        "omitting it is legitimate and common.\n\n"
        "Helm 2 charts (``apiVersion: v1``) are skipped, the "
        "``type:`` field doesn't exist in v1 and HELM-001 already "
        "catches the v1 shape."
    ),
    known_fp=(
        "Some chart-generation tools (early ``helm create`` "
        "templates, third-party scaffolders) omit ``type:`` "
        "deliberately to defer to Helm's default. The rule still "
        "fires; suppress per chart with a rationale, or — better "
        "— add the explicit ``type: application`` line.",
    ),
    incident_refs=(
        "Common refactoring drift: a chart originally written as "
        "an ``application`` has its templates pulled out and the "
        "``type:`` forgotten. ``helm install`` against the "
        "library-shaped result fails with a cryptic error that "
        "doesn't immediately point at the missing type "
        "declaration; the chart's review process didn't catch "
        "the change because no schema rule was in place.",
    ),
    exploit_example=(
        "# Vulnerable: an invalid type value (typo). Helm ignores it\n"
        "# at install time rather than erroring, so the chart's\n"
        "# intended role is silently lost.\n"
        "# Chart.yaml\n"
        "apiVersion: v2\n"
        "name: myapp\n"
        "version: 1.0.0\n"
        "type: aplication\n"
        "\n"
        "# Safe: a valid explicit type (or omit it to accept Helm's\n"
        "# 'application' default).\n"
        "# Chart.yaml\n"
        "apiVersion: v2\n"
        "name: myapp\n"
        "version: 1.0.0\n"
        "type: application"
    ),
)


_VALID_TYPES: frozenset[str] = frozenset({"application", "library"})


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
        if chart.api_version == "v1":
            continue  # Helm 2: HELM-001 owns this surface.
        t = chart.chart_yaml.get("type")
        if t is None:
            # Omitting ``type:`` is legitimate: Helm 3 defaults a missing
            # type to ``application``. Only a present-but-invalid value is
            # the silent-failure shape this rule targets.
            continue
        if isinstance(t, str) and t in _VALID_TYPES:
            continue
        offenders.append(f"{chart.name}: type={t!r}")
    passed = not offenders
    desc = (
        "Every Helm 3 chart declares an explicit application / "
        "library type."
        if passed else
        f"{len(offenders)} Helm 3 chart(s) have a missing or "
        f"invalid type field: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=ctx.charts[0].chart_yaml_path,
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
