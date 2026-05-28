"""HELM-011. Chart dependency repository URL embeds plaintext credentials."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import HelmContext

RULE = Rule(
    id="HELM-011",
    title="Chart dependency repository URL embeds plaintext credentials",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-10"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798", "CWE-522"),
    recommendation=(
        "Move the credential out of the URL and into the consumer's "
        "Helm-side credential store. Three stable patterns:\n\n"
        "* Add the repo once with credentials: ``helm repo add "
        "<name> https://<host>/<path> --username <u> --password "
        "<p>``. The credentials land in the user's "
        "``~/.config/helm/repositories.yaml`` (not in the repo) "
        "and the chart's ``Chart.yaml`` references the alias "
        "(``repository: @<name>``).\n"
        "* For CI/CD environments, inject credentials at chart-"
        "fetch time from environment variables (Helm 3 honors "
        "``HELM_REGISTRY_USERNAME`` / ``HELM_REGISTRY_PASSWORD`` "
        "for OCI registries) and keep ``Chart.yaml`` clean.\n"
        "* For pure HTTPS chart repos, switch to OCI "
        "(``repository: oci://<registry>/<repo>``). OCI registries "
        "use the standard Docker credential helper chain, so "
        "credentials live in ``~/.docker/config.json`` or a "
        "managed credential helper, never in Chart.yaml.\n\n"
        "Credentials embedded in a committed ``Chart.yaml`` lock "
        "the password into git history. Rotation requires "
        "consumer-side updates *plus* history scrub before the "
        "leaked credential stops being useful to an attacker."
    ),
    docs_note=(
        "Reads each ``Chart.yaml`` ``dependencies[].repository`` "
        "URL and fires when the authority component carries an "
        "``<user>:<pass>@`` prefix. Empty-password forms "
        "(``https://user:@host``) and ``${VAR}`` placeholders are "
        "skipped — the former is an operator-flagged 'no "
        "credential intended' marker and the latter resolves at "
        "fetch time from the environment rather than the "
        "manifest text.\n\n"
        "Distinct from HELM-003 (non-HTTPS scheme), which catches "
        "the transport-side risk. This rule catches the "
        "credential-leakage risk: an HTTPS URL with embedded "
        "credentials passes HELM-003 cleanly but still leaks the "
        "credential into git."
    ),
    known_fp=(
        "Templated Chart.yaml files that materialize a placeholder "
        "credential form (``https://__USER__:__PASS__@host``) and "
        "substitute the real value at install time trip this rule "
        "by shape. Suppress per dependency when the placeholder "
        "marker is stable; the rule's placeholder skip-list only "
        "recognizes ``${...}``.",
    ),
    incident_refs=(
        "Long-running pattern of internal chart-museum credentials "
        "leaking through Chart.yaml committed to public mirrors. "
        "The credential's audit trail (last rotated, who has it) "
        "is lost the moment the file lands in a clone an "
        "attacker controls; rotation costs scale with the number "
        "of consumers.",
    ),
    exploit_example=(
        "# Vulnerable: credential pasted into the dependency URL.\n"
        "# Chart.yaml\n"
        "apiVersion: v2\n"
        "name: my-app\n"
        "version: 1.0.0\n"
        "dependencies:\n"
        "  - name: redis\n"
        "    version: 17.0.0\n"
        "    repository: https://deploy-bot:s3cret@charts.corp/private/\n"
        "\n"
        "# Attack: ``git push`` lands Chart.yaml in repo history.\n"
        "# Any clone (CI cache, contractor laptop, archived backup)\n"
        "# carries the deploy-bot credential indefinitely. A leak\n"
        "# of the repo turns into full read access to the internal\n"
        "# chart-museum, including any private charts that weren't\n"
        "# otherwise meant to be visible.\n"
        "\n"
        "# Safe: alias-based reference with credentials in the\n"
        "# user's local Helm config.\n"
        "# $ helm repo add corp-charts https://charts.corp/private/\n"
        "#     --username deploy-bot --password $TOKEN\n"
        "# Chart.yaml\n"
        "dependencies:\n"
        "  - name: redis\n"
        "    version: 17.0.0\n"
        "    repository: \"@corp-charts\""
    ),
)


# Match ``://user:pass@host``. Excludes empty-password forms and
# ``${var}`` placeholders so the rule's signal stays clean.
_AUTH_RE = re.compile(
    r"://(?P<user>[^/@:\s\${]+):(?P<pass>[^/@\s\${][^/@\s]*)@",
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
        for idx, dep in enumerate(chart.dependencies):
            url = dep.get("repository")
            if not isinstance(url, str):
                continue
            m = _AUTH_RE.search(url)
            if not m:
                continue
            user = m.group("user")
            host = url.split("@", 1)[1].split("/", 1)[0]
            name = dep.get("name", f"deps[{idx}]")
            offenders.append(
                f"{chart.name}: dependency {name!r} at {user}@{host}"
            )
            locations.append(Location(
                path=chart.chart_yaml_path,
                start_line=1, end_line=1,
            ))
    passed = not offenders
    desc = (
        "No chart dependency URLs carry embedded credentials."
        if passed else
        f"{len(offenders)} chart dependency URL(s) carry embedded "
        f"credentials: {'; '.join(offenders[:3])}"
        f"{' …' if len(offenders) > 3 else ''}. Each credential "
        f"persists in git history; rotation requires consumer-"
        f"side updates plus history scrub."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=ctx.charts[0].chart_yaml_path,
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
