"""NUGET-007, multiple NuGet sources without packageSourceMapping."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import NuGetConfig

RULE = Rule(
    id="NUGET-007",
    title="Multiple NuGet sources without packageSourceMapping",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Add a ``<packageSourceMapping>`` section to NuGet.config "
        "that maps each package pattern to its intended source. "
        "Without source mapping, NuGet queries every configured "
        "source for every package and installs the highest version "
        "found across all of them, the exact shape exploited by "
        "dependency confusion attacks. Source mapping pins each "
        "package namespace to one feed so a malicious publication "
        "on a secondary feed is never considered."
    ),
    docs_note=(
        "Fires when NuGet.config has more than one package source "
        "and no ``packageSourceMapping`` section."
    ),
    exploit_example=(
        "# Vulnerable: two sources, no mapping. NuGet queries both\n"
        "# and installs the highest version found across them.\n"
        "# An attacker publishes Contoso.Internal 99.0.0 on\n"
        "# nuget.org; NuGet picks it over the real 2.1.0 from\n"
        "# the private feed.\n"
        "<!-- NuGet.config -->\n"
        "<packageSources>\n"
        '  <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />\n'
        '  <add key="internal" value="https://nuget.corp.local/v3/index.json" />\n'
        "</packageSources>\n"
        "\n"
        "# Safe: add packageSourceMapping.\n"
        "<packageSourceMapping>\n"
        '  <packageSource key="nuget.org">\n'
        '    <package pattern="*" />\n'
        "  </packageSource>\n"
        '  <packageSource key="internal">\n'
        '    <package pattern="Contoso.*" />\n'
        "  </packageSource>\n"
        "</packageSourceMapping>"
    ),
)


def check(config: NuGetConfig) -> Finding:
    multiple_sources = len(config.sources) > 1
    has_mapping = bool(config.source_mappings)
    fire = multiple_sources and not has_mapping
    if not multiple_sources:
        desc = (
            "NuGet.config declares zero or one package source; "
            "packageSourceMapping is not required."
        )
    elif has_mapping:
        desc = (
            "NuGet.config declares multiple package sources and "
            "has a packageSourceMapping section."
        )
    else:
        source_names = ", ".join(s.name for s in config.sources[:5])
        if len(config.sources) > 5:
            source_names += f" (+{len(config.sources) - 5} more)"
        desc = (
            f"NuGet.config declares {len(config.sources)} package "
            f"sources ({source_names}) but has no "
            f"packageSourceMapping. NuGet queries every source for "
            f"every package and installs the highest version found, "
            f"enabling dependency confusion attacks."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=config.path, description=desc,
        recommendation=RULE.recommendation, passed=not fire,
    )
