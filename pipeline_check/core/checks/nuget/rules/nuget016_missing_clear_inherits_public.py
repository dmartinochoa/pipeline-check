"""NUGET-016. Private feed without <clear/> inherits the public gallery."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

from ...base import Finding, Severity
from ...rule import Rule
from ..base import NuGetConfig, NuGetContext

RULE = Rule(
    id="NUGET-016",
    title="Private feed without <clear/> inherits the public gallery",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Add a ``<clear />`` element as the first child of "
        "``<packageSources>`` in ``NuGet.config``, then list every "
        "source the project is allowed to use explicitly:\n\n"
        "    <packageSources>\n"
        "      <clear />\n"
        "      <add key=\"internal\" value=\"https://nuget.corp.local/v3/index.json\" />\n"
        "      <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n"
        "    </packageSources>\n\n"
        "NuGet merges ``packageSources`` across the machine, user, "
        "and repo configs, so a repo config that lists only the "
        "internal feed still resolves ``nuget.org`` (added by the "
        "machine-level default config). Because NuGet installs the "
        "highest version found across every active source, a public "
        "package that shadows an internal name can win the race. "
        "``<clear />`` discards the inherited sources so only the "
        "ones you list apply. Pair it with ``<packageSourceMapping>`` "
        "(see NUGET-007) to pin each namespace to one feed."
    ),
    docs_note=(
        "Fires when a ``NuGet.config`` declares at least one "
        "non-``nuget.org`` package source and its "
        "``<packageSources>`` block has no ``<clear />`` element. "
        "The rule re-reads the file to detect ``<clear />`` (the "
        "loader keeps only ``<add>`` entries). A source counts as "
        "the public gallery when its URL contains ``nuget.org``; "
        "anything else (an internal Nexus / Artifactory / "
        "Azure Artifacts feed, a local folder) is treated as a "
        "private feed whose names a public package could shadow.\n\n"
        "Distinct from NUGET-007 (multiple sources without "
        "``packageSourceMapping``): NUGET-007 only fires when one "
        "config enumerates two or more sources, so it structurally "
        "misses the common shape this rule catches, a config that "
        "lists only the internal feed while ``nuget.org`` leaks in "
        "through config inheritance. Microsoft's \"3 Ways to "
        "Mitigate Risk Using Private Package Feeds\" names "
        "``<clear/>`` as the fix."
    ),
    known_fp=(
        "A repo whose only source is an internal mirror that itself "
        "proxies and screens nuget.org may accept the inherited "
        "gallery deliberately. The rule still fires because the "
        "config text alone can't prove the mirror screens for "
        "dependency confusion. Suppress per config with a one-line "
        "rationale naming the mirror's policy.",
    ),
    incident_refs=(
        "Birsan 2021 dependency-confusion research: internal "
        "package names resolved against the public registry because "
        "the public feed stayed active alongside the private one. "
        "The .NET face of the attack is a NuGet.config that adds a "
        "private feed without ``<clear/>``, leaving nuget.org in the "
        "resolution set so a public package with the internal name "
        "and a higher version is installed.",
    ),
    exploit_example=(
        "<!-- Vulnerable: internal feed added, no <clear/>. nuget.org\n"
        "     is still inherited from the machine-level config. -->\n"
        "<configuration>\n"
        "  <packageSources>\n"
        "    <add key=\"internal\" value=\"https://nuget.corp.local/v3/index.json\" />\n"
        "  </packageSources>\n"
        "</configuration>\n"
        "\n"
        "<!-- Attack: the internal package Contoso.Billing is at\n"
        "     2.1.0 on the private feed. An attacker publishes\n"
        "     Contoso.Billing 99.0.0 on nuget.org. Restore queries\n"
        "     both active sources and installs the public 99.0.0.\n"
        "-->\n"
        "\n"
        "<!-- Safe: <clear/> drops the inherited sources. -->\n"
        "<configuration>\n"
        "  <packageSources>\n"
        "    <clear />\n"
        "    <add key=\"internal\" value=\"https://nuget.corp.local/v3/index.json\" />\n"
        "    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n"
        "  </packageSources>\n"
        "</configuration>"
    ),
)


_MSBUILD_NS = re.compile(r"^\{[^}]+\}")


def _strip_ns(tag: str) -> str:
    return _MSBUILD_NS.sub("", tag)


def _package_sources_cleared(cfg_path: str) -> bool:
    """Re-parse the file: is there a ``<clear/>`` in ``<packageSources>``?

    The loader keeps only ``<add>`` entries, so the presence of a
    ``<clear/>`` (which discards inherited sources) has to be read
    back from the file. Returns ``True`` when any ``<packageSources>``
    block contains a direct ``<clear>`` child.
    """
    try:
        tree = ET.parse(cfg_path)
    except (ET.ParseError, OSError):
        # Unparseable here means the loader also failed; treat as
        # not-cleared so we don't suppress on a parse error.
        return False
    for elem in tree.iter():
        if _strip_ns(elem.tag) != "packageSources":
            continue
        for child in elem:
            if _strip_ns(child.tag) == "clear":
                return True
    return False


def _is_public_gallery(url: str) -> bool:
    # Match the host on a dot boundary, not a bare substring, so a
    # lookalike feed (``nuget.org.evil.example``, ``nuget-org.attacker``)
    # isn't misread as the public gallery and dropped from the private
    # set. Mirrors the host-allowlist idiom in gha057.
    host = (urlparse(url).hostname or "").lower()
    return host == "nuget.org" or host.endswith(".nuget.org")


def check(cfg: NuGetConfig, ctx: NuGetContext) -> Finding:
    private = [s for s in cfg.sources if not _is_public_gallery(s.url)]
    if not private:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=cfg.path,
            description=(
                "NuGet.config declares no private package source; "
                "inheriting the public gallery carries no "
                "dependency-confusion risk."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    cfg_path = Path(cfg.path)
    if not cfg_path.is_absolute() and ctx.scan_root is not None:
        cfg_path = ctx.scan_root / cfg_path
    if _package_sources_cleared(str(cfg_path)):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=cfg.path,
            description=(
                "NuGet.config clears inherited sources with "
                "<clear/> before adding its own; the public gallery "
                "is not silently inherited."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    names = ", ".join(s.name for s in private[:5])
    if len(private) > 5:
        names += f" (+{len(private) - 5} more)"
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=cfg.path,
        description=(
            f"NuGet.config adds {len(private)} private feed / feeds "
            f"({names}) with no <clear/> in <packageSources>. NuGet "
            f"merges sources across machine / user / repo configs, so "
            f"nuget.org stays in the resolution set and a public "
            f"package shadowing an internal name can win on "
            f"highest-version-wins (dependency confusion)."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
