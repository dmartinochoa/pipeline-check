"""NUGET-017. Public gallery active alongside a private feed, not disabled."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

from ...base import Finding, Severity
from ...rule import Rule
from ..base import NuGetConfig, NuGetContext

RULE = Rule(
    id="NUGET-017",
    title="Public gallery active alongside a private feed, not disabled",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "When a ``NuGet.config`` lists both a private feed and "
        "``nuget.org`` as active sources, disable the public gallery "
        "for restore unless you genuinely consume public packages "
        "from it, or pin every namespace to one feed with "
        "``<packageSourceMapping>`` (NUGET-007). The targeted fix is "
        "a ``<disabledPackageSources>`` entry:\n\n"
        "    <disabledPackageSources>\n"
        "      <add key=\"nuget.org\" value=\"true\" />\n"
        "    </disabledPackageSources>\n\n"
        "With the gallery active, NuGet's highest-version-wins "
        "resolution lets a public package that shadows an internal "
        "name win the restore, the Birsan dependency-confusion "
        "vector. ``packageSourceMapping`` is the strongest control "
        "(each name resolves from exactly one feed); disabling the "
        "gallery is the blunt instrument when no public package is "
        "needed."
    ),
    docs_note=(
        "Fires when a ``NuGet.config`` (1) lists at least one "
        "private (non-``nuget.org``) source, (2) lists the public "
        "gallery as an explicit active ``<add>`` source, and (3) "
        "does NOT disable that gallery key in "
        "``<disabledPackageSources>``. The rule re-reads the file to "
        "collect the truthy ``<disabledPackageSources>`` keys (the "
        "loader doesn't surface them).\n\n"
        "Companion to NUGET-016, scoped to the complementary "
        "mitigation: NUGET-016 owns the inheritance case (only the "
        "private feed listed, no ``<clear/>``, so ``nuget.org`` "
        "leaks in from the machine config), while this rule owns the "
        "explicit-coexistence case (both feeds listed, the gallery "
        "not disabled). A config that uses ``<clear/>`` and then "
        "re-adds ``nuget.org`` passes NUGET-016 but still trips this "
        "rule, the gallery is active. A config that absent both "
        "mitigations legitimately trips both."
    ),
    known_fp=(
        "A repo that deliberately consumes public packages from "
        "``nuget.org`` alongside its private feed, and pins names "
        "with ``packageSourceMapping`` (NUGET-007) so confusion "
        "can't occur, may keep the gallery active by design. The "
        "rule doesn't read the mapping coverage; suppress per config "
        "with a rationale once the namespace pinning is confirmed.",
    ),
    incident_refs=(
        "Birsan 2021 dependency-confusion research. The .NET face is "
        "a NuGet.config that keeps ``nuget.org`` active next to a "
        "private feed without disabling it or pinning namespaces, so "
        "a public package with an internal name and a higher version "
        "wins the highest-version-wins restore.",
    ),
    exploit_example=(
        "<!-- Vulnerable: both feeds active, gallery not disabled. -->\n"
        "<configuration>\n"
        "  <packageSources>\n"
        "    <clear />\n"
        "    <add key=\"internal\" value=\"https://nuget.corp.local/v3/index.json\" />\n"
        "    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n"
        "  </packageSources>\n"
        "</configuration>\n"
        "\n"
        "<!-- Attack: internal Contoso.Billing is 2.1.0 on the\n"
        "     private feed; an attacker publishes 99.0.0 on\n"
        "     nuget.org. Both sources are active, so restore picks\n"
        "     the public 99.0.0. (The <clear/> means NUGET-016\n"
        "     passes; only this rule catches the live gallery.) -->\n"
        "\n"
        "<!-- Safe: disable the gallery for restore. -->\n"
        "<configuration>\n"
        "  <packageSources>\n"
        "    <clear />\n"
        "    <add key=\"internal\" value=\"https://nuget.corp.local/v3/index.json\" />\n"
        "    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n"
        "  </packageSources>\n"
        "  <disabledPackageSources>\n"
        "    <add key=\"nuget.org\" value=\"true\" />\n"
        "  </disabledPackageSources>\n"
        "</configuration>"
    ),
)


_MSBUILD_NS = re.compile(r"^\{[^}]+\}")
_TRUTHY = {"true", "1", "yes"}


def _strip_ns(tag: str) -> str:
    return _MSBUILD_NS.sub("", tag)


def _is_public_gallery(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host == "nuget.org" or host.endswith(".nuget.org")


def _disabled_source_keys(cfg_path: str) -> set[str]:
    """Re-parse the file for ``<disabledPackageSources>`` and return
    the set of source keys disabled with a truthy value. The loader
    doesn't surface this section, so it's read back from disk."""
    out: set[str] = set()
    try:
        tree = ET.parse(cfg_path)
    except (ET.ParseError, OSError):
        return out
    for elem in tree.iter():
        if _strip_ns(elem.tag) != "disabledPackageSources":
            continue
        for child in elem:
            if _strip_ns(child.tag) != "add":
                continue
            key = child.get("key") or ""
            value = (child.get("value") or "").strip().lower()
            if key and value in _TRUTHY:
                out.add(key)
    return out


def check(cfg: NuGetConfig, ctx: NuGetContext) -> Finding:
    private = [s for s in cfg.sources if not _is_public_gallery(s.url)]
    public = [s for s in cfg.sources if _is_public_gallery(s.url)]
    # No private feed => no dependency-confusion surface; gallery-only
    # configs are a different (benign) posture.
    if not private or not public:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=cfg.path,
            description=(
                "NuGet.config does not list both a private feed and "
                "an explicit public gallery source."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    cfg_path = Path(cfg.path)
    if not cfg_path.is_absolute() and ctx.scan_root is not None:
        cfg_path = ctx.scan_root / cfg_path
    disabled = _disabled_source_keys(str(cfg_path))
    active_public = [s for s in public if s.name not in disabled]
    if not active_public:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=cfg.path,
            description=(
                "The public gallery is disabled via "
                "<disabledPackageSources>; it can't shadow the "
                "private feed at restore."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    names = ", ".join(s.name for s in active_public[:3])
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=cfg.path,
        description=(
            f"NuGet.config keeps the public gallery active ({names}) "
            f"alongside {len(private)} private feed / feeds without a "
            f"<disabledPackageSources> entry. NuGet's "
            f"highest-version-wins restore lets a public package "
            f"shadowing an internal name win (dependency confusion); "
            f"disable the gallery or pin names with "
            f"<packageSourceMapping>."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
