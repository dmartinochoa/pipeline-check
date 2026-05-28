"""NUGET-011. packageSourceMapping pattern is a global wildcard."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import NuGetConfig

RULE = Rule(
    id="NUGET-011",
    title="packageSourceMapping pattern is a global wildcard",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Replace the ``*`` (or other broadly-matching wildcard) "
        "pattern with explicit package-name prefixes so each "
        "package is routed to the source the team has chosen for "
        "it. The point of ``<packageSourceMapping>`` is to gate "
        "every package against a single trusted source per "
        "namespace; a ``*`` catch-all defeats the gate and lets "
        "any package — including dependency-confusion typo-squats "
        "— flow through whichever source happens to win the "
        "race.\n\n"
        "Example for an internal package convention:\n\n"
        "    <packageSourceMapping>\n"
        "      <packageSource key=\"nuget.org\">\n"
        "        <package pattern=\"Newtonsoft.Json\" />\n"
        "        <package pattern=\"Microsoft.*\" />\n"
        "      </packageSource>\n"
        "      <packageSource key=\"corp-nexus\">\n"
        "        <package pattern=\"Corp.*\" />\n"
        "        <package pattern=\"Internal.*\" />\n"
        "      </packageSource>\n"
        "    </packageSourceMapping>\n\n"
        "Every package now maps to exactly one source via "
        "longest-prefix match. A typo-squat that doesn't match a "
        "known prefix is rejected at restore time."
    ),
    docs_note=(
        "Walks ``NuGet.config`` ``<packageSourceMapping>`` entries "
        "and fires when any ``<package pattern=\"...\">`` is a "
        "global wildcard. The recognized wildcard shapes:\n\n"
        "* ``*`` — match everything\n"
        "* ``**`` — equivalent to ``*`` in NuGet pattern syntax\n\n"
        "Prefix wildcards (``Microsoft.*``, ``Corp.*``) are the "
        "*intended* use of ``<package pattern>`` — they map a "
        "package-name namespace to a specific source and don't "
        "trip this rule. The signal is specifically the "
        "unbounded global wildcard that turns the mapping into a "
        "no-op.\n\n"
        "Distinct from NUGET-007 (no packageSourceMapping at all): "
        "this rule catches the case where mapping exists but is "
        "ineffective."
    ),
    known_fp=(
        "Some workspaces use a global ``*`` deliberately to route "
        "all packages through a single internal mirror that does "
        "its own dependency-confusion screening. The rule still "
        "fires because the mapping itself doesn't carry the "
        "screening guarantee. Suppress per config with a one-line "
        "rationale naming the mirror's policy.",
    ),
    incident_refs=(
        "Pattern in .NET monorepos that adopt "
        "``<packageSourceMapping>`` as a quick fix during a "
        "dependency-confusion incident response: the initial "
        "mapping uses ``*`` to avoid breaking existing restore "
        "paths, the cleanup pass that replaces it with explicit "
        "prefixes never lands. The mapping looks present at "
        "audit time but provides no real gating.",
    ),
    exploit_example=(
        "<!-- Vulnerable: wildcard defeats the mapping. -->\n"
        "<packageSourceMapping>\n"
        "  <packageSource key=\"corp-nexus\">\n"
        "    <package pattern=\"*\" />\n"
        "  </packageSource>\n"
        "</packageSourceMapping>\n"
        "\n"
        "<!-- Attack: a contributor names an internal package\n"
        "     ``Corp.Internal.PaymentLib`` and a typo-squatter\n"
        "     publishes ``Corp.Intemal.PaymentLib`` on nuget.org.\n"
        "     The wildcard mapping routes every package through\n"
        "     the corp source first, but because the corp source\n"
        "     also reflects nuget.org via a transparent proxy,\n"
        "     the typo-squat is served and consumed.\n"
        "-->\n"
        "\n"
        "<!-- Safe: explicit per-namespace mapping. -->\n"
        "<packageSourceMapping>\n"
        "  <packageSource key=\"nuget.org\">\n"
        "    <package pattern=\"Newtonsoft.Json\" />\n"
        "    <package pattern=\"Microsoft.*\" />\n"
        "  </packageSource>\n"
        "  <packageSource key=\"corp-nexus\">\n"
        "    <package pattern=\"Corp.*\" />\n"
        "  </packageSource>\n"
        "</packageSourceMapping>"
    ),
)


_WILDCARDS: frozenset[str] = frozenset({"*", "**"})


def check(cfg: NuGetConfig) -> Finding:
    offenders: list[str] = []
    for mapping in cfg.source_mappings:
        for pattern in mapping.patterns:
            if pattern.strip() in _WILDCARDS:
                offenders.append(f"{mapping.source}: {pattern!r}")
    passed = not offenders
    desc = (
        "Every packageSourceMapping pattern is an explicit "
        "prefix; no global wildcards."
        if passed else
        f"{len(offenders)} packageSourceMapping entry / entries "
        f"use a global wildcard: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The catch-all "
        f"defeats per-source routing and lets dependency-"
        f"confusion typo-squats flow through."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=cfg.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
