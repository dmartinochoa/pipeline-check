"""NUGET-001, PackageReference uses a floating NuGet version range."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import NuGetProject

RULE = Rule(
    id="NUGET-001",
    title="Floating NuGet version range",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Replace NuGet floating version ranges (``[1.0,)``, "
        "``(,2.0)``, ``[1.0,2.0)``, ``*``) with an exact version "
        "pin (``<PackageReference Include=\"Newtonsoft.Json\" "
        "Version=\"13.0.3\" />``). Floating ranges let NuGet resolve "
        "any later version that fits the interval, so a compromised "
        "patch release reaches the build on the next restore without "
        "a project file change. Pair the pinned reference with a "
        "committed ``packages.lock.json`` (NUGET-006) for "
        "reproducible restores."
    ),
    docs_note=(
        "Fires when a ``<PackageReference>`` Version attribute "
        "contains a NuGet range interval (``[1.0,2.0)``, "
        "``(,2.0]``, etc.) or a bare ``*`` wildcard."
    ),
)

# NuGet range grammar: bracket/paren-delimited intervals containing a
# comma (``[1.0,2.0)``, ``(,2.0]``, ``[1.0,)``), or a bare ``*``
# wildcard that resolves to the latest stable release.
_FLOAT_RE = re.compile(r"[\[\(].*,.*[\]\)]|\*")


def check(project: NuGetProject) -> Finding:
    offenders: list[str] = []
    for ref in project.package_refs:
        if ref.version is None:
            continue
        if _FLOAT_RE.search(ref.version):
            offenders.append(f"{ref.name}: {ref.version}")
    passed = not offenders
    desc = (
        "Every PackageReference is pinned to an exact version."
        if passed else
        f"{len(offenders)} PackageReference(s) use a floating "
        f"version range: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A compromised patch "
        f"release reaches the build on the next restore without a "
        f"project file change."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=project.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
