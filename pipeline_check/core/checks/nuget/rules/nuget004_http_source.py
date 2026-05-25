"""NUGET-004, NuGet.config declares an HTTP-only package source."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import NuGetConfig

RULE = Rule(
    id="NUGET-004",
    title="HTTP-only NuGet package source",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-319", "CWE-494"),
    recommendation=(
        "Change every ``<add key=\"...\" value=\"http://...\" />`` "
        "package source in NuGet.config to ``https://``. "
        "Plaintext-HTTP sources let a network attacker swap "
        "downloaded packages in flight (the canonical supply-chain "
        "MITM). If your internal feed has a self-signed certificate, "
        "install the CA into the build agent's trust store instead "
        "of falling back to HTTP."
    ),
    docs_note=(
        "Fires when a ``<packageSources>`` entry in NuGet.config "
        "uses an ``http://`` URL."
    ),
)


def check(config: NuGetConfig) -> Finding:
    offenders: list[str] = []
    for source in config.sources:
        if source.url.lower().startswith("http://"):
            offenders.append(f"{source.name}: {source.url}")
    passed = not offenders
    desc = (
        "Every package source in NuGet.config uses HTTPS."
        if passed else
        f"{len(offenders)} package source(s) use plaintext HTTP: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A network attacker "
        f"can swap downloaded packages in flight."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=config.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
