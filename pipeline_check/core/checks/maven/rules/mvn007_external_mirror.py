"""MVN-007, settings.xml mirror routes external traffic through one repo."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PomFile

RULE = Rule(
    id="MVN-007",
    title="settings.xml mirror routes external traffic through one repo",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-8", "CICD-SEC-3"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Replace ``<mirrorOf>*</mirrorOf>`` and "
        "``<mirrorOf>external:*</mirrorOf>`` with a narrowly-scoped "
        "list naming the upstream repositories you actually want to "
        "redirect (``central``, ``central,jcenter``). A wildcard "
        "mirror routes every dependency, including ones declared by "
        "transitive POMs the build hasn't approved, through the "
        "mirror operator: a single compromise of that mirror "
        "compromises every artifact the build resolves. Pin the "
        "mirror URL to ``https://`` and audit the mirror operator's "
        "publishing controls."
    ),
    docs_note=(
        "Fires on any ``<mirror>`` in a ``settings.xml`` whose "
        "``<mirrorOf>`` value is ``*`` or ``external:*`` (the two "
        "patterns that capture arbitrary external traffic). "
        "Repository-specific patterns (``central``, "
        "``!internal-only,*``) and explicit allowlists are exempt. "
        "Project POMs that don't carry a ``<mirrors>`` block "
        "silently pass."
    ),
    known_fp=(
        "Single-team artifact-proxy patterns (one Nexus / "
        "Artifactory acting as the universal upstream front) "
        "legitimately use ``<mirrorOf>*</mirrorOf>`` and rely on "
        "the proxy's own access controls. If the proxy is a "
        "controlled artifact-allowlist target rather than a "
        "passthrough, suppress with a rationale naming the proxy "
        "endpoint and the allowlist that gates it.",
    ),
)


_WILDCARD_PATTERNS: frozenset[str] = frozenset({"*", "external:*"})


def check(pom: PomFile) -> Finding:
    if not pom.is_settings:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="pom.xml has no <mirrors> block.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for mirror in pom.mirrors:
        pattern = mirror.mirror_of.strip()
        if pattern in _WILDCARD_PATTERNS:
            offenders.append(f"{mirror.id} -> {mirror.url} (mirrorOf={pattern})")
            locations.append(Location(
                path=pom.path, start_line=mirror.line_no, end_line=mirror.line_no,
            ))
    passed = not offenders
    desc = (
        "No mirror routes arbitrary external traffic."
        if passed else
        f"{len(offenders)} mirror(s) route arbitrary external "
        f"traffic: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A compromise of the "
        f"mirror operator compromises every artifact the build "
        f"resolves."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
