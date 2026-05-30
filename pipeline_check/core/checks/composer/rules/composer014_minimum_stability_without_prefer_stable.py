"""COMPOSER-014. ``minimum-stability`` lowered without ``prefer-stable``."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ComposerFile

RULE = Rule(
    id="COMPOSER-014",
    title="composer.json minimum-stability lowered without prefer-stable",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1104", "CWE-1357"),
    recommendation=(
        "Set ``\"prefer-stable\": true`` alongside a lowered "
        "``minimum-stability``, or raise ``minimum-stability`` "
        "back to ``stable``. With ``prefer-stable`` off, Composer "
        "is free to resolve every dependency to a "
        "dev / alpha / beta / RC release even when a stable "
        "version exists, pulling unreviewed code across the whole "
        "tree. ``prefer-stable: true`` keeps the wider floor "
        "(needed for a few genuine pre-release deps) while still "
        "preferring stable wherever it can.\n\n"
        "COMPOSER-005 flags the lowered floor on its own; this "
        "rule narrows to the higher-risk combination where "
        "nothing pulls resolution back toward stable."
    ),
    docs_note=(
        "Fires when top-level ``minimum-stability`` is one of "
        "``dev``, ``alpha``, ``beta``, or ``RC`` and top-level "
        "``prefer-stable`` is not ``true``. Reads both top-level "
        "keys. Where COMPOSER-005 fires on any lowered floor, "
        "COMPOSER-014 is the subset where ``prefer-stable`` does "
        "not soften it, so the two overlap by design (005 is the "
        "broad signal, 014 the sharper one)."
    ),
    known_fp=(
        "Projects that intentionally track dev dependencies may "
        "accept the lowered floor. Adding ``prefer-stable: true`` "
        "keeps the wider range while preferring stable where "
        "available, which clears this rule without giving up the "
        "pre-release access.",
    ),
    incident_refs=(),
    exploit_example=None,
)


_UNSTABLE: frozenset[str] = frozenset({"dev", "alpha", "beta", "rc"})


def check(pom: ComposerFile) -> Finding:
    stability = pom.minimum_stability.strip().lower()
    unstable = stability in _UNSTABLE
    has_prefer_stable = pom.prefer_stable is True
    if not unstable or has_prefer_stable:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "minimum-stability is at the stable floor, or "
                "prefer-stable is set to pull resolution back "
                "toward stable."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    locations: list[Location] = []
    idx = pom.text.find('"minimum-stability"')
    if idx >= 0:
        line = pom.text[:idx].count("\n") + 1
        locations.append(Location(
            path=pom.path, start_line=line, end_line=line,
        ))
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path,
        description=(
            f"minimum-stability is ``{pom.minimum_stability}`` and "
            f"prefer-stable is not set — Composer may resolve any "
            f"dependency to a pre-release even when a stable "
            f"version exists. Add ``prefer-stable: true`` or "
            f"restore the stable floor."
        ),
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
    )
