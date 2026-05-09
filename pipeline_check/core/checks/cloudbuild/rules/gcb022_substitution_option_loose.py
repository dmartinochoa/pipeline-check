"""GCB-022, ``options.substitutionOption: ALLOW_LOOSE`` masks undefined refs."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GCB-022",
    title="options.substitutionOption set to ALLOW_LOOSE",
    severity=Severity.LOW,
    owasp=("CICD-SEC-4",),
    esf=("ESF-S-INPUT-VAL",),
    cwe=("CWE-1188",),
    recommendation=(
        "Drop ``options.substitutionOption`` (the default is "
        "``MUST_MATCH``) or set it explicitly to ``MUST_MATCH``. "
        "``ALLOW_LOOSE`` makes Cloud Build expand undefined "
        "substitutions to the empty string instead of failing the "
        "build. That paper-overs typos (``$_REGON`` instead of "
        "``$_REGION``), masks unset variables that should have "
        "tripped review, and combined with ``dynamicSubstitutions: "
        "true`` (GCB-004) it widens the command-injection surface "
        "by letting attacker-controlled substitution tokens collapse "
        "to empty strings inside shell commands."
    ),
    docs_note=(
        "Cloud Build accepts two values for "
        "``options.substitutionOption``: ``MUST_MATCH`` (default, "
        "any undefined ``$_VAR`` reference fails the build at parse "
        "time) and ``ALLOW_LOOSE`` (undefined references silently "
        "expand to ``\"\"``). The default is the safer setting; this "
        "rule only fires on the explicit ``ALLOW_LOOSE`` opt-in. "
        "Builds that genuinely depend on optional substitutions "
        "should pass them through ``substitutions:`` defaults, not "
        "rely on silent empty-string fallback."
    ),
    known_fp=(
        "Migration scenarios where a long-running pipeline pre-dates "
        "MUST_MATCH and the operator needs ALLOW_LOOSE temporarily. "
        "Suppress with a brief ``.pipelinecheckignore`` rationale "
        "and an ``expires:`` date so the waiver doesn't outlive the "
        "migration.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    options = doc.get("options")
    if not isinstance(options, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No ``options:`` block, substitutionOption defaults to MUST_MATCH.",
            recommendation=RULE.recommendation, passed=True,
        )
    raw = options.get("substitutionOption")
    if not isinstance(raw, str):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="``options.substitutionOption`` is unset, defaults to MUST_MATCH.",
            recommendation=RULE.recommendation, passed=True,
        )
    if raw.strip().upper() == "ALLOW_LOOSE":
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                f"``options.substitutionOption: {raw}`` lets undefined "
                "``$_VAR`` references expand to the empty string. "
                "Drop the option or set it to ``MUST_MATCH``."
            ),
            recommendation=RULE.recommendation, passed=False,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=f"``options.substitutionOption: {raw}`` is the strict default.",
        recommendation=RULE.recommendation, passed=True,
    )
