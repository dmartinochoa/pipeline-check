"""PYPI-020, direct dependency's upstream repo scores poorly on OpenSSF Scorecard."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PypiContext, RequirementsFile, iter_specs, requirement_package_name

#: Aggregate Scorecard score below which a dependency is surfaced.
#: OpenSSF treats < 5 as "needs improvement"; >= 7.5 as good.
_SCORE_FLOOR = 5.0

RULE = Rule(
    id="PYPI-020",
    title="Direct dependency has a low OpenSSF Scorecard",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "A low OpenSSF Scorecard (or a failed Dangerous-Workflow "
        "check) on a direct dependency's own repository is a "
        "weak-link signal: the project lacks the maintenance and "
        "CI-hardening practices (branch protection, pinned actions, "
        "no ``pull_request_target`` script injection, code review) "
        "that make a compromise less likely and more detectable. "
        "Weigh a better-scored alternative where one exists, pin to a "
        "reviewed version, and for the ones you keep, watch them more "
        "closely (cooldown, provenance). This is an upstream-posture "
        "signal, not a defect you can fix in your own repo. The npm "
        "analog is NPM-016."
    ),
    docs_note=(
        "Network-dependent: needs ``--resolve-remote``. The "
        "dependency's GitHub repo is resolved from its PyPI metadata "
        "(``info.project_urls`` / ``home_page``, the same per-package "
        "JSON document the cooldown / provenance passes read), then "
        "each repo is looked up against the OpenSSF Scorecard API "
        "(``api.securityscorecards.dev``), which is the one extra "
        "network surface this rule adds. Flags a dependency whose "
        "upstream repo scores below 5/10 or fails the "
        "Dangerous-Workflow check.\n\n"
        "Scoped to direct, index-resolved dependencies. A package "
        "with no GitHub repo in its PyPI metadata, or one the "
        "Scorecard project hasn't indexed, is skipped. LOW severity, "
        "an informational upstream-posture signal below the default "
        "``--fail-on`` gate; passes silently when ``--resolve-remote`` "
        "is off or the APIs can't be reached."
    ),
    known_fp=(
        "Scorecard scores a repo's *practices*, not whether a given "
        "release is malicious; a low score is a prior, not a verdict. "
        "Small but well-run projects can score low on checks that "
        "assume a larger team (code-review, CII-best-practices). "
        "Treat it as a prompt to look closer, and suppress per-"
        "resource for dependencies the team has vetted.",
    ),
    incident_refs=(
        "OpenSSF Scorecard (securityscorecards.dev): the "
        "Dangerous-Workflow check specifically detects the "
        "``pull_request_target`` + untrusted-checkout script-injection "
        "pattern behind multiple real CI compromises, so a failing "
        "score on a dependency's repo is a concrete, not abstract, "
        "weak-link signal.",
    ),
    exploit_example=(
        "# Risk: ``sketchy-helper``'s upstream GitHub repo scores 2/10\n"
        "# on OpenSSF Scorecard and fails the Dangerous-Workflow check\n"
        "# (an exploitable pull_request_target pattern in its own CI).\n"
        "# A repo that can't keep its own pipeline safe is a weaker\n"
        "# link in yours.\n"
        "# requirements.txt\n"
        "sketchy-helper==1.4.0\n"
        "\n"
        "# Surface it: ``pipeline_check --pipeline pypi\n"
        "# --resolve-remote`` resolves each direct dependency's GitHub\n"
        "# repo from its PyPI metadata and queries the OpenSSF\n"
        "# Scorecard API, flagging the low-scoring and\n"
        "# dangerous-workflow upstreams so you can weigh a\n"
        "# better-maintained alternative.\n"
    ),
)


def check(rf: RequirementsFile, ctx: PypiContext | None = None) -> Finding:
    scorecards = ctx.scorecards if ctx is not None else {}
    if not scorecards:
        # No metadata; silent pass. ``--resolve-remote`` is the opt-in
        # network path; its absence must not fail CI on the default
        # offline scan.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=rf.path,
            description=(
                "No Scorecard metadata available (re-run with "
                "``--resolve-remote`` to enable Scorecard analysis)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    seen: set[str] = set()
    for line in iter_specs(rf):
        name = requirement_package_name(line.body)
        if name is None or name in seen:
            continue
        seen.add(name)
        result = scorecards.get(name)
        if result is None:
            continue  # no GitHub repo / not indexed by Scorecard
        low_score = result.score < _SCORE_FLOOR
        if not low_score and not result.dangerous_workflow_failed:
            continue
        reason = (
            "dangerous-workflow"
            if result.dangerous_workflow_failed and not low_score
            else f"score {result.score:g}/10"
            if not result.dangerous_workflow_failed
            else f"score {result.score:g}/10, dangerous-workflow"
        )
        offenders.append(f"{name} ({reason})")
        locations.append(Location(
            path=rf.path, start_line=line.line_no, end_line=line.line_no,
        ))
    passed = not offenders
    desc = (
        "No direct dependency has a low OpenSSF Scorecard."
        if passed else
        f"{len(offenders)} direct dependency / dependencies have a weak "
        f"upstream OpenSSF Scorecard: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A low-scoring or "
        f"dangerous-workflow upstream is a weaker link in your supply "
        f"chain."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
