"""NPM-016, direct dependency's upstream repo scores poorly on OpenSSF Scorecard."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmContext, NpmManifest, iter_manifest_dependencies

#: Aggregate Scorecard score below which a dependency is surfaced.
#: OpenSSF treats < 5 as "needs improvement"; >= 7.5 as good.
_SCORE_FLOOR = 5.0

RULE = Rule(
    id="NPM-016",
    title="Direct dependency has a low OpenSSF Scorecard",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "A low OpenSSF Scorecard (or a failed Dangerous-Workflow check) "
        "on a direct dependency's own repository is a weak-link signal: "
        "the project lacks the maintenance and CI-hardening practices "
        "(branch protection, pinned actions, no `pull_request_target` "
        "script injection, code review) that make a compromise less "
        "likely and more detectable. Weigh a better-scored alternative "
        "where one exists, pin to a reviewed version, and for the ones "
        "you keep, watch them more closely (cooldown, provenance). This "
        "is an upstream-posture signal, not a defect you can fix in your "
        "own repo."
    ),
    docs_note=(
        "Network-dependent: needs ``--resolve-remote``. The dependency's "
        "GitHub repo comes from its packument (the same fetch NPM-008 / "
        "NPM-014 / NPM-015 use), then each repo is looked up against the "
        "OpenSSF Scorecard API (``api.securityscorecards.dev``), which "
        "is the one extra network surface this rule adds beyond the "
        "registry. Fires when the aggregate score is below "
        f"{_SCORE_FLOOR:g}/10 OR the Dangerous-Workflow check failed "
        "(an exploitable workflow pattern in the dependency's own repo). "
        "Scoped to direct dependencies with a resolvable GitHub repo; "
        "packages with no GitHub repo or not indexed by Scorecard are "
        "skipped. LOW severity by design: it's an advisory upstream "
        "posture signal that stays below the default ``--fail-on`` gate. "
        "Passes silently when ``--resolve-remote`` is off or the "
        "Scorecard API can't be reached."
    ),
    known_fp=(
        "Scorecard penalizes practices that don't always apply (e.g. a "
        "single-maintainer library that doesn't use code review by "
        "policy) and its data can lag a repo's current state. A low "
        "score is a prompt to look, not proof of risk. Suppress "
        "per-resource for dependencies the team has vetted directly.",
    ),
    incident_refs=(
        "OpenSSF Scorecard: an automated assessment of a repo's "
        "security practices (branch protection, pinned dependencies, "
        "dangerous workflows, code review, maintenance). Low-scoring "
        "upstreams are over-represented in supply-chain incident "
        "post-mortems.",
    ),
    exploit_example=(
        "// Risk: ``sketchy-lib`` is a direct dependency whose own\n"
        "// GitHub repo scores 3.1/10 on OpenSSF Scorecard and fails\n"
        "// the Dangerous-Workflow check, meaning its CI has an\n"
        "// exploitable ``pull_request_target`` pattern. A fork PR\n"
        "// could compromise its release pipeline and ship a malicious\n"
        "// version to you on the next bump.\n"
        "// package.json\n"
        "{\n"
        "  \"dependencies\": {\n"
        "    \"sketchy-lib\": \"^1.0.0\"\n"
        "  }\n"
        "}\n"
        "\n"
        "// Surface it: ``pipeline_check --pipeline npm\n"
        "// --resolve-remote`` resolves each direct dependency's GitHub\n"
        "// repo and queries the OpenSSF Scorecard API, flagging the\n"
        "// low-scoring and dangerous-workflow upstreams so you can\n"
        "// weigh a better-maintained alternative.\n"
    ),
)


def check(manifest: NpmManifest, ctx: NpmContext | None = None) -> Finding:
    scorecards = ctx.scorecards if ctx is not None else {}
    if not scorecards:
        # No metadata — silent pass. ``--resolve-remote`` is the opt-in
        # network path; its absence must not fail CI on the default
        # offline scan.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "No Scorecard metadata available (re-run with "
                "``--resolve-remote`` to enable Scorecard analysis)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    offenders: list[str] = []
    locations: list[Location] = []
    seen: set[str] = set()
    for section, name, _spec in iter_manifest_dependencies(manifest):
        if name in seen:
            continue  # same dep in two sections — report once
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
        offenders.append(f"{section}.{name} ({reason})")
        idx = manifest.text.find(f'"{name}"')
        line_no = manifest.text[:idx].count("\n") + 1 if idx >= 0 else 1
        locations.append(Location(
            path=manifest.path, start_line=line_no, end_line=line_no,
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
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
