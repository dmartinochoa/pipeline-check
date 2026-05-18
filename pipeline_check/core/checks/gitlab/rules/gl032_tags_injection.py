"""GL-032, job ``tags:`` interpolates an attacker-controllable variable."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from ._helpers import UNTRUSTED_VAR_RE

RULE = Rule(
    id="GL-032",
    title="tags: interpolates untrusted CI variable",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"),
    cwe=("CWE-345",),
    recommendation=(
        "Hard-code ``tags:`` to a specific runner tag list. If runner "
        "selection has to be parameterised, validate the candidate "
        "value against an explicit allowlist in a job ``rules:`` "
        "block before the job runs, and never accept a "
        "``$CI_COMMIT_*`` / ``$CI_MERGE_REQUEST_*`` field as a tag "
        "value directly."
    ),
    docs_note=(
        "GL-014 catches self-managed runners that aren't ephemeral; "
        "this rule catches the upstream targeting choice. When "
        "``tags:`` is computed from an attacker-controllable CI "
        "variable, the operator (or anyone who can craft a PR title / "
        "branch name / commit message that the workflow consumes) "
        "picks where the job runs, including any privileged tag the "
        "instance exposes (``deploy-prod``, ``signer``, ``hsm`` …). "
        "The rule reuses the same untrusted-context catalog as GL-002 "
        "(``CI_COMMIT_MESSAGE``, ``CI_COMMIT_REF_NAME``, "
        "``CI_MERGE_REQUEST_TITLE`` and friends) so the two rules "
        "stay in lockstep."
    ),
    known_fp=(
        "Workflows that intentionally select runners by environment "
        "via a vetted ``variables:`` block (``RUNNER_TAG: deploy-"
        "prod``) referencing a build-time-set value are out of "
        "scope, the rule only matches the curated untrusted-"
        "predefined-variable catalog. Static custom variables "
        "(``$DEPLOY_FLEET`` defined inside the workflow file) are "
        "intentionally not flagged.",
    ),
)


def _tags_strings(tags: Any) -> list[str]:
    """Return every string value contributing to *tags*.

    GitLab accepts ``tags:`` as either a list of strings or, in
    rare cases, a single string scalar. Non-string entries are
    skipped, the YAML loader already accepted them, so the
    surface for injection is what matters here, not the schema.
    """
    out: list[str] = []
    if isinstance(tags, str):
        out.append(tags)
    elif isinstance(tags, list):
        for item in tags:
            if isinstance(item, str):
                out.append(item)
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for name, job in iter_jobs(doc):
        for value in _tags_strings(job.get("tags")):
            if UNTRUSTED_VAR_RE.search(value):
                offenders.append(name)
                break
    passed = not offenders
    desc = (
        "No job's ``tags:`` interpolates attacker-controllable variables."
        if passed else
        f"{len(offenders)} job(s) compute ``tags:`` from "
        f"attacker-controllable CI variables: "
        f"{', '.join(sorted(set(offenders))[:5])}"
        f"{'…' if len(set(offenders)) > 5 else ''}. "
        f"A pipeline trigger (or anyone whose PR title / branch name "
        f"the workflow consumes) can route the job onto any runner "
        f"tag the instance exposes, including privileged self-"
        f"managed tags."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        # AC-014 intersects these with GL-020's persistence anchors.
        job_anchors=tuple(dict.fromkeys(offenders)),
    )
