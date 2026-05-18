"""GHA-001. Actions must be pinned to a 40-char commit SHA."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location
from ..uses_parser import parse_uses

RULE = Rule(
    id="GHA-001",
    title="Action not pinned to commit SHA",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Replace tag/branch references (`@v4`, `@main`) with the full "
        "40-char commit SHA. Use Dependabot or StepSecurity to keep the "
        "pins fresh."
    ),
    docs_note=(
        "Every `uses:` reference should pin a specific 40-char commit "
        "SHA. Tag and branch refs (`@v4`, `@main`) can be silently "
        "moved to malicious commits by whoever controls the upstream "
        "repository, a third-party action compromise will propagate "
        "into the pipeline on the next run."
    ),
    incident_refs=(
        "tj-actions/changed-files compromise "
        "([CVE-2025-30066](https://www.cve.org/CVERecord?id=CVE-2025-30066), "
        "March 2025): a malicious commit retagged behind ``@v1`` / "
        "``@v45`` shipped CI-secret exfiltration to roughly 23,000 "
        "repos that had pinned the action to a mutable tag instead "
        "of a commit SHA.",
        "reviewdog/action-setup compromise "
        "([CVE-2025-30154](https://www.cve.org/CVERecord?id=CVE-2025-30154), "
        "March 2025): same week, similar mechanism. Tag-pinned "
        "consumers auto-pulled the malicious version; SHA-pinned "
        "consumers were unaffected.",
    ),
    exploit_example=(
        "# Tag-pinned reference (vulnerable):\n"
        "- uses: tj-actions/changed-files@v45\n"
        "\n"
        "# Attack: the upstream maintainer (or anyone who compromises\n"
        "# the upstream repo) force-moves the v45 tag to a malicious\n"
        "# commit:\n"
        "#   git tag -f v45 <attacker-controlled-sha>\n"
        "#   git push --force origin v45\n"
        "# Every consumer's next workflow run pulls the new code\n"
        "# automatically, executing the attacker's payload with the\n"
        "# job's secrets and GITHUB_TOKEN in scope.\n"
        "\n"
        "# Safe: pin to a 40-char commit SHA (immutable):\n"
        "- uses: tj-actions/changed-files@a284dc1814e3fdd1a3a7f16c11f02e2cd5a98f93  # v45.0.0"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    unpinned: list[str] = []
    locations: list[Location] = []
    # Preserve insertion order without duplicates so the reachability-
    # aware AC-018 chain sees every job that contains an unpinned step.
    anchor_jobs: dict[str, None] = {}
    for job_id, job in iter_jobs(doc):
        for step in iter_steps(job):
            ref = parse_uses(step.get("uses"))
            if ref is None or ref.kind != "remote-action":
                continue
            if not ref.is_pinned_to_sha:
                unpinned.append(ref.raw)
                locations.append(step_location(path, step))
                anchor_jobs[job_id] = None
    passed = not unpinned
    desc = (
        "Every `uses:` reference is pinned to a 40-char commit SHA."
        if passed else
        f"{len(unpinned)} action reference(s) are pinned to a tag or "
        f"branch rather than a commit SHA: "
        f"{', '.join(sorted(set(unpinned))[:5])}"
        f"{'…' if len(set(unpinned)) > 5 else ''}. "
        f"Tags and branches can be moved to malicious commits by "
        f"whoever controls the upstream repository."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        job_anchors=tuple(anchor_jobs),
    )
