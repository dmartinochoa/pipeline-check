"""RUN-006. A known-compromised action actually executed in run history.

Where GHA-040 flags a known-compromised action *reference* in the current
workflow file, this is the runtime confirmation: the action's
``Download action repository`` line is present in a run's logs, so the
compromised code provably ran. It catches two things the static scan
cannot:

  * **Tag-repoint.** The workflow pins ``@v44`` (a tag the static scan
    treats as just unpinned), but the run log shows ``v44`` resolved to
    the registry's malicious commit SHA. The tj-actions/changed-files
    (CVE-2025-30066) and the 2026 Trivy / Checkmarx campaigns all
    force-moved tags this way, and the incident was visible in run
    history first.
  * **A since-reverted workflow.** The workflow was fixed (the bad ref
    removed) after the fact, so GHA-040 is now clean, yet the run history
    still records that the compromised action executed with the repo's
    secrets and ``GITHUB_TOKEN`` in scope.

Only meaningful under ``--audit-runs-logs``: the match is read from the
same privileged-trigger run logs RUN-003 / RUN-004 already download, so it
adds no fetches. That scopes it to the highest-impact subset (a
``pull_request_target`` / ``workflow_run`` run, where repo secrets and a
write-scoped token are in scope); detection is exact on the IOC registry
but recall is bounded to the runs whose logs were fetched.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import RunsContext, repo_resource, run_resource

RULE = Rule(
    id="RUN-006",
    title="Known-compromised action executed in run history",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-3", "CICD-SEC-4"),
    cwe=("CWE-506", "CWE-829"),
    recommendation=(
        "Treat this as a confirmed supply-chain compromise that ran in "
        "your CI: rotate every secret and token that was in scope for the "
        "affected run(s), review what the run accessed or pushed, and pin "
        "the action to a known-good commit SHA (never a tag, which the "
        "attacker can force-move). Cross-check the cited advisory for the "
        "clean post-incident version. If the workflow still references the "
        "compromised action, fix it now (GHA-040)."
    ),
    docs_note=(
        "Only evaluated with ``--audit-runs-logs``. Scans the "
        "privileged-trigger run logs RUN-003 / RUN-004 already download for "
        "GitHub's ``Download action repository 'owner/repo@ref' (SHA:...)`` "
        "lines and matches both the pinned ref and the resolved commit SHA "
        "against the curated GHA-040 known-compromised-action registry "
        "(tj-actions/changed-files, reviewdog/action-setup, the 2026 "
        "aquasecurity / checkmarx campaigns). Matching the resolved SHA is "
        "what catches a tag-repoint: a workflow pinned to ``@v44`` whose "
        "tag was force-moved to a malicious commit. Scoped to the fetched "
        "privileged-trigger run logs (repo secrets + write token in scope), "
        "so recall is bounded to those runs; the IOC match itself is exact."
    ),
)


def check(ctx: RunsContext) -> list[Finding]:
    if not ctx.logs_scanned:
        # Metadata-only run; don't imply the logs were checked.
        return [Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=repo_resource(ctx),
            description=(
                "Run-log scanning was not enabled; pass --audit-runs-logs "
                "to download and scan privileged-trigger run logs for a "
                "known-compromised action that actually executed."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    if not ctx.compromised_action_runs:
        return [Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=repo_resource(ctx),
            description=(
                "No known-compromised action was found executing in the "
                "scanned run logs."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    by_id = {r.run_id: r for r in ctx.runs}
    findings: list[Finding] = []
    for run_id, hits in sorted(ctx.compromised_action_runs.items()):
        run = by_id.get(run_id)
        url = f" {run.html_url}" if run and run.html_url else ""
        labels = ", ".join(sorted(hits))
        # One advisory carries the citation; if several actions hit, name
        # the first (all are in the same incident family in practice).
        advisory = next(iter(hits[label] for label in sorted(hits)), "")
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=run_resource(ctx, run) if run else repo_resource(ctx),
            description=(
                f"Run #{run_id} ("
                + (f"{run.name or 'workflow'} on `{run.event}`, " if run else "")
                + f"executed a known-compromised action: {labels}. The "
                f"compromised code ran with the run's secrets and token in "
                f"scope. {advisory}{url}".rstrip()
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
