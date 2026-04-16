"""GL-014 — self-managed runners should carry an ephemeral tag."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

# GitLab SaaS shared runner tags — if a job uses ONLY these, it's
# not self-managed. Lowercase for comparison.
_SAAS_TAGS = frozenset({
    "saas-linux-small-amd64", "saas-linux-medium-amd64",
    "saas-linux-large-amd64", "saas-linux-xlarge-amd64",
    "saas-linux-2xlarge-amd64",
    "saas-macos-medium-m1",
    "saas-windows-medium-amd64",
    "gitlab-org", "gitlab-org-docker",
})


RULE = Rule(
    id="GL-014",
    title="Self-managed runner without ephemeral tag",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"),
    recommendation=(
        "Register the runner with `--executor docker` + "
        "`--docker-pull-policy always` so containers are fresh per "
        "job, and add an `ephemeral` tag. Alternatively use the "
        "GitLab Runner Operator with autoscaling."
    ),
    docs_note=(
        "Self-managed runners that don't tear down between jobs leak "
        "filesystem and process state. The check looks for an "
        "`ephemeral` tag on any job whose `tags:` list doesn't match "
        "SaaS-only runner names."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offending: list[str] = []
    for name, job in iter_jobs(doc):
        tags = job.get("tags")
        if not isinstance(tags, list) or not tags:
            continue
        tag_set = {str(t).lower() for t in tags}
        # Skip if all tags are known SaaS runner tags.
        if tag_set <= _SAAS_TAGS:
            continue
        if "ephemeral" not in tag_set:
            offending.append(name)
    passed = not offending
    desc = (
        "No self-managed job runs without an ephemeral tag."
        if passed else
        f"{len(offending)} job(s) use self-managed runner tags without "
        f"an `ephemeral` marker: {', '.join(offending)}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
