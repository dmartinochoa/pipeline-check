"""GL-011 — MR-triggered pipelines must not use `include: local:`."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ._helpers import pipeline_runs_on_mr


RULE = Rule(
    id="GL-011",
    title="include: local file pulled in MR-triggered pipeline",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-PIN-DEPS"),
    recommendation=(
        "Move the included template into a separate, read-only "
        "project and reference it via `include: project: ... ref: "
        "<sha-or-tag>`. That way the included content is fixed at "
        "MR creation time and not editable from the MR branch."
    ),
    docs_note=(
        "`include: local: '<path>'` resolves from the current "
        "pipeline's checked-out tree. On an MR pipeline the tree is "
        "the MR source branch — the MR author controls the included "
        "YAML content."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    if not pipeline_runs_on_mr(doc, None):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Pipeline does not run on merge_request events.",
            recommendation="No action required.", passed=True,
        )
    includes = doc.get("include")
    if includes is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Pipeline has no `include:` directive.",
            recommendation="No action required.", passed=True,
        )
    items = includes if isinstance(includes, list) else [includes]
    local_includes: list[str] = []
    for entry in items:
        if isinstance(entry, str) and not entry.startswith(("http://", "https://")):
            local_includes.append(entry)
        elif isinstance(entry, dict) and entry.get("local"):
            local_includes.append(str(entry["local"]))
    passed = not local_includes
    desc = (
        "MR-triggered pipeline does not use `include: local:` for any file."
        if passed else
        f"Pipeline runs on `merge_request_event` AND pulls "
        f"{len(local_includes)} `include: local:` file(s) from the "
        f"checked-out tree: {', '.join(local_includes[:5])}"
        f"{'…' if len(local_includes) > 5 else ''}. The MR author "
        f"can edit those files; arbitrary CI configuration runs "
        f"against the MR with the project's CI credentials in scope."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
