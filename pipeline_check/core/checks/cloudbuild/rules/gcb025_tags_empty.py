"""GCB-025. Build has no top-level ``tags:`` for audit / discoverability."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GCB-025",
    title="Build has no tags for audit / discoverability",
    severity=Severity.LOW,
    owasp=("CICD-SEC-10",),
    esf=("ESF-D-BUILD-LOGS",),
    cwe=("CWE-778",),
    recommendation=(
        "Add a top-level ``tags:`` array to every ``cloudbuild.yaml``"
        ", at minimum, an environment tag (``prod`` / ``staging`` / "
        "``dev``) and a service tag (``backend`` / ``frontend`` / "
        "``infra``). Cloud Build records tags in the build metadata "
        "and Cloud Logging entries so post-incident triage of "
        "``which build emitted this`` becomes a single "
        "``gcloud builds list --filter='tags:prod'`` query. "
        "Without tags, builds discoverable only by build-id; the "
        "id is a UUID with no signal."
    ),
    docs_note=(
        "Cloud Build tags are user-defined labels attached to a "
        "build. They appear in the build's metadata (``tags:`` "
        "field on the Build resource), in every Cloud Logging "
        "audit event for the build, and as a filter argument to "
        "``gcloud builds list --filter='tags:<value>'``. "
        "Substitution-bearing tags (``$BRANCH_NAME``, "
        "``$COMMIT_SHA``) count as populated. Cloud Build "
        "expands them at submission time."
    ),
    known_fp=(
        "Single-purpose project-local builds in a sandbox project "
        "may legitimately not need tags. Suppress with "
        "``--ignore-file`` if that matches.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    raw_tags = doc.get("tags")
    tag_list: list[str] = (
        [x for x in raw_tags if isinstance(x, str) and x.strip()]
        if isinstance(raw_tags, list) else []
    )
    if tag_list:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                f"Build declares {len(tag_list)} tag(s) for audit / "
                "discoverability."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=(
            "Build has no ``tags:`` array (or it's empty). Tags "
            "drive Cloud Logging filtering and incident-triage "
            "discovery; without them the build is anchored only "
            "by its UUID build-id."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
