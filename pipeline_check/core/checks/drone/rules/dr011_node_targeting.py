"""DR-011. ``node:`` map interpolates an attacker-controllable Drone variable."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Pipeline

RULE = Rule(
    id="DR-011",
    title="node map interpolates attacker-controllable Drone variable",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7", "CICD-SEC-1"),
    esf=("ESF-D-CODE-INTEGRITY", "ESF-S-RUNNER-ISOLATION"),
    cwe=("CWE-78", "CWE-1357"),
    recommendation=(
        "Pin every ``node:`` map entry to a static literal that "
        "matches your runner-targeting policy. Drone uses ``node:`` "
        "to route a pipeline to runners with matching labels (e.g. "
        "``node: { instance: ci-prod-amd64 }``). When the map "
        "value interpolates ``${DRONE_BRANCH}`` / "
        "``${DRONE_PULL_REQUEST_*}`` / ``${DRONE_COMMIT_AUTHOR}``, "
        "the pusher gets to pick which runner pool runs the "
        "pipeline, including a privileged pool reserved for the "
        "deploy step. Production runner pools should also carry a "
        "label the agent itself enforces (the runner's "
        "``DRONE_RUNNER_LABELS`` env var, plus a server-side "
        "policy on which repos can target which labels) so the "
        "rule is one layer of defense-in-depth."
    ),
    docs_note=(
        "Drone substitutes ``${VAR}`` template tokens against the "
        "build context before the runner picks an agent. The "
        "rule walks the pipeline-level ``node:`` map (Drone "
        "doesn't expose a per-step variant) for any reference to "
        "the same author-controllable variables DR-003 tracks "
        "(``DRONE_BRANCH``, ``DRONE_TAG``, "
        "``DRONE_PULL_REQUEST_*``, ``DRONE_COMMIT_AUTHOR*``, "
        "``DRONE_COMMIT_MESSAGE``, ``DRONE_REPO``).\n\n"
        "Detection is value-only and case-sensitive against the "
        "documented variable names; trusted server-controlled "
        "fields like ``DRONE_BUILD_NUMBER`` and "
        "``DRONE_REPO_NAMESPACE`` (for non-fork repos) aren't on "
        "the tainted list. Closes parity with BK-015 / GHA-036 / "
        "GL-032 / JF-032 / ADO-030 / CC-031."
    ),
    known_fp=(
        "Some teams use a static prefix plus a CI-controlled "
        "tail (``node: { pool: build-${DRONE_REPO_NAME} }``) to "
        "share a runner pool across repos. ``DRONE_REPO_NAME`` "
        "is set by the server, not the pusher, so it isn't on "
        "the tainted list, but if your team has its own "
        "conventions for trusted Drone vars, suppress on the "
        "specific pipeline name.",
    ),
    exploit_example=(
        "# Vulnerable: ``node.queue: ${DRONE_BRANCH}`` lets a PR\n"
        "# author route their build to any runner pool by naming\n"
        "# their branch after it. A branch named ``production``\n"
        "# routes the PR build to the production-only runner with\n"
        "# elevated permissions, which were never meant to be\n"
        "# reachable from a PR.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "node:\n"
        "  queue: ${DRONE_BRANCH}\n"
        "steps:\n"
        "  - name: deploy\n"
        "    image: deploy-cli@sha256:abc123...\n"
        "    commands:\n"
        "      - ./deploy.sh\n"
        "\n"
        "# Safe: pin the runner label to a static literal that\n"
        "# matches your targeting policy. Production runners\n"
        "# should ALSO enforce the label server-side (Drone\n"
        "# agent's ``--labels`` flag) so the rule is one layer\n"
        "# of defense-in-depth.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "node:\n"
        "  queue: production\n"
        "steps:\n"
        "  - name: deploy\n"
        "    image: deploy-cli@sha256:abc123...\n"
        "    commands:\n"
        "      - ./deploy.sh"
    ),
)


# Same tainted set DR-003 uses for command-body interpolation,
# intentionally narrower than the full DR_*_AUTHOR / DR_*_BRANCH
# fan-out so the rule stays low-noise on tag-only releases that
# legitimately route to a tag-flavored runner pool.
_TAINTED_VARS = (
    "DRONE_BRANCH",
    "DRONE_TAG",
    "DRONE_SOURCE_BRANCH",
    "DRONE_TARGET_BRANCH",
    "DRONE_PULL_REQUEST",
    "DRONE_PULL_REQUEST_TITLE",
    "DRONE_PULL_REQUEST_BRANCH",
    "DRONE_COMMIT_AUTHOR",
    "DRONE_COMMIT_AUTHOR_NAME",
    "DRONE_COMMIT_AUTHOR_EMAIL",
    "DRONE_COMMIT_MESSAGE",
    "DRONE_TAG_MESSAGE",
    "DRONE_REPO",
)

_INTERP_RE = re.compile(
    r"\$\{?(" + "|".join(_TAINTED_VARS) + r")\}?(?![A-Za-z0-9_])"
)


def _scan_value(value: Any) -> list[str]:
    """Return tainted variable names interpolated in *value*."""
    hits: list[str] = []
    if isinstance(value, str):
        hits.extend(m.group(1) for m in _INTERP_RE.finditer(value))
    elif isinstance(value, dict):
        for v in value.values():
            hits.extend(_scan_value(v))
    elif isinstance(value, list):
        for item in value:
            hits.extend(_scan_value(item))
    return hits


def check(pipeline: Pipeline) -> Finding:
    node = pipeline.data.get("node")
    if node is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path,
            description=(
                "Pipeline declares no ``node:`` map, runner "
                "targeting is left to the server / runner default."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    hits = sorted(set(_scan_value(node)))
    passed = not hits
    desc = (
        "Pipeline ``node:`` map uses static literals only."
        if passed else
        f"Pipeline ``node:`` map interpolates "
        f"{len(hits)} attacker-controllable Drone variable(s): "
        f"{', '.join(hits[:5])}"
        f"{'...' if len(hits) > 5 else ''}. The pusher controls "
        f"which runner pool the pipeline lands on."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
