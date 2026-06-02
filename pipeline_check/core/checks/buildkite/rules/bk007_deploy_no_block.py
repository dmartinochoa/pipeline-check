"""BK-007. Deploy steps must be gated by a manual ``block:`` step."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import step_commands, step_label

RULE = Rule(
    id="BK-007",
    title="Deploy step not gated by a manual block / input",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2", "CICD-SEC-7"),
    esf=("ESF-D-CHANGE-MGMT",),
    cwe=("CWE-285",),
    recommendation=(
        "Insert a ``- block: \"Deploy?\"`` (or ``- input:`` step) in "
        "front of every deploy step. Buildkite waits for a human to "
        "click *Unblock* before the gated steps run, which prevents "
        "an unreviewed merge from auto-deploying to production. "
        "Combine with ``branches: main`` so the gate only appears on "
        "release branches."
    ),
    docs_note=(
        "A step is treated as a deploy when its label, key, or any "
        "command line contains a deploy keyword (``deploy``, ``ship-"
        "it``, ``release``, ``promote``, ``rollout``, ``terraform "
        "apply``, ``kubectl apply``, ``helm upgrade``, ``helm "
        "install``, ``aws ecs update-service``). The check passes "
        "when at least one "
        "preceding step in the same pipeline file is a ``block:`` or "
        "``input:`` flow-control step."
    ),
    known_fp=(
        "Pipelines where the deploy gate lives in a triggered "
        "pipeline rather than the local file, the local pipeline "
        "looks ungated even though the actual deploy is gated "
        "downstream. Add a no-op ``block:`` to silence.",
    ),
    exploit_example=(
        "# Vulnerable: a deploy step with no preceding manual block.\n"
        "steps:\n"
        "  - label: \":rocket: Deploy prod\"\n"
        "    command: \"aws s3 sync ./dist s3://prod-site\"\n"
        "\n"
        "# Attack: there's no `block:` ahead of the deploy, so every\n"
        "# build that reaches this step ships to production\n"
        "# automatically. An unreviewed merge (or a compromised branch)\n"
        "# deploys with no human in the loop.\n"
        "\n"
        "# Safe: gate the deploy behind a manual block.\n"
        "steps:\n"
        "  - block: \"Deploy to prod?\"\n"
        "    branches: \"main\"\n"
        "  - label: \":rocket: Deploy prod\"\n"
        "    command: \"aws s3 sync ./dist s3://prod-site\""
    ),
)

# Heuristic deploy markers. Lower-cased before match.
_DEPLOY_KEYWORDS_RE = re.compile(
    r"\b(deploy|ship-it|release|promote|rollout|"
    r"helm\s+(?:upgrade|install)|kubectl\s+apply|terraform\s+apply|"
    r"aws\s+ecs\s+update-service|aws\s+lambda\s+update-function-code|"
    r"gcloud\s+run\s+deploy)\b",
    re.IGNORECASE,
)


def _is_block_or_input(step: dict[str, Any]) -> bool:
    return "block" in step or "input" in step


def _step_is_deploy(step: dict[str, Any]) -> bool:
    for k in ("label", "key"):
        v = step.get(k)
        if isinstance(v, str) and _DEPLOY_KEYWORDS_RE.search(v):
            return True
    for cmd in step_commands(step):
        if _DEPLOY_KEYWORDS_RE.search(cmd):
            return True
    return False


def _walk_steps(steps: list[Any]) -> list[Any]:
    """Flatten a steps list, expanding ``group`` containers."""
    out: list[Any] = []
    for s in steps:
        if isinstance(s, dict) and "group" in s and isinstance(
            s.get("steps"), list,
        ):
            out.append({"_group_marker": s.get("group", "")})
            out.extend(s["steps"])
        else:
            out.append(s)
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    raw_steps = doc.get("steps") or []
    if not isinstance(raw_steps, list):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path, description="No steps declared.",
            recommendation="No action required.", passed=True,
        )
    flat = _walk_steps(raw_steps)
    has_block_so_far = False
    ungated: list[str] = []
    for idx, step in enumerate(flat):
        if not isinstance(step, dict):
            continue
        if _is_block_or_input(step):
            has_block_so_far = True
            continue
        # ``- wait`` (string form) and other flow-control don't gate
        # deploys; only block/input do.
        if any(k in step for k in ("wait", "trigger")):
            continue
        if _step_is_deploy(step) and not has_block_so_far:
            ungated.append(step_label(step, idx))
    passed = not ungated
    desc = (
        "Deploy steps are gated by a preceding block / input step."
        if passed else
        f"{len(ungated)} deploy step(s) run without a preceding "
        f"manual gate: {', '.join(ungated[:5])}"
        f"{'…' if len(ungated) > 5 else ''}. Add a "
        f"``- block: \"Deploy?\"`` so a human approves before "
        f"production code ships."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        # ``job_anchors`` carries the ungated deploy-step labels so the
        # reachability-aware AC-026 chain can intersect them with the
        # injection-bearing steps BK-003 surfaces. Buildkite has no
        # named-job concept; the step label is the natural anchor.
        job_anchors=tuple(ungated),
    )
