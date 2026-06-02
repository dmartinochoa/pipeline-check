"""BK-013, deploy steps must restrict to a release branch."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_command_steps, step_commands, step_label

RULE = Rule(
    id="BK-013",
    title="Deploy step has no branches: filter",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-ENV-SEP",),
    cwe=("CWE-284",),
    recommendation=(
        "Add ``branches: \"main release/*\"`` (or your release "
        "branch glob) to every deploy step. Buildkite skips the "
        "step on any other branch, which prevents a feature-branch "
        "PR from accidentally promoting code to production. "
        "Combine with BK-007's manual ``block:`` so a release "
        "branch *plus* a human approval is the path to deploy."
    ),
    docs_note=(
        "A step is treated as a deploy when its command line contains "
        "a deploy keyword (``deploy``, ``ship-it``, ``release``, "
        "``promote``, ``rollout``, ``helm upgrade``, ``kubectl "
        "apply``, ``terraform apply``, ``aws ecs update-service``, "
        "``aws lambda update-function-code``, ``gcloud run deploy``), "
        "or its label / key begins with an unambiguous deploy verb "
        "(``deploy``, ``ship-it``, ``rollout``) or with ``release`` / "
        "``promote`` as the leading word (after optional emoji / "
        "punctuation). Labels that only mention ``release`` or "
        "``promote`` mid-phrase (e.g. 'Build release artifact') are "
        "not flagged. The check passes when the step declares "
        "``branches:`` with at least one literal branch name (a "
        "wildcard like ``\"*\"`` is treated as an explicit opt-out, "
        "not a passing filter, and still trips). The pipeline-level "
        "default also counts, top-level ``steps:`` with ``branches:`` "
        "propagates."
    ),
    known_fp=(
        "Trunk-based teams that branch-protect ``main`` and treat "
        "every merge as a deploy candidate may not use ``branches:``. "
        "Add ``branches: main`` to make the policy explicit, or "
        "ignore BK-013 in ``.pipeline-check-ignore.yml`` with a "
        "scope of ``main``-only repos.",
    ),
    exploit_example=(
        "# Vulnerable: a deploy step with no branches: filter.\n"
        "steps:\n"
        "  - label: \"Deploy\"\n"
        "    command: \"kubectl apply -f k8s/\"\n"
        "\n"
        "# Attack: the step runs on every branch, so a feature branch\n"
        "# or a fork PR build promotes its own code to the cluster.\n"
        "# There's no release-branch boundary between \"someone pushed\"\n"
        "# and \"it's in prod.\"\n"
        "\n"
        "# Safe: restrict the deploy to the release branch (pair with\n"
        "# BK-007's manual block).\n"
        "  - label: \"Deploy\"\n"
        "    branches: \"main\"\n"
        "    command: \"kubectl apply -f k8s/\""
    ),
)


# Full keyword set used for command-line matching.  Commands are precise
# enough that any occurrence of "release" / "promote" is genuine.
_DEPLOY_KEYWORDS_RE = re.compile(
    r"\b(deploy|ship-it|release|promote|rollout|"
    r"helm\s+(?:upgrade|install)|kubectl\s+apply|terraform\s+apply|"
    r"aws\s+ecs\s+update-service|aws\s+lambda\s+update-function-code|"
    r"gcloud\s+run\s+deploy)\b",
    re.IGNORECASE,
)

# Narrower pattern for label / key matching.  "release" and "promote" are
# only treated as deploy intent when they appear as the *leading verb* of
# the label (optionally after emoji, punctuation, or whitespace).  This
# avoids false positives on labels like "Build release artifact" or
# "Generate release notes" whose commands perform no deploy action.
# Unambiguous action words (deploy, ship-it, rollout) and multi-token
# tool invocations are matched anywhere in the label as before.
_LABEL_DEPLOY_RE = re.compile(
    r"(?:"
    # Unambiguous single-word deploy verbs — match anywhere.
    r"\b(?:deploy|ship-it|rollout)\b"
    r"|"
    # Multi-token tool invocations — match anywhere.
    r"(?:helm\s+(?:upgrade|install)|kubectl\s+apply|terraform\s+apply|"
    r"aws\s+ecs\s+update-service|aws\s+lambda\s+update-function-code|"
    r"gcloud\s+run\s+deploy)"
    r"|"
    # "release" / "promote" only when leading the label (after optional
    # emoji / punctuation / whitespace so ":rocket: Release to prod" still
    # fires, but "Build release artifact" does not).
    r"(?:^[\s\W]*)(?:release|promote)\b"
    r")",
    re.IGNORECASE,
)


def _step_is_deploy(step: dict[str, Any]) -> bool:
    for k in ("label", "key"):
        v = step.get(k)
        if isinstance(v, str) and _LABEL_DEPLOY_RE.search(v):
            return True
    for cmd in step_commands(step):
        if _DEPLOY_KEYWORDS_RE.search(cmd):
            return True
    return False


def _branches_filter_present(step: dict[str, Any], pipeline_default: Any) -> bool:
    """Return True when the step has an effective branches: filter.

    A literal string list, single string with at least one non-wildcard
    token, or an inherited pipeline-level default all count. ``"*"`` /
    empty / ``null`` do not.
    """
    raw = step.get("branches", pipeline_default)
    if isinstance(raw, str):
        tokens = raw.split()
    elif isinstance(raw, list):
        tokens = [str(t) for t in raw if isinstance(t, str)]
    else:
        return False
    real = [t for t in tokens if t.strip() and t.strip() != "*"]
    return bool(real)


def check(path: str, doc: dict[str, Any]) -> Finding:
    pipeline_default = doc.get("branches")
    offenders: list[str] = []
    for idx, step in iter_command_steps(doc):
        if not _step_is_deploy(step):
            continue
        if not _branches_filter_present(step, pipeline_default):
            offenders.append(step_label(step, idx))
    passed = not offenders
    desc = (
        "Every deploy step declares a ``branches:`` filter."
        if passed else
        f"{len(offenders)} deploy step(s) run on any branch: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Add ``branches: main`` "
        f"so a feature-branch PR can't accidentally promote to prod."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
