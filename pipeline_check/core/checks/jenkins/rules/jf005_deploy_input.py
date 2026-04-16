"""JF-005 — deploy stages must have a manual `input` approval gate."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import DEPLOY_RE

RULE = Rule(
    id="JF-005",
    title="Deploy stage missing manual `input` approval",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL",),
    recommendation=(
        "Add an `input` step to every deploy-like stage (e.g. "
        "`input message: 'Promote to prod?', submitter: "
        "'releasers'`). Combine with a Jenkins folder-scoped "
        "permission so only release engineers see the prompt."
    ),
    docs_note=(
        "A stage named `deploy` / `release` / `publish` / `promote` "
        "should either use the declarative `input { ... }` directive "
        "or call `input message: ...` somewhere in its body. "
        "Without one, any push that triggers the pipeline ships to "
        "the target with no human review."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    ungated: list[str] = []
    for name, body in jf.stages:
        if not DEPLOY_RE.search(name):
            continue
        has_input = (
            bool(re.search(r"\binput\s*[({]", body))
            or bool(re.search(r"\binput\s+message\s*:", body))
        )
        if not has_input:
            ungated.append(name)
    passed = not ungated
    desc = (
        "All deploy-like stages declare a manual `input` approval gate."
        if passed else
        f"{len(ungated)} deploy-like stage(s) run without a manual "
        f"`input` gate: {', '.join(ungated)}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
