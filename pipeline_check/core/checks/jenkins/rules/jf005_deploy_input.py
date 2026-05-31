"""JF-005, deploy stages must have a manual `input` approval gate."""
from __future__ import annotations

import re

from ..._primitives.oci_refs import extract_image_anchors_from_strings
from ...base import Finding, ResourceAnchor, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import DEPLOY_RE

RULE = Rule(
    id="JF-005",
    title="Deploy stage missing manual `input` approval",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL",),
    cwe=("CWE-284",),
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
    exploit_example=(
        "// Vulnerable: a deploy stage with no manual input gate.\n"
        "stage('Deploy to prod') {\n"
        "  steps {\n"
        "    sh 'aws s3 sync ./dist s3://prod-site'\n"
        "  }\n"
        "}\n"
        "\n"
        "// Attack: nothing pauses the pipeline. Any commit that\n"
        "// triggers the job ships to production with no human review,\n"
        "// a self-merged change or a compromised branch deploys\n"
        "// straight through.\n"
        "\n"
        "// Safe: require a manual approval, scoped to release engineers.\n"
        "stage('Deploy to prod') {\n"
        "  steps {\n"
        "    input message: 'Promote to prod?', submitter: 'releasers'\n"
        "    sh 'aws s3 sync ./dist s3://prod-site'\n"
        "  }\n"
        "}"
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    ungated: list[str] = []
    ungated_bodies: list[str] = []
    for name, body in jf.stages:
        if not DEPLOY_RE.search(name):
            continue
        has_input = (
            bool(re.search(r"\binput\s*[({]", body))
            or bool(re.search(r"\binput\s+message\s*:", body))
        )
        if not has_input:
            ungated.append(name)
            ungated_bodies.append(body)
    passed = not ungated
    desc = (
        "All deploy-like stages declare a manual `input` approval gate."
        if passed else
        f"{len(ungated)} deploy-like stage(s) run without a manual "
        f"`input` gate: {', '.join(ungated)}."
    )
    # ResourceAnchor phase 1 (AC-005): emit oci_image anchors only
    # for the UNGATED deploy stages' bodies. Walking the whole
    # Jenkinsfile text would attach images from gated stages
    # (and non-executable comment text) to the ungated finding and
    # over-confirm AC-005 chains. Only on failing finding.
    anchors: tuple[ResourceAnchor, ...] = ()
    if not passed:
        seen: dict[str, ResourceAnchor] = {}
        for body in ungated_bodies:
            for a in extract_image_anchors_from_strings(body):
                seen.setdefault(a.identity, a)
        anchors = tuple(seen.values())
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        resource_anchors=anchors,
    )
