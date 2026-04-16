"""JF-014 — agents should declare an ephemeral marker."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

_AGENT_LABEL_RE = re.compile(
    r"agent\s*\{\s*label\s+['\"]([^'\"]+)['\"]",
)


RULE = Rule(
    id="JF-014",
    title="Agent label missing ephemeral marker",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"),
    recommendation=(
        "Register Jenkins agents with ephemeral lifecycle (e.g. "
        "Kubernetes pod templates or EC2 Fleet plugin) and include "
        "`ephemeral` in the label string so the pipeline declares "
        "its expectation."
    ),
    docs_note=(
        "Static Jenkins agents that persist between builds leak "
        "workspace files and process state. The check looks for an "
        "`ephemeral` substring in `agent { label '...' }` blocks."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    offending: list[str] = []
    for m in _AGENT_LABEL_RE.finditer(jf.text):
        label = m.group(1).lower()
        if "ephemeral" not in label:
            offending.append(m.group(1))
    passed = not offending
    desc = (
        "All agent labels include an ephemeral marker."
        if passed else
        f"{len(offending)} agent label(s) lack an `ephemeral` "
        f"marker: {', '.join(offending[:5])}"
        f"{'…' if len(offending) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
