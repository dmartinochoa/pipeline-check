"""JF-003 — pipeline must not use bare `agent any`."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile


RULE = Rule(
    id="JF-003",
    title="Pipeline uses `agent any` (no executor isolation)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-5",),
    esf=("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"),
    recommendation=(
        "Replace `agent any` with `agent { label 'build-pool' }` "
        "(targeting a labelled pool) or `agent { docker { image "
        "'...' } }` (ephemeral container). Reserve broad-access "
        "agents for jobs that genuinely need them."
    ),
    docs_note=(
        "`agent any` is the broadest possible executor scope — any "
        "registered executor can be picked, including ones with "
        "broader IAM / file-system access than this build needs. A "
        "compromise of one job blast-radiates across every pool."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    passed = not re.search(r"\bagent\s+any\b", jf.text)
    desc = (
        "Pipeline does not use `agent any`."
        if passed else
        "Pipeline declares `agent any`, so any registered executor "
        "can be picked."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
