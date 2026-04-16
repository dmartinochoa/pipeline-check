"""JF-015 — pipeline should declare a `timeout` wrapper."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

_TIMEOUT_RE = re.compile(r"\btimeout\s*\(")


RULE = Rule(
    id="JF-015",
    title="Pipeline has no `timeout` wrapper — unbounded build",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-TIMEOUT",),
    recommendation=(
        "Wrap the pipeline body or individual stages with "
        "`timeout(time: N, unit: 'MINUTES') { … }`. Without an "
        "explicit timeout, the build runs until the Jenkins global "
        "default (or indefinitely)."
    ),
    docs_note=(
        "Without a `timeout()` wrapper, the pipeline runs until the "
        "Jenkins controller's global timeout (or indefinitely if none "
        "is configured). Explicit timeouts cap blast radius and the "
        "window during which a compromised step has workspace access."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    passed = bool(_TIMEOUT_RE.search(jf.text))
    desc = (
        "Pipeline declares a `timeout()` wrapper."
        if passed else
        "Pipeline has no `timeout()` wrapper — the build will run "
        "until the Jenkins global default (or indefinitely)."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
