"""JF-011 — pipeline must declare a buildDiscarder / logRotator retention policy."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import BUILD_DISCARDER_RE

RULE = Rule(
    id="JF-011",
    title="Pipeline has no `buildDiscarder` retention policy",
    severity=Severity.LOW,
    owasp=("CICD-SEC-10",),
    esf=("ESF-D-BUILD-LOGS", "ESF-C-AUDIT"),
    recommendation=(
        "Add `options { buildDiscarder(logRotator(numToKeepStr: "
        "'30', daysToKeepStr: '90')) }` (declarative) or the "
        "`properties([buildDiscarder(...)])` equivalent in scripted "
        "pipelines. Tune the numbers to your retention policy."
    ),
    docs_note=(
        "Without a retention policy, build logs accumulate "
        "indefinitely; a secret that once leaked into a log stays "
        "visible to anyone who can read jobs. Recognises declarative "
        "`options { buildDiscarder(...) }`, scripted "
        "`properties([buildDiscarder(...)])`, and bare `logRotator(...)`."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    passed = bool(BUILD_DISCARDER_RE.search(jf.text))
    desc = (
        "Pipeline declares a `buildDiscarder` / `logRotator` policy."
        if passed else
        "Pipeline has no `buildDiscarder` / `logRotator` policy. "
        "Build logs accumulate indefinitely."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
