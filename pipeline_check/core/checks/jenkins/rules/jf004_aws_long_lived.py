"""JF-004 — withCredentials must not bind long-lived AWS keys."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import AWS_KEY_BINDING_RE, AWS_KEY_VAR_RE

RULE = Rule(
    id="JF-004",
    title="AWS auth uses long-lived access keys via withCredentials",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-TOKEN-HYGIENE",),
    recommendation=(
        "Switch to the AWS plugin's IAM-role / OIDC binding (e.g. "
        "`withAWS(role: 'arn:aws:iam::…:role/jenkins')`) so each "
        "build assumes a short-lived role. Remove the static "
        "AWS_ACCESS_KEY_ID secret from the Jenkins credentials "
        "store once the role is in place."
    ),
    docs_note=(
        "Fires when BOTH a credentialsId containing `aws` is "
        "referenced AND an AWS key variable name appears. Requires "
        "both so an OIDC role binding (which doesn't use key "
        "variables) doesn't false-positive."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    binding = bool(AWS_KEY_BINDING_RE.search(jf.text))
    var = bool(AWS_KEY_VAR_RE.search(jf.text))
    passed = not (binding and var)
    desc = (
        "Pipeline does not bind long-lived AWS access keys."
        if passed else
        "Pipeline uses `withCredentials` to bind long-lived "
        "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY values."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
