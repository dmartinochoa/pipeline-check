"""JF-004, withCredentials must not bind long-lived AWS keys."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import (
    AWS_KEY_BINDING_RE,
    AWS_KEY_VAR_BINDING_RE,
    AWS_KEY_VAR_RE,
    WITH_AWS_CREDS_RE,
)

RULE = Rule(
    id="JF-004",
    title="AWS auth uses long-lived access keys via withCredentials",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-TOKEN-HYGIENE",),
    cwe=("CWE-522",),
    recommendation=(
        "Switch to the AWS plugin's IAM-role / OIDC binding (e.g. "
        "`withAWS(role: 'arn:aws:iam::…:role/jenkins')`) so each "
        "build assumes a short-lived role. Remove the static "
        "AWS_ACCESS_KEY_ID secret from the Jenkins credentials "
        "store once the role is in place."
    ),
    docs_note=(
        "Fires when BOTH a credentialsId containing `aws` is "
        "referenced AND an AWS key variable name appears (requires "
        "both so an OIDC role binding doesn't false-positive). Also "
        "fires when `withAWS(credentials: '…')` is used, the "
        "safe alternative is `withAWS(role: '…')`."
    ),
    exploit_example=(
        "// Vulnerable: withCredentials binds long-lived AWS keys.\n"
        "stage('Deploy') {\n"
        "  steps {\n"
        "    withCredentials([usernamePassword(\n"
        "        credentialsId: 'aws-prod',\n"
        "        usernameVariable: 'AWS_ACCESS_KEY_ID',\n"
        "        passwordVariable: 'AWS_SECRET_ACCESS_KEY')]) {\n"
        "      sh 'aws s3 sync ./dist s3://prod-site'\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "// Attack: the static keys land in the build environment. A\n"
        "// leaked console log, a malicious shared library, or an `sh`\n"
        "// step that dumps env exfiltrates them. The long-lived IAM\n"
        "// user keys keep working until someone rotates them by hand.\n"
        "\n"
        "// Safe: assume a short-lived role per build.\n"
        "    withAWS(role: 'arn:aws:iam::123456789012:role/jenkins') {\n"
        "      sh 'aws s3 sync ./dist s3://prod-site'\n"
        "    }"
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    # Pattern 1: withCredentials + AWS key variable names. Either an
    # "aws"-named credentialsId paired with an AWS key variable, or a
    # binding keyword bound directly to an AWS key env name (which flags
    # even a non-"aws" credentialsId like 'prod-static').
    binding = bool(AWS_KEY_BINDING_RE.search(jf.text))
    var = bool(AWS_KEY_VAR_RE.search(jf.text))
    with_creds_long_lived = (binding and var) or bool(
        AWS_KEY_VAR_BINDING_RE.search(jf.text)
    )

    # Pattern 2: withAWS(credentials: '...'), static credential ID
    # (withAWS(role: '...') is the safe pattern and is NOT matched)
    with_aws_creds = bool(WITH_AWS_CREDS_RE.search(jf.text))

    passed = not (with_creds_long_lived or with_aws_creds)
    if with_aws_creds and not with_creds_long_lived:
        detail = (
            "Pipeline uses `withAWS(credentials: '…')` which binds "
            "static credentials. Use `withAWS(role: '…')` instead."
        )
    else:
        detail = (
            "Pipeline uses `withCredentials` to bind long-lived "
            "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY values."
        )
    desc = (
        "Pipeline does not bind long-lived AWS access keys."
        if passed else detail
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
