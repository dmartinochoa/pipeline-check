"""IAM-004. CI/CD role grants iam:PassRole with Resource:'*'."""
from __future__ import annotations

from ..._iam_policy import passrole_wildcard
from ..._primitives.anchors import iam_role
from ...base import Finding, ResourceAnchor, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="IAM-004",
    title="CI/CD role can PassRole to any role",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-269",),
    recommendation=(
        "Restrict iam:PassRole to specific role ARNs and add an "
        "iam:PassedToService condition."
    ),
    docs_note=(
        "``iam:PassRole`` with ``Resource: '*'`` lets the principal "
        "hand any role to any service. Combined with a service that "
        "runs your code (Lambda, ECS, CodeBuild, EC2 Instance "
        "Profiles), this is role-hop privilege escalation: launch "
        "an ephemeral resource configured with a higher-privileged "
        "role, run code under that identity, exfil. Scoping by ARN "
        "+ ``iam:PassedToService`` removes the escalation path."
    ),
    exploit_example=(
        "# Vulnerable: pipeline role grants PassRole with Resource: '*'.\n"
        "{\n"
        "  \"Version\": \"2012-10-17\",\n"
        "  \"Statement\": [{\n"
        "    \"Effect\": \"Allow\",\n"
        "    \"Action\": [\"iam:PassRole\", \"lambda:CreateFunction\",\n"
        "                \"lambda:InvokeFunction\"],\n"
        "    \"Resource\": \"*\"\n"
        "  }]\n"
        "}\n"
        "\n"
        "# Attack: from a build shell, create a Lambda configured with\n"
        "# the highest-privileged role you can name and invoke it:\n"
        "#\n"
        "#   aws lambda create-function --function-name pwn \\\n"
        "#     --role arn:aws:iam::123456789012:role/prod-admin \\\n"
        "#     --runtime python3.12 --handler i.h \\\n"
        "#     --zip-file fileb://payload.zip\n"
        "#   aws lambda invoke --function-name pwn /tmp/out\n"
        "#\n"
        "# The Lambda now runs as ``prod-admin`` even though the\n"
        "# pipeline principal never had that role's permissions\n"
        "# directly. Classic role-hop privilege escalation.\n"
        "\n"
        "# Safe: pin to one role ARN AND require the pass be scoped\n"
        "# to the service that legitimately consumes it.\n"
        "{\n"
        "  \"Effect\": \"Allow\",\n"
        "  \"Action\": \"iam:PassRole\",\n"
        "  \"Resource\": \"arn:aws:iam::123456789012:role/lambda-deploy-target\",\n"
        "  \"Condition\": {\n"
        "    \"StringEquals\": {\"iam:PassedToService\": \"lambda.amazonaws.com\"}\n"
        "  }\n"
        "}"
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for role in catalog.cicd_roles():
        role_name = role.get("RoleName", "<unnamed>")
        docs, error = catalog.iam_role_policy_docs(role_name)
        offenders = [n for n, d in docs if passrole_wildcard(d)]
        passed = not offenders and error is None
        if error:
            desc = f"{error}. Cannot verify iam:PassRole scope for '{role_name}'."
        elif offenders:
            desc = (
                f"Policy/policies {offenders} grant iam:PassRole with Resource: '*', "
                f"a classic privilege-escalation path."
            )
        else:
            desc = f"No policy on '{role_name}' grants iam:PassRole with Resource: '*'."
        # ResourceAnchor phase 1: emit the role's full ARN so AC-019
        # can intersect against LMB-003's execution-role anchor —
        # confirming the case where the Lambda that leaks credentials
        # is itself running as the wildcard-PassRole role.
        anchors: tuple[ResourceAnchor, ...] = ()
        arn = role.get("Arn")
        if isinstance(arn, str):
            built = iam_role(arn)
            if built is not None:
                anchors = (built,)
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=role_name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
            resource_anchors=anchors,
        ))
    return findings
