"""IAM-002. CI/CD role has a wildcard Action in any attached policy."""
from __future__ import annotations

from ..._iam_policy import has_wildcard_action
from ..._primitives.anchors import iam_role
from ...base import Finding, ResourceAnchor, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="IAM-002",
    title="CI/CD role has wildcard Action in attached policy",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-269",),
    recommendation="Replace wildcard actions with specific IAM actions.",
    docs_note=(
        "``Action: '*'`` (or service-prefix wildcards like "
        "``s3:*``) on an attached policy is functionally equivalent "
        "to AdministratorAccess for that resource. The wildcard "
        "absorbs every new IAM action AWS adds, so the role's "
        "authority grows without any local change."
    ),
    exploit_example=(
        "# Vulnerable: the role can do literally anything in S3.\n"
        "# Any compromise of any pipeline that assumes this role\n"
        "# (poisoned action, leaked credential, malicious build\n"
        "# step) can read, write, or delete every object in every\n"
        "# bucket the account owns. Privilege escalation also hides\n"
        "# inside the wildcard: ``s3:PutBucketPolicy`` is part of\n"
        "# ``s3:*``, so the attacker can open the bucket to the\n"
        "# public after the initial foothold.\n"
        "{\n"
        '  "Version": "2012-10-17",\n'
        '  "Statement": [{\n'
        '    "Effect": "Allow",\n'
        '    "Action": "s3:*",\n'
        '    "Resource": "*"\n'
        "  }]\n"
        "}\n"
        "\n"
        "# Safe: enumerate the actions the pipeline actually needs\n"
        "# and scope ``Resource`` to the specific bucket. A new\n"
        "# requirement then triggers a policy review instead of\n"
        "# silently widening authority.\n"
        "{\n"
        '  "Version": "2012-10-17",\n'
        '  "Statement": [{\n'
        '    "Effect": "Allow",\n'
        '    "Action": [\n'
        '      "s3:GetObject",\n'
        '      "s3:PutObject",\n'
        '      "s3:ListBucket"\n'
        "    ],\n"
        '    "Resource": [\n'
        '      "arn:aws:s3:::my-build-artifacts",\n'
        '      "arn:aws:s3:::my-build-artifacts/*"\n'
        "    ]\n"
        "  }]\n"
        "}"
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for role in catalog.cicd_roles():
        role_name = role.get("RoleName", "<unnamed>")
        docs, error = catalog.iam_role_policy_docs(role_name)
        offenders = [n for n, d in docs if has_wildcard_action(d)]
        passed = not offenders and error is None
        if error:
            desc = f"{error}. Cannot verify wildcard actions for '{role_name}'."
        elif offenders:
            desc = f"Policy/policies {offenders} on '{role_name}' use Action: '*'."
        else:
            desc = f"No policy on '{role_name}' uses Action: '*'."
        # ResourceAnchor phase 1: pair the wildcard-authority role with
        # cross-provider chain legs (AC-016 GHA-030 ``role-to-assume``)
        # via the canonical ``iam_role`` kind. boto3's list_roles output
        # includes the full ``Arn`` field for every role, so the
        # canonicalizer just verifies the shape. We don't emit an
        # anchor when the role lacks an ARN (malformed fixture / very
        # old API version) — better to skip than emit a half-formed key
        # that would silently miss a chain intersection.
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
