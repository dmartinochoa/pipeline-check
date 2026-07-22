"""SM-001. Secrets Manager secrets referenced by CI/CD have no rotation."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

# AWS appends a 6-char random suffix to a secret ARN: ``...:secret:NAME-AbCdEf``.
_ARN_SUFFIX_RE = re.compile(r"-[A-Za-z0-9]{6}$")


def _secret_arn(value: str) -> str:
    """Normalize a CodeBuild SECRETS_MANAGER ARN reference to the secret ARN.

    The value may carry a trailing ``:json-key:version-stage:version-id``
    suffix; keep only the first seven colon-delimited segments
    (``arn:aws:secretsmanager:region:account:secret:NAME``).
    """
    return ":".join(value.split(":")[:7])


def _arn_friendly_name(arn: str) -> str:
    """Friendly secret name from an ARN: the ``:secret:`` tail, random
    suffix stripped. Returns the input unchanged when it isn't an ARN."""
    if ":secret:" not in arn:
        return arn
    return _ARN_SUFFIX_RE.sub("", arn.split(":secret:", 1)[1])

RULE = Rule(
    id="SM-001",
    title="Secrets Manager secret has no rotation configured",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Enable automatic rotation on every Secrets Manager secret referenced "
        "by a CodeBuild project or CodePipeline. Unrotated secrets persist "
        "indefinitely, so a single leak (e.g. a build log that echoed the "
        "value) compromises the secret for its full lifetime."
    ),
    docs_note=(
        "Only secrets actually referenced by CodeBuild are checked, secrets "
        "used purely by application workloads are out of scope for a CI/CD "
        "scanner."
    ),
    exploit_example=(
        "# Vulnerable: a Secrets Manager secret with no rotation\n"
        "# configured. The credential lives forever; any leak\n"
        "# (log echo, accidental commit, .env file in an artifact)\n"
        "# stays valid until manually rotated, which usually means\n"
        "# until someone notices.\n"
        "import boto3\n"
        "sm = boto3.client('secretsmanager')\n"
        "sm.describe_secret(SecretId='prod/db-master')\n"
        "# {'RotationEnabled': False, ...}\n"
        "\n"
        "# Safe: enable rotation against a rotation Lambda. AWS\n"
        "# provides templates for RDS / DocumentDB / Redshift\n"
        "# rotation; custom secrets need a Lambda that knows how\n"
        "# to rotate the credential.\n"
        "sm.rotate_secret(\n"
        "    SecretId='prod/db-master',\n"
        "    RotationLambdaARN='arn:aws:lambda:us-east-1:123:function:rotate-rds',\n"
        "    RotationRules={'AutomaticallyAfterDays': 30},\n"
        ")"
    ),
)


def _referenced_secret_names(catalog: ResourceCatalog) -> set[str]:
    """Return the set of Secrets Manager secret IDs referenced by CodeBuild."""
    refs: set[str] = set()
    for project in catalog.codebuild_projects():
        env = project.get("environment") or {}
        for ev in env.get("environmentVariables", []):
            if ev.get("type") == "SECRETS_MANAGER":
                value = ev.get("value")
                if isinstance(value, str) and value:
                    # An ARN value keeps the secret ARN (minus any trailing
                    # version/stage suffix); a bare reference is the secret
                    # name. Never split on every colon, that reduced an ARN
                    # to the literal "arn".
                    refs.add(_secret_arn(value) if value.startswith("arn:") else value)
    return refs


def _reference_matches(ref: str, name: str, arn: str) -> bool:
    """True when CI/CD reference *ref* names the secret (*name*, *arn*).

    Match exactly, never by substring: a bare-name reference must equal
    the secret ``Name`` and an ARN reference must equal the ARN (or its
    suffix-stripped friendly name), so ``my-secret`` does not bleed onto
    ``my-secret-staging``.
    """
    if ref in (name, arn):
        return True
    if ref.startswith("arn:") and ":secret:" in ref:
        # Don't blanket-strip the reference: a name whose last segment is
        # 6 alnum chars (``my-secret`` -> ``-secret``) would be mangled to
        # ``my``. Compare the raw ``:secret:`` tail first (a reference
        # usually omits AWS's random suffix), then fall back to a strip
        # only when the tail actually carries one.
        ref_tail = ref.split(":secret:", 1)[1]
        friendly_arn = _arn_friendly_name(arn)
        if ref_tail in (name, friendly_arn):
            return True
        if _ARN_SUFFIX_RE.search(ref_tail):
            stripped = _ARN_SUFFIX_RE.sub("", ref_tail)
            return stripped in (name, friendly_arn)
    return False


def check(catalog: ResourceCatalog) -> list[Finding]:
    referenced = _referenced_secret_names(catalog)
    if not referenced:
        return []
    findings: list[Finding] = []
    for secret in catalog.secrets():
        name = secret.get("Name", "")
        arn = secret.get("ARN", "")
        if not any(_reference_matches(ref, name, arn) for ref in referenced):
            continue
        last_rotated = secret.get("LastRotatedDate")
        rotation = secret.get("RotationEnabled", False)
        passed = bool(rotation)
        if passed:
            desc = (
                f"Secret '{name}' has rotation enabled "
                f"(last rotated: {last_rotated or 'never'})."
            )
        else:
            desc = (
                f"Secret '{name}' is referenced by CodeBuild but has no "
                "rotation configured."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
