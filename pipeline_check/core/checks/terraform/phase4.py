"""Phase-4 Terraform checks — gap fills + Terraform-native rules.

Two groups:

**AWS-runtime parity** (IDs shared with ``aws/rules/``):
    SIGN-001  No aws_signer_signing_profile referenced by Lambda deploys  MED   CICD-SEC-9
    EB-002    aws_cloudwatch_event_target.arn is a wildcard                HIGH  CICD-SEC-8
    CW-001    No aws_cloudwatch_metric_alarm on CodeBuild FailedBuilds     LOW   CICD-SEC-10

**Terraform-native** (IDs with TF- prefix — no AWS runtime analogue,
because the signal only exists in declarative source):
    TF-001    aws_iam_access_key resource declares a long-lived key       CRIT  CICD-SEC-6
    TF-002    Resource attribute contains a hard-coded secret shape        CRIT  CICD-SEC-6
    TF-003    CodeBuild VPC shares its VPC with a public subnet            HIGH  CICD-SEC-7

The gap-fill IDs are whitelisted: we only emit them when the plan
declares resources the check can actually reason about, matching the
gating behaviour of ``EB-001``/``CT-001``. Without that, an empty plan
would flood reports with spurious findings.
"""
from __future__ import annotations

from .._patterns import PLACEHOLDER_MARKER_RE, SECRET_NAME_RE, SECRET_VALUE_RE
from ..base import Finding, Severity
from .base import TerraformBaseCheck

# Resource attributes scanned by LMB-003 / SSM-001 / CB-001 already — skip
# here so operators don't see the same plaintext twice under two IDs.
_TF002_SKIP_TYPES = {
    "aws_lambda_function",      # LMB-003
    "aws_ssm_parameter",        # SSM-001
    "aws_codebuild_project",    # CB-001
}

# Resource types whose plaintext inputs routinely carry strings that
# look secret-shaped but aren't (e.g. ARNs, connection strings of
# public AWS endpoints). The blanket scan is intentionally narrow.
# aws_secretsmanager_secret_version is included deliberately: the
# ``secret_string`` attribute is a common place people paste literal
# tokens during local development and forget to swap out before merge.
_TF002_SCAN_TYPES = {
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_redshift_cluster",
    "aws_elasticache_replication_group",
    "aws_docdb_cluster",
    "aws_neptune_cluster",
    "aws_opensearch_domain",
    "aws_memorydb_cluster",
    "aws_secretsmanager_secret_version",
}

_LAMBDA_SIGNER_PLATFORM = "AWSLambda"


class Phase4Checks(TerraformBaseCheck):

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(_sign001(self.ctx))
        findings.extend(_eb002(self.ctx))
        findings.extend(_cw001(self.ctx))
        findings.extend(_tf001_iam_access_key(self.ctx))
        findings.extend(_tf002_plan_secrets(self.ctx))
        findings.extend(_tf003_codebuild_public_subnet(self.ctx))
        return findings


# ---------------------------------------------------------------------------
# SIGN-001 — aws_signer_signing_profile exists when Lambda code-signing is wired
# ---------------------------------------------------------------------------

def _sign001(ctx) -> list[Finding]:
    fns_with_signing = [
        fn for fn in ctx.resources("aws_lambda_function")
        if fn.values.get("code_signing_config_arn")
    ]
    # Gate: without any Lambda using code-signing, an absent profile
    # isn't a finding — nothing in the plan needs one.
    if not fns_with_signing:
        return []
    profiles = list(ctx.resources("aws_signer_signing_profile"))
    lambda_profiles = [
        p for p in profiles
        if _LAMBDA_SIGNER_PLATFORM in (p.values.get("platform_id") or "")
    ]
    passed = bool(lambda_profiles)
    if passed:
        desc = (
            f"{len(lambda_profiles)} Lambda-platform signing profile(s) declared: "
            + ", ".join(p.address for p in lambda_profiles)
        )
    else:
        desc = (
            f"{len(fns_with_signing)} Lambda function(s) reference "
            "code_signing_config_arn but no aws_signer_signing_profile with "
            "an AWSLambda-* platform_id is declared in the plan."
        )
    return [Finding(
        check_id="SIGN-001",
        title="No AWS Signer profile defined for Lambda deploys",
        severity=Severity.MEDIUM,
        resource=", ".join(fn.address for fn in fns_with_signing),
        description=desc,
        recommendation=(
            "Declare an aws_signer_signing_profile with platform_id "
            "``AWSLambda-SHA384-ECDSA`` and wire it into every "
            "aws_lambda_code_signing_config the plan creates."
        ),
        passed=passed,
    )]


# ---------------------------------------------------------------------------
# EB-002 — aws_cloudwatch_event_target.arn with wildcard
# ---------------------------------------------------------------------------

def _eb002(ctx) -> list[Finding]:
    out: list[Finding] = []
    for t in ctx.resources("aws_cloudwatch_event_target"):
        arn = t.values.get("arn", "") or ""
        if "*" not in arn:
            continue
        out.append(Finding(
            check_id="EB-002",
            title="EventBridge target ARN contains a wildcard",
            severity=Severity.HIGH,
            resource=t.address,
            description=f"Target ARN contains wildcard: {arn}.",
            recommendation=(
                "Replace wildcard target ARNs with specific resource ARNs; "
                "EventBridge routes the event to any resource matching the "
                "prefix, which frequently triggers unintended Lambda or SNS "
                "sends."
            ),
            passed=False,
        ))
    return out


# ---------------------------------------------------------------------------
# CW-001 — CloudWatch alarm on CodeBuild FailedBuilds
# ---------------------------------------------------------------------------

def _cw001(ctx) -> list[Finding]:
    projects = list(ctx.resources("aws_codebuild_project"))
    # Gate: only emit when the plan manages CodeBuild. A plan that
    # doesn't touch CodeBuild shouldn't trip an observability rule.
    if not projects:
        return []
    alarms = list(ctx.resources("aws_cloudwatch_metric_alarm"))
    covered = any(
        (a.values.get("namespace") == "AWS/CodeBuild"
         and a.values.get("metric_name") == "FailedBuilds")
        for a in alarms
    )
    if covered:
        return [Finding(
            check_id="CW-001",
            title="No CloudWatch alarm on CodeBuild FailedBuilds metric",
            severity=Severity.LOW,
            resource="plan-wide (aws_cloudwatch_metric_alarm)",
            description="At least one aws_cloudwatch_metric_alarm watches AWS/CodeBuild FailedBuilds.",
            recommendation="No action required.",
            passed=True,
        )]
    return [Finding(
        check_id="CW-001",
        title="No CloudWatch alarm on CodeBuild FailedBuilds metric",
        severity=Severity.LOW,
        resource="plan-wide (aws_cloudwatch_metric_alarm)",
        description=(
            f"Plan declares {len(projects)} CodeBuild project(s) but no "
            "aws_cloudwatch_metric_alarm on AWS/CodeBuild FailedBuilds."
        ),
        recommendation=(
            "Add an aws_cloudwatch_metric_alarm with namespace "
            "``AWS/CodeBuild`` and metric_name ``FailedBuilds`` so "
            "repeated build failures page on-call."
        ),
        passed=False,
    )]


# ---------------------------------------------------------------------------
# TF-001 — aws_iam_access_key as code
# ---------------------------------------------------------------------------

def _tf001_iam_access_key(ctx) -> list[Finding]:
    out: list[Finding] = []
    for k in ctx.resources("aws_iam_access_key"):
        user = k.values.get("user", "") or "<unknown user>"
        out.append(Finding(
            check_id="TF-001",
            title="aws_iam_access_key resource declares a long-lived IAM access key",
            severity=Severity.CRITICAL,
            resource=k.address,
            description=(
                f"Plan creates a long-lived access key for IAM user {user!r}. "
                "The credential material is written into Terraform state and "
                "there is no built-in rotation — any principal with state "
                "read access obtains an unrotated AWS credential."
            ),
            recommendation=(
                "Delete the aws_iam_access_key resource and grant the "
                "workload an IAM role assumed via OIDC or instance profile. "
                "If a static key is genuinely required, create it out of "
                "band and store only the key ID in Terraform."
            ),
            passed=False,
        ))
    return out


# ---------------------------------------------------------------------------
# TF-002 — hard-coded secret shapes in resource attributes
# ---------------------------------------------------------------------------

def _tf002_plan_secrets(ctx) -> list[Finding]:
    out: list[Finding] = []
    for r in ctx.resources():
        if r.type in _TF002_SKIP_TYPES:
            continue
        if r.type not in _TF002_SCAN_TYPES:
            continue
        hits = _scan_values(r.values)
        if not hits:
            continue
        summary = ", ".join(f"{path}={label}" for path, label in hits[:3])
        out.append(Finding(
            check_id="TF-002",
            title="Resource attribute contains a hard-coded secret shape",
            severity=Severity.CRITICAL,
            resource=r.address,
            description=(
                f"{len(hits)} attribute(s) carry credential-shaped values — "
                f"e.g. {summary}{'...' if len(hits) > 3 else ''}."
            ),
            recommendation=(
                "Move the value to Secrets Manager / SSM SecureString and "
                "reference it via a data source or ``manage_master_user_"
                "password = true``. Plan JSON and Terraform state store "
                "attribute values in clear text."
            ),
            passed=False,
        ))
    return out


def _scan_values(values: dict) -> list[tuple[str, str]]:
    """Return [(dot.path, detector-name)] for secret-shaped string leaves."""
    hits: list[tuple[str, str]] = []
    _walk(values, "", hits)
    return hits


def _walk(node, path: str, hits: list[tuple[str, str]]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            subpath = f"{path}.{k}" if path else str(k)
            _walk(v, subpath, hits)
        return
    if isinstance(node, list):
        for i, v in enumerate(node):
            _walk(v, f"{path}[{i}]", hits)
        return
    if not isinstance(node, str) or not node:
        return
    # Suppress obvious placeholders — ``<your-password>`` etc.
    if PLACEHOLDER_MARKER_RE.search(node):
        return
    # Vendor-token shape match is strongest signal.
    if SECRET_VALUE_RE.match(node):
        hits.append((path, "vendor-token"))
        return
    # Fallback: secret-named leaf (``master_password``, ``auth_token``,
    # …) with a non-trivial value. Suppress references like ``var.X``
    # or ``${...}`` which are Terraform interpolation residues.
    leaf = path.rsplit(".", 1)[-1].split("[")[0]
    if SECRET_NAME_RE.search(leaf) and len(node) >= 8 and "${" not in node:
        hits.append((path, "secret-named attribute"))


# ---------------------------------------------------------------------------
# TF-003 — CodeBuild VPC shares its VPC with a public subnet
# ---------------------------------------------------------------------------

def _tf003_codebuild_public_subnet(ctx) -> list[Finding]:
    # Build {vpc_id: [addresses of public subnets]} for subnets whose
    # vpc_id is resolvable.
    public_by_vpc: dict[str, list[str]] = {}
    for sn in ctx.resources("aws_subnet"):
        if not sn.values.get("map_public_ip_on_launch"):
            continue
        vpc_id = sn.values.get("vpc_id")
        if not isinstance(vpc_id, str) or not vpc_id:
            continue
        public_by_vpc.setdefault(vpc_id, []).append(sn.address)
    out: list[Finding] = []
    for p in ctx.resources("aws_codebuild_project"):
        cfg = (p.values.get("vpc_config") or [None])[0]
        if not cfg:
            continue
        vpc_id = cfg.get("vpc_id")
        if not isinstance(vpc_id, str) or not vpc_id:
            # Unresolvable vpc_id — cannot reason; stay silent.
            continue
        public = public_by_vpc.get(vpc_id, [])
        out.append(Finding(
            check_id="TF-003",
            title="CodeBuild VPC shares its VPC with a public subnet",
            severity=Severity.HIGH,
            resource=p.address,
            description=(
                f"CodeBuild vpc_id {vpc_id!r} also contains public subnet(s) "
                f"{public}. If vpc_config.subnets happens to include one, "
                "builds run with a public-IP-eligible ENI."
                if public else
                f"CodeBuild vpc_id {vpc_id!r} has no public subnets in the plan."
            ),
            recommendation=(
                "Place CodeBuild in private subnets with a NAT gateway for "
                "egress; set ``map_public_ip_on_launch = false`` on the "
                "subnets referenced by vpc_config.subnets."
            ),
            passed=not public,
        ))
    return out
