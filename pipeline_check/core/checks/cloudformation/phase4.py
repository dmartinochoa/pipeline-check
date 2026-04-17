"""CloudFormation Phase-4 parity — gap fills + CFN-native rules.

Mirrors ``checks/terraform/phase4.py`` resource-for-resource:

**AWS-runtime parity** (IDs shared with ``aws/rules/``):
    SIGN-001  No AWS::Signer::SigningProfile when Lambda code-signing   MED   CICD-SEC-9
    EB-002    AWS::Events::Rule target Arn contains a wildcard           HIGH  CICD-SEC-8
    CW-001    No AWS::CloudWatch::Alarm on AWS/CodeBuild FailedBuilds    LOW   CICD-SEC-10

**CloudFormation-native** (IDs with CF- prefix):
    CF-001    AWS::IAM::AccessKey declares a long-lived key              CRIT  CICD-SEC-6
    CF-002    Resource property contains a hard-coded secret shape       CRIT  CICD-SEC-6
    CF-003    CodeBuild VPC shares its VPC with a public subnet          HIGH  CICD-SEC-7

Intrinsics (``{"Ref": ...}``, ``{"Fn::Sub": ...}``) are treated as
non-literal — a rule that can only reason about concrete strings stays
silent when the value is unresolved, rather than false-matching.
"""
from __future__ import annotations

from .._patterns import PLACEHOLDER_MARKER_RE, SECRET_NAME_RE, SECRET_VALUE_RE
from ..base import Finding, Severity
from .base import CloudFormationBaseCheck, as_str, is_intrinsic, resolve_literal

# Resource types whose secret-carrying properties are covered by
# existing rules (LMB-003, SSM-001, CB-001) or are the legitimate
# home for secret material.
_CF002_SKIP_TYPES = {
    "AWS::Lambda::Function",
    "AWS::SSM::Parameter",
    "AWS::CodeBuild::Project",
    "AWS::SecretsManager::Secret",
}

# Stateful data stores — narrow allow-list of types whose property
# maps historically carry hard-coded database credentials.
_CF002_SCAN_TYPES = {
    "AWS::RDS::DBInstance",
    "AWS::RDS::DBCluster",
    "AWS::Redshift::Cluster",
    "AWS::ElastiCache::ReplicationGroup",
    "AWS::DocDB::DBCluster",
    "AWS::Neptune::DBCluster",
    "AWS::OpenSearchService::Domain",
    "AWS::MemoryDB::Cluster",
}


class Phase4Checks(CloudFormationBaseCheck):

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(_sign001(self.ctx))
        findings.extend(_eb002(self.ctx))
        findings.extend(_cw001(self.ctx))
        findings.extend(_cf001_iam_access_key(self.ctx))
        findings.extend(_cf002_template_secrets(self.ctx))
        findings.extend(_cf003_codebuild_public_subnet(self.ctx))
        return findings


# ---------------------------------------------------------------------------
# SIGN-001 — Lambda code-signing needs a matching signer profile
# ---------------------------------------------------------------------------

def _sign001(ctx) -> list[Finding]:
    signed_fns = [
        fn for fn in ctx.resources("AWS::Lambda::Function")
        if fn.properties.get("CodeSigningConfigArn")
    ]
    if not signed_fns:
        return []
    lambda_profiles = [
        p for p in ctx.resources("AWS::Signer::SigningProfile")
        if "AWSLambda" in as_str(p.properties.get("PlatformId"))
    ]
    passed = bool(lambda_profiles)
    if passed:
        desc = (
            f"{len(lambda_profiles)} Lambda-platform signing profile(s) declared: "
            + ", ".join(p.address for p in lambda_profiles)
        )
    else:
        desc = (
            f"{len(signed_fns)} Lambda function(s) reference "
            "CodeSigningConfigArn but no AWS::Signer::SigningProfile with "
            "an AWSLambda-* PlatformId is declared in the template."
        )
    return [Finding(
        check_id="SIGN-001",
        title="No AWS Signer profile defined for Lambda deploys",
        severity=Severity.MEDIUM,
        resource=", ".join(fn.address for fn in signed_fns),
        description=desc,
        recommendation=(
            "Declare an AWS::Signer::SigningProfile with PlatformId "
            "``AWSLambda-SHA384-ECDSA`` and wire it into every "
            "AWS::Lambda::CodeSigningConfig the template creates."
        ),
        passed=passed,
    )]


# ---------------------------------------------------------------------------
# EB-002 — AWS::Events::Rule target ARNs with wildcards
# ---------------------------------------------------------------------------

def _eb002(ctx) -> list[Finding]:
    out: list[Finding] = []
    params = ctx.parameter_defaults
    for rule in ctx.resources("AWS::Events::Rule"):
        targets = rule.properties.get("Targets") or []
        if not isinstance(targets, list):
            continue
        for idx, target in enumerate(targets):
            if not isinstance(target, dict):
                continue
            # Try literal first; fall back to resolving intrinsics the
            # static scanner can reduce (``Fn::Sub "...:*"``, ``Ref`` to
            # a parameter with a wildcard default, etc.).
            arn = as_str(target.get("Arn")) or (
                resolve_literal(target.get("Arn"), params) or ""
            )
            if "*" not in arn:
                continue
            tid = target.get("Id") or f"Targets[{idx}]"
            out.append(Finding(
                check_id="EB-002",
                title="EventBridge target ARN contains a wildcard",
                severity=Severity.HIGH,
                resource=f"{rule.address}.{tid}",
                description=f"Target ARN contains wildcard: {arn}.",
                recommendation=(
                    "Replace wildcard target ARNs with specific resource "
                    "ARNs; EventBridge routes the event to any resource "
                    "matching the prefix, which frequently triggers "
                    "unintended Lambda or SNS sends."
                ),
                passed=False,
            ))
    return out


# ---------------------------------------------------------------------------
# CW-001 — CloudWatch alarm on CodeBuild FailedBuilds
# ---------------------------------------------------------------------------

def _cw001(ctx) -> list[Finding]:
    projects = list(ctx.resources("AWS::CodeBuild::Project"))
    if not projects:
        return []
    alarms = list(ctx.resources("AWS::CloudWatch::Alarm"))
    covered = any(
        (as_str(a.properties.get("Namespace")) == "AWS/CodeBuild"
         and as_str(a.properties.get("MetricName")) == "FailedBuilds")
        for a in alarms
    )
    if covered:
        return [Finding(
            check_id="CW-001",
            title="No CloudWatch alarm on CodeBuild FailedBuilds metric",
            severity=Severity.LOW,
            resource="template-wide (AWS::CloudWatch::Alarm)",
            description="At least one AWS::CloudWatch::Alarm watches AWS/CodeBuild FailedBuilds.",
            recommendation="No action required.",
            passed=True,
        )]
    return [Finding(
        check_id="CW-001",
        title="No CloudWatch alarm on CodeBuild FailedBuilds metric",
        severity=Severity.LOW,
        resource="template-wide (AWS::CloudWatch::Alarm)",
        description=(
            f"Template declares {len(projects)} CodeBuild project(s) but "
            "no AWS::CloudWatch::Alarm on AWS/CodeBuild FailedBuilds."
        ),
        recommendation=(
            "Add an AWS::CloudWatch::Alarm with Namespace "
            "``AWS/CodeBuild`` and MetricName ``FailedBuilds`` so "
            "repeated build failures page on-call."
        ),
        passed=False,
    )]


# ---------------------------------------------------------------------------
# CF-001 — AWS::IAM::AccessKey as code
# ---------------------------------------------------------------------------

def _cf001_iam_access_key(ctx) -> list[Finding]:
    out: list[Finding] = []
    for k in ctx.resources("AWS::IAM::AccessKey"):
        user = as_str(k.properties.get("UserName")) or "<unknown user>"
        out.append(Finding(
            check_id="CF-001",
            title="AWS::IAM::AccessKey resource declares a long-lived IAM access key",
            severity=Severity.CRITICAL,
            resource=k.address,
            description=(
                f"Template creates a long-lived access key for IAM user {user!r}. "
                "The SecretAccessKey is emitted as a stack output or must be "
                "referenced via Fn::GetAtt — either way the credential is "
                "stored in the CloudFormation stack metadata without rotation."
            ),
            recommendation=(
                "Delete the AWS::IAM::AccessKey resource and grant the "
                "workload an IAM role assumed via OIDC or instance profile. "
                "If a static key is genuinely required, create it out of "
                "band and inject only the key ID as a parameter."
            ),
            passed=False,
        ))
    return out


# ---------------------------------------------------------------------------
# CF-002 — hard-coded secret shapes in resource properties
# ---------------------------------------------------------------------------

def _cf002_template_secrets(ctx) -> list[Finding]:
    out: list[Finding] = []
    for r in ctx.resources():
        if r.type in _CF002_SKIP_TYPES or r.type not in _CF002_SCAN_TYPES:
            continue
        hits = _scan_values(r.properties)
        if not hits:
            continue
        summary = ", ".join(f"{path}={label}" for path, label in hits[:3])
        out.append(Finding(
            check_id="CF-002",
            title="Resource property contains a hard-coded secret shape",
            severity=Severity.CRITICAL,
            resource=r.address,
            description=(
                f"{len(hits)} property leaf/leaves carry credential-shaped "
                f"values — e.g. {summary}{'...' if len(hits) > 3 else ''}."
            ),
            recommendation=(
                "Move the value to AWS Secrets Manager or SSM SecureString "
                "and reference it via a dynamic reference "
                "(``{{resolve:secretsmanager:...}}``) or the managed-"
                "master-user-password property. Template bodies are "
                "stored in the CloudFormation service in clear text."
            ),
            passed=False,
        ))
    return out


def _scan_values(node) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    _walk(node, "", hits)
    return hits


def _walk(node, path: str, hits: list[tuple[str, str]]) -> None:
    if isinstance(node, dict):
        # Treat unresolved intrinsics as opaque — they carry a Ref or
        # Fn::Sub expression, never a literal credential.
        if is_intrinsic(node):
            return
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
    if PLACEHOLDER_MARKER_RE.search(node):
        return
    if SECRET_VALUE_RE.match(node):
        hits.append((path, "vendor-token"))
        return
    leaf = path.rsplit(".", 1)[-1].split("[")[0]
    # CFN property names are PascalCase; SECRET_NAME_RE is case-
    # insensitive so it matches ``MasterUserPassword`` and ``AuthToken``.
    if SECRET_NAME_RE.search(leaf) and len(node) >= 8:
        hits.append((path, "secret-named property"))


# ---------------------------------------------------------------------------
# CF-003 — CodeBuild VPC shares its VPC with a public subnet
# ---------------------------------------------------------------------------

def _cf003_codebuild_public_subnet(ctx) -> list[Finding]:
    params = ctx.parameter_defaults
    public_by_vpc: dict[str, list[str]] = {}
    for sn in ctx.resources("AWS::EC2::Subnet"):
        if not _is_public(sn.properties.get("MapPublicIpOnLaunch")):
            continue
        vpc_id = resolve_literal(sn.properties.get("VpcId"), params)
        if not vpc_id:
            continue
        public_by_vpc.setdefault(vpc_id, []).append(sn.address)
    out: list[Finding] = []
    for p in ctx.resources("AWS::CodeBuild::Project"):
        cfg = p.properties.get("VpcConfig")
        if not isinstance(cfg, dict) or not cfg:
            continue
        vpc_id = resolve_literal(cfg.get("VpcId"), params)
        if not vpc_id:
            continue
        public = public_by_vpc.get(vpc_id, [])
        out.append(Finding(
            check_id="CF-003",
            title="CodeBuild VPC shares its VPC with a public subnet",
            severity=Severity.HIGH,
            resource=p.address,
            description=(
                f"CodeBuild VpcId {vpc_id!r} also contains public subnet(s) "
                f"{public}. If VpcConfig.Subnets happens to include one, "
                "builds run with a public-IP-eligible ENI."
                if public else
                f"CodeBuild VpcId {vpc_id!r} has no public subnets in the template."
            ),
            recommendation=(
                "Place CodeBuild in private subnets with a NAT gateway "
                "for egress; set MapPublicIpOnLaunch=false on the "
                "subnets referenced by VpcConfig.Subnets."
            ),
            passed=not public,
        ))
    return out


def _is_public(value) -> bool:
    """True when MapPublicIpOnLaunch is provably truthy."""
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False
