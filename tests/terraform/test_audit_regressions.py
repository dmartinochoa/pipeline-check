"""Regression tests from the rule audit (Terraform crash / FN fixes).

Each test pins a specific defect the 2026-07 audit found: a check that
crashed on valid-but-unusual input, or that produced a false positive /
false negative. Grouped here so the audit's Terraform coverage is
auditable in one place.
"""
from __future__ import annotations

import json

from pipeline_check.core.checks._iam_policy import is_oidc_trust_stmt
from pipeline_check.core.checks._patterns import SECRET_NAME_RE
from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.terraform.base import TerraformContext
from pipeline_check.core.checks.terraform.codebuild import _cb004_timeout
from pipeline_check.core.checks.terraform.ecr import _ecr003_public_policy
from pipeline_check.core.checks.terraform.iam import IAMChecks
from pipeline_check.core.checks.terraform.phase4 import (
    _tf001_iam_access_key,
    _tf003_codebuild_public_subnet,
)
from pipeline_check.core.checks.terraform.rules import iam001_admin_access as iam001
from pipeline_check.core.checks.terraform.rules import (
    s3001_public_access_block as s3001,
)
from pipeline_check.core.checks.terraform.rules import s3002_encryption as s3002
from pipeline_check.core.checks.terraform.rules import s3003_versioning as s3003
from pipeline_check.core.checks.terraform.rules import (
    s3004_access_logging as s3004,
)
from pipeline_check.core.checks.terraform.rules import sm001_rotation as sm001
from pipeline_check.core.checks.terraform.rules import sm002_public_policy as sm002
from pipeline_check.core.checks.terraform.s3 import _s3005_secure_transport
from pipeline_check.core.checks.terraform.services import _lambda, _ssm

_ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _plan(resources):
    return {"format_version": "1.2", "planned_values": {"root_module": {
        "resources": resources, "child_modules": []}}}


def _role(name, trust, **kw):
    vals = {"name": name, "assume_role_policy": trust}
    vals.update(kw)
    return {
        "address": f"aws_iam_role.{name}", "mode": "managed",
        "type": "aws_iam_role", "name": name, "values": vals,
    }


class TestIamContextScalarShapes:
    """``_role_is_cicd`` used to iterate ``Statement`` and index
    ``Principal`` assuming a list-of-dicts with dict principals, so a
    single-dict ``Statement`` or a bare string ``Principal`` raised and
    (via ``_guard_check``) degraded every IAM-* rule to a silent pass.
    """

    def test_single_dict_statement_codebuild_admin_fires(self):
        # A codebuild-trusted admin role whose trust policy is authored
        # with a single-dict ``Statement`` (not a list) must still be
        # recognized as CI/CD-scoped and flagged by IAM-001.
        trust = json.dumps({"Statement": {
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole"}})
        ctx = TerraformContext(_plan([
            _role("ci", trust, managed_policy_arns=[_ADMIN])]))
        f = iam001.check(ctx)
        assert f and not f[0].passed

    def test_list_statement_still_fires(self):
        # Regression guard: the common list form is unaffected.
        trust = json.dumps({"Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole"}]})
        ctx = TerraformContext(_plan([
            _role("ci", trust, managed_policy_arns=[_ADMIN])]))
        f = iam001.check(ctx)
        assert f and not f[0].passed

    def test_public_string_principal_does_not_crash(self):
        # ``Principal: "*"`` (a public trust, string not dict) is not a
        # CI/CD role; the check must skip it, not raise.
        trust = json.dumps({"Statement": {
            "Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}})
        ctx = TerraformContext(_plan([
            _role("pub", trust, managed_policy_arns=[_ADMIN])]))
        assert iam001.check(ctx) == []
        # The legacy per-service class path must also not raise.
        assert IAMChecks(ctx).run() == []


class TestIsOidcTrustStmtStringPrincipal:
    def test_string_principal_returns_none(self):
        # A bare ``Principal: "*"`` is a public/anonymous trust, not a
        # Federated OIDC one; must be a non-match rather than a crash.
        assert is_oidc_trust_stmt(
            {"Effect": "Allow", "Principal": "*"}) is None

    def test_federated_oidc_still_matched(self):
        host = is_oidc_trust_stmt({"Effect": "Allow", "Principal": {
            "Federated": "arn:aws:iam::123456789012:oidc-provider/"
            "token.actions.githubusercontent.com"}})
        assert host == "token.actions.githubusercontent.com"


class TestScalarPolicyAndBlockCrashes:
    """Policy documents and nested blocks can arrive in scalar / single-dict
    / unresolved-reference forms that used to raise and (via the per-rule
    guard) silently drop the finding.
    """

    def test_s3005_single_dict_deny_recognized(self):
        # A bucket policy authored with a single-dict Statement (not a
        # list) that denies non-TLS requests must be credited, not crash.
        doc = json.dumps({"Statement": {
            "Effect": "Deny", "Principal": "*", "Action": "s3:*",
            "Resource": "*",
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}}})
        assert _s3005_secure_transport({"bucket": "b", "policy": doc}, "b").passed

    def test_s3005_non_object_policy_does_not_crash(self):
        assert _s3005_secure_transport(
            {"bucket": "b", "policy": "[1,2,3]"}, "b").passed is False

    def test_ecr003_single_dict_public_detected(self):
        doc = json.dumps({"Statement": {
            "Effect": "Allow", "Principal": "*", "Action": "ecr:*"}})
        assert _ecr003_public_policy(doc, "r").passed is False

    def test_ecr003_non_object_policy_does_not_crash(self):
        assert _ecr003_public_policy("[1,2]", "r").passed is True

    def test_lmb003_string_variables_does_not_crash(self):
        # environment.variables can be an unresolved HCL reference (string)
        # in plan mode; the check must treat it as no variables, not iterate.
        plan = _plan([{
            "address": "aws_lambda_function.fn", "mode": "managed",
            "type": "aws_lambda_function", "name": "fn",
            "values": {"function_name": "fn",
                       "environment": {"variables": "${local.envmap}"}}}])
        lmb003 = [f for f in _lambda(TerraformContext(plan))
                  if f.check_id == "LMB-003"]
        assert lmb003 and lmb003[0].passed is True

    def test_cb004_string_timeout_does_not_crash(self):
        # build_timeout as an unresolved reference string must not raise on
        # a ``str < int`` comparison; it degrades to "unknown / not set".
        f = _cb004_timeout({"build_timeout": "${var.t}"}, "aws_codebuild_project.p")
        assert f.check_id == "CB-004" and f.passed is False

    def test_cb004_numeric_string_parsed(self):
        f = _cb004_timeout({"build_timeout": "60"}, "aws_codebuild_project.p")
        assert f.passed is True

    def test_cb004_integer_still_works(self):
        assert _cb004_timeout(
            {"build_timeout": 60}, "aws_codebuild_project.p").passed is True
        assert _cb004_timeout(
            {"build_timeout": 600}, "aws_codebuild_project.p").passed is False


class TestKMS002AccountRootBaseline:
    """A4: terraform KMS-002 flagged the AWS-documented default key policy
    (``kms:*`` to the account root); the rule's own exploit_example labels
    that shape "Safe"."""

    def _kms002(self, policy):
        from pipeline_check.core.checks.terraform.services import _kms
        plan = _plan([{
            "address": "aws_kms_key.k", "mode": "managed",
            "type": "aws_kms_key", "name": "k",
            "values": {"customer_master_key_spec": "SYMMETRIC_DEFAULT",
                       "policy": json.dumps(policy)}}])
        f = [x for x in _kms(TerraformContext(plan)) if x.check_id == "KMS-002"]
        return f[0]

    def test_account_root_passes(self):
        pol = {"Statement": [{
            "Sid": "Enable IAM User Permissions", "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
            "Action": "kms:*", "Resource": "*"}]}
        assert self._kms002(pol).passed is True

    def test_non_root_wildcard_fires(self):
        pol = {"Statement": [{
            "Sid": "CI", "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::111122223333:role/CI"},
            "Action": "kms:*", "Resource": "*"}]}
        assert self._kms002(pol).passed is False


def _pipeline(bucket):
    return {
        "address": "aws_codepipeline.p", "mode": "managed",
        "type": "aws_codepipeline", "name": "p",
        "values": {
            "name": "p", "stage": [],
            "artifact_store": [{"location": bucket}],
        },
    }


class TestA2PlanModeBucketJoin:
    """A2: the S3-00x artifact-bucket rules join a side-resource by its
    ``bucket`` value, but on a fresh ``terraform plan`` that value is a
    computed reference ``planned_values`` omits, so the join misses and
    the whole family false-fired CRITICAL/HIGH on a fully-configured
    plan. When a side-resource's ``bucket`` is unresolved, an unmatched
    bucket is now reported "could not correlate" instead of failing.
    """

    def test_s3001_unknown_bucket_pab_does_not_false_fire(self):
        # Artifact bucket name is a known literal; the PAB (all four
        # flags true) has no ``bucket`` key — the shape terraform emits
        # for ``bucket = aws_s3_bucket.x.id`` at plan time.
        plan = _plan([
            _pipeline("my-artifacts"),
            {"address": "aws_s3_bucket_public_access_block.a",
             "mode": "managed", "type": "aws_s3_bucket_public_access_block",
             "name": "a", "values": {
                 "block_public_acls": True, "ignore_public_acls": True,
                 "block_public_policy": True, "restrict_public_buckets": True}},
        ])
        f = s3001.check(TerraformContext(plan))
        assert len(f) == 1
        assert f[0].passed is True
        assert "could not correlate" in f[0].description.lower()

    def test_s3001_genuinely_missing_pab_still_fires(self):
        # No PAB resource at all in the plan: the failure must stand.
        plan = _plan([_pipeline("my-artifacts")])
        f = s3001.check(TerraformContext(plan))
        assert len(f) == 1
        assert f[0].passed is False

    def test_s3001_resolved_join_still_evaluates(self):
        # A PAB whose bucket resolves to the artifact bucket but leaves a
        # flag false must still fail — the unresolved path must not mask
        # a real misconfiguration.
        plan = _plan([
            _pipeline("my-artifacts"),
            {"address": "aws_s3_bucket_public_access_block.a",
             "mode": "managed", "type": "aws_s3_bucket_public_access_block",
             "name": "a", "values": {
                 "bucket": "my-artifacts",
                 "block_public_acls": True, "ignore_public_acls": True,
                 "block_public_policy": True, "restrict_public_buckets": False}},
        ])
        f = s3001.check(TerraformContext(plan))
        assert f[0].passed is False

    def test_s3002_unknown_bucket_sse_does_not_false_fire(self):
        plan = _plan([
            _pipeline("my-artifacts"),
            {"address": "aws_s3_bucket_server_side_encryption_configuration.a",
             "mode": "managed",
             "type": "aws_s3_bucket_server_side_encryption_configuration",
             "name": "a", "values": {
                 "rule": [{"apply_server_side_encryption_by_default": [
                     {"sse_algorithm": "aws:kms"}]}]}},
        ])
        f = s3002.check(TerraformContext(plan))
        assert f[0].passed is True
        assert "could not correlate" in f[0].description.lower()


class TestS3InlineBlockFallback:
    """S3-002/003/004 only joined the standalone ``aws_s3_bucket_*``
    resources; AWS-provider-v3 stacks configure SSE / versioning /
    logging as inline blocks on ``aws_s3_bucket`` and were false-flagged.
    """

    def _bucket(self, name, **inline):
        vals = {"bucket": name}
        vals.update(inline)
        return {"address": f"aws_s3_bucket.{name}", "mode": "managed",
                "type": "aws_s3_bucket", "name": name, "values": vals}

    def test_s3002_inline_sse_passes(self):
        plan = _plan([
            _pipeline("art"),
            self._bucket("art", server_side_encryption_configuration=[
                {"rule": [{"apply_server_side_encryption_by_default": [
                    {"sse_algorithm": "aws:kms"}]}]}]),
        ])
        f = s3002.check(TerraformContext(plan))
        assert f[0].passed is True

    def test_s3003_inline_versioning_passes(self):
        plan = _plan([
            _pipeline("art"),
            self._bucket("art", versioning=[{"enabled": True}]),
        ])
        f = s3003.check(TerraformContext(plan))
        assert f[0].passed is True

    def test_s3003_inline_versioning_suspended_fails(self):
        plan = _plan([
            _pipeline("art"),
            self._bucket("art", versioning=[{"enabled": False}]),
        ])
        f = s3003.check(TerraformContext(plan))
        assert f[0].passed is False

    def test_s3004_inline_logging_passes(self):
        plan = _plan([
            _pipeline("art"),
            self._bucket("art", logging=[{"target_bucket": "logs"}]),
        ])
        f = s3004.check(TerraformContext(plan))
        assert f[0].passed is True

    def test_no_inline_and_no_standalone_still_fails(self):
        # A bucket resource with no inline versioning must still fail.
        plan = _plan([_pipeline("art"), self._bucket("art")])
        f = s3003.check(TerraformContext(plan))
        assert f[0].passed is False


class TestA2SecretRotationJoin:
    """A2: SM-001 keys rotations by ``secret_id``, computed at apply
    time and omitted from a fresh plan, so the rule's own "Safe"
    example (secret + rotation) false-fired HIGH. It also never matched
    a ``.arn`` interpolation.
    """

    def _secret(self, name):
        return {"address": f"aws_secretsmanager_secret.{name}",
                "mode": "managed", "type": "aws_secretsmanager_secret",
                "name": name, "values": {"name": name}}

    def _rotation(self, secret_id):
        vals = {} if secret_id is None else {"secret_id": secret_id}
        return {"address": "aws_secretsmanager_secret_rotation.r",
                "mode": "managed",
                "type": "aws_secretsmanager_secret_rotation",
                "name": "r", "values": vals}

    def test_unknown_secret_id_does_not_false_fire(self):
        # Rotation present, secret_id computed (absent) at plan time.
        plan = _plan([self._secret("db"), self._rotation(None)])
        f = sm001.check(TerraformContext(plan))
        assert len(f) == 1
        assert f[0].passed is True
        assert "computed at apply time" in f[0].description.lower()

    def test_no_rotation_still_fires(self):
        plan = _plan([self._secret("db")])
        f = sm001.check(TerraformContext(plan))
        assert f[0].passed is False

    def test_arn_interpolation_matches(self):
        plan = _plan([
            self._secret("db"),
            self._rotation("${aws_secretsmanager_secret.db.arn}"),
        ])
        f = sm001.check(TerraformContext(plan))
        assert f[0].passed is True
        assert "matching" in f[0].description.lower()


class TestTerraformFpAndSeverityFixes:
    """Assorted terraform_c5 FP / bug fixes from the 2026-07 audit."""

    def test_tf001_emits_high_matching_rule_metadata(self):
        # The finding hardcoded CRITICAL while RULE.severity is HIGH.
        plan = _plan([{
            "address": "aws_iam_access_key.k", "mode": "managed",
            "type": "aws_iam_access_key", "name": "k",
            "values": {"user": "svc"}}])
        f = _tf001_iam_access_key(TerraformContext(plan))
        assert f and f[0].severity == Severity.HIGH

    def test_sm002_org_scoped_wildcard_passes(self):
        # Wildcard principal narrowed by aws:PrincipalOrgID is the
        # AWS-documented cross-account pattern, not world-open.
        pol = json.dumps({"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": "secretsmanager:GetSecretValue", "Resource": "*",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}}]})
        plan = _plan([{
            "address": "aws_secretsmanager_secret_policy.p", "mode": "managed",
            "type": "aws_secretsmanager_secret_policy", "name": "p",
            "values": {"policy": pol}}])
        f = sm002.check(TerraformContext(plan))
        assert f and f[0].passed is True

    def test_sm002_unconstrained_wildcard_still_fires(self):
        pol = json.dumps({"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]})
        plan = _plan([{
            "address": "aws_secretsmanager_secret_policy.p", "mode": "managed",
            "type": "aws_secretsmanager_secret_policy", "name": "p",
            "values": {"policy": pol}}])
        f = sm002.check(TerraformContext(plan))
        assert f and f[0].passed is False

    def test_ssm001_oauth_name_not_flagged(self):
        # ``AUTH`` no longer matches within ``oauth`` / ``author``.
        assert SECRET_NAME_RE.search("/app/oauth_redirect_url") is None
        assert SECRET_NAME_RE.search("author_email") is None
        plan = _plan([{
            "address": "aws_ssm_parameter.p", "mode": "managed",
            "type": "aws_ssm_parameter", "name": "p",
            "values": {"name": "/app/oauth_redirect_url", "type": "String"}}])
        assert not any(
            f.check_id == "SSM-001" for f in _ssm(TerraformContext(plan))
        )

    def test_ssm001_auth_token_still_flagged(self):
        assert SECRET_NAME_RE.search("AUTH_TOKEN") is not None
        plan = _plan([{
            "address": "aws_ssm_parameter.p", "mode": "managed",
            "type": "aws_ssm_parameter", "name": "p",
            "values": {"name": "/app/auth_token", "type": "String"}}])
        f = [f for f in _ssm(TerraformContext(plan)) if f.check_id == "SSM-001"]
        assert f and f[0].passed is False


class TestTf003SubnetScoping:
    """TF-003 failed a CodeBuild project whenever ANY subnet in its VPC
    was public, ignoring which subnets ``vpc_config.subnets`` attaches.
    """

    def _subnet(self, name, public, vpc="vpc-1"):
        return {"address": f"aws_subnet.{name}", "mode": "managed",
                "type": "aws_subnet", "name": name,
                "values": {"vpc_id": vpc,
                           "map_public_ip_on_launch": public}}

    def _codebuild(self, subnets):
        return {"address": "aws_codebuild_project.b", "mode": "managed",
                "type": "aws_codebuild_project", "name": "b",
                "values": {"name": "b", "vpc_config": [{
                    "vpc_id": "vpc-1", "subnets": subnets}]}}

    def test_private_referenced_subnet_passes_despite_public_peer(self):
        # Two-tier VPC: project attaches only the private subnet; a
        # public subnet elsewhere in the VPC must not fail the project.
        plan = _plan([
            self._subnet("priv", False),
            self._subnet("pub", True),
            self._codebuild(["${aws_subnet.priv.id}"]),
        ])
        f = [f for f in _tf003_codebuild_public_subnet(TerraformContext(plan))
             if f.check_id == "TF-003"]
        assert f and f[0].passed is True

    def test_public_referenced_subnet_fails(self):
        plan = _plan([
            self._subnet("pub", True),
            self._codebuild(["${aws_subnet.pub.id}"]),
        ])
        f = [f for f in _tf003_codebuild_public_subnet(TerraformContext(plan))
             if f.check_id == "TF-003"]
        assert f and f[0].passed is False

    def test_unresolved_subnets_fall_back_to_vpc_heuristic(self):
        # subnets computed at plan time (empty): fall back to VPC-wide.
        plan = _plan([
            self._subnet("pub", True),
            self._codebuild([]),
        ])
        f = [f for f in _tf003_codebuild_public_subnet(TerraformContext(plan))
             if f.check_id == "TF-003"]
        assert f and f[0].passed is False


def _managed(addr, rtype, name, values):
    return {"address": addr, "mode": "managed", "type": rtype,
            "name": name, "values": values}


class TestCodePipelineLowFindings:
    """2026-07 audit LOW findings on the terraform CodePipeline family."""

    def test_cp002_aws_managed_alias_is_not_customer_key(self):
        # CP-002 FN: an ``alias/aws/s3`` encryption_key is the AWS-managed
        # key, not a customer-managed one, so the store is not compliant.
        from pipeline_check.core.checks.terraform.codepipeline import (
            _cp002_artifact_encryption,
        )
        f = _cp002_artifact_encryption(
            {"artifact_store": [{"location": "b",
             "encryption_key": [{"id": "alias/aws/s3", "type": "KMS"}]}]}, "p")
        assert f.passed is False
        # a real CMK still passes
        f = _cp002_artifact_encryption(
            {"artifact_store": [{"location": "b",
             "encryption_key": [{"id": "arn:aws:kms:us-east-1:1:key/x",
                                 "type": "KMS"}]}]}, "p")
        assert f.passed is True

    def test_cp001_same_stage_parallel_approval_does_not_gate(self):
        # CP-001 FN: an Approval and Deploy in the same stage with no
        # run_order run in parallel, so the deploy is not gated.
        from pipeline_check.core.checks.terraform.codepipeline import (
            _cp001_approval_before_deploy,
        )
        stages = [{"name": "Release", "action": [
            {"name": "a", "category": "Approval", "provider": "Manual"},
            {"name": "d", "category": "Deploy"}]}]
        assert _cp001_approval_before_deploy(stages, "p").passed is False
        # a strictly-lower run_order approval in the same stage does gate
        stages = [{"name": "Release", "action": [
            {"name": "a", "category": "Approval", "run_order": 1},
            {"name": "d", "category": "Deploy", "run_order": 2}]}]
        assert _cp001_approval_before_deploy(stages, "p").passed is True

    def test_cp005_prod_stage_without_deploy_action_does_not_fire(self):
        # CP-005 FP: a prod-named stage that only runs tests is not a
        # release gate.
        from pipeline_check.core.checks.terraform.phase3 import (
            _pbac005_cp005_cp007,
        )
        r = _managed("aws_codepipeline.p", "aws_codepipeline", "p", {
            "name": "p", "role_arn": "r", "stage": [
                {"name": "ProdSmokeTests",
                 "action": [{"name": "t", "category": "Test"}]}]})
        fs = [f for f in _pbac005_cp005_cp007(TerraformContext(_plan([r])))
              if f.check_id == "CP-005"]
        assert not fs
        # a prod stage with a Deploy and no approval still fires
        r = _managed("aws_codepipeline.p", "aws_codepipeline", "p", {
            "name": "p", "role_arn": "r", "stage": [
                {"name": "Prod",
                 "action": [{"name": "d", "category": "Deploy"}]}]})
        fs = [f for f in _pbac005_cp005_cp007(TerraformContext(_plan([r])))
              if f.check_id == "CP-005"]
        assert fs and fs[0].passed is False

    def test_cp007_match_all_glob_is_open(self):
        # CP-007 FN: ``includes = ["**"]`` matches every branch.
        from pipeline_check.core.checks.terraform.phase3 import (
            _pbac005_cp005_cp007,
        )
        def _trigger(includes):
            return _managed("aws_codepipeline.p", "aws_codepipeline", "p", {
                "name": "p", "pipeline_type": "V2", "role_arn": "r",
                "stage": [], "trigger": [{
                    "provider_type": "CodeStarSourceConnection",
                    "git_configuration": [{"pull_request": [
                        {"branches": {"includes": includes}}]}]}]})
        fs = [f for f in _pbac005_cp005_cp007(
            TerraformContext(_plan([_trigger(["**"])]))) if f.check_id == "CP-007"]
        assert fs and fs[0].passed is False
        fs = [f for f in _pbac005_cp005_cp007(
            TerraformContext(_plan([_trigger(["main"])]))) if f.check_id == "CP-007"]
        assert not fs

    def test_cd002_custom_all_at_once_config_fires(self):
        # CD-002 FN: a custom deployment config with minimum_healthy_hosts
        # value 0 is semantically all-at-once.
        from pipeline_check.core.checks.terraform.rules.cd002_all_at_once import (
            check as cd002_check,
        )
        cfg = _managed(
            "aws_codedeploy_deployment_config.c",
            "aws_codedeploy_deployment_config", "c",
            {"deployment_config_name": "all-in",
             "minimum_healthy_hosts": [{"type": "HOST_COUNT", "value": 0}]})
        grp = _managed(
            "aws_codedeploy_deployment_group.g",
            "aws_codedeploy_deployment_group", "g",
            {"deployment_config_name": "all-in", "app_name": "a",
             "deployment_group_name": "g"})
        fs = [f for f in cd002_check(TerraformContext(_plan([cfg, grp])))
              if not f.passed]
        assert fs
        # a graduated custom config (value 1) does not fire
        cfg["values"]["minimum_healthy_hosts"] = [{"type": "HOST_COUNT",
                                                   "value": 1}]
        fs = [f for f in cd002_check(TerraformContext(_plan([cfg, grp])))
              if not f.passed]
        assert not fs


class TestCodeBuildLowFindings:
    """2026-07 audit LOW findings on the terraform CodeBuild rules."""

    def test_cb001_null_env_var_name_does_not_crash(self):
        from pipeline_check.core.checks.terraform.codebuild import (
            _cb001_plaintext_secrets,
        )
        f = _cb001_plaintext_secrets(
            {"environment": [{"environment_variable": [
                {"name": None, "value": "x"}]}]}, "a")
        assert f.check_id == "CB-001"  # no TypeError

    def test_cb009_unresolved_image_reference_not_asserted_pinned(self):
        from pipeline_check.core.checks.terraform.extended import _cb009
        f = _cb009({"environment": [{"image": "${var.build_image}"}]}, "addr")
        assert f.passed is True
        assert "unresolved" in f.description
        # a real tag image still fails
        f2 = _cb009({"environment": [{"image": "myrepo/img:1.0"}]}, "addr")
        assert f2.passed is False

    def test_cb004_timeout_fire_and_pass(self):
        from pipeline_check.core.checks.terraform.codebuild import (
            _cb004_timeout,
        )
        # unset timeout fires
        assert _cb004_timeout({}, "a").passed is False
        # >= 480 fires
        assert _cb004_timeout({"build_timeout": 480}, "a").passed is False
        # a sensible value passes
        assert _cb004_timeout({"build_timeout": 60}, "a").passed is True

    def test_cb005_outdated_image_fire_and_pass(self):
        from pipeline_check.core.checks.terraform.codebuild import (
            _cb005_image_version,
        )
        outdated = {"environment": [{"image": "aws/codebuild/standard:5.0"}]}
        assert _cb005_image_version(outdated, "a").passed is False
        current = {"environment": [{"image": "aws/codebuild/standard:7.0"}]}
        assert _cb005_image_version(current, "a").passed is True


class TestTerraformC3LowFindings:
    """2026-07 audit LOW findings (terraform_c3 chunk)."""

    def test_iam001_govcloud_partition_admin_arn(self):
        from pipeline_check.core.checks.terraform.iam import _iam001_admin_access
        gov = _iam001_admin_access(
            ["arn:aws-us-gov:iam::aws:policy/AdministratorAccess"], "ci")
        assert gov.passed is False
        china = _iam001_admin_access(
            ["arn:aws-cn:iam::aws:policy/AdministratorAccess"], "ci")
        assert china.passed is False
        clean = _iam001_admin_access(
            ["arn:aws:iam::aws:policy/ReadOnlyAccess"], "ci")
        assert clean.passed is True

    def test_ecr005_kms_dsse_is_customer_managed(self):
        from pipeline_check.core.checks.terraform.ecr import _ecr005_kms_encryption
        dsse = _ecr005_kms_encryption(
            {"encryption_configuration": [
                {"encryption_type": "KMS_DSSE",
                 "kms_key": "arn:aws:kms:us-east-1:1:key/k"}]}, "r")
        assert dsse.passed is True
        aes = _ecr005_kms_encryption(
            {"encryption_configuration": [{"encryption_type": "AES256"}]}, "r")
        assert aes.passed is False

    def test_ecr002_immutable_with_exclusion_description(self):
        from pipeline_check.core.checks.terraform.ecr import _ecr002_tag_mutability
        f = _ecr002_tag_mutability(
            {"image_tag_mutability": "IMMUTABLE_WITH_EXCLUSION"}, "r")
        assert f.passed is False
        assert "IMMUTABLE_WITH_EXCLUSION" in f.description

    def test_cwl_name_prefix_log_group_inspected(self):
        from pipeline_check.core.checks.terraform.base import TerraformContext
        from pipeline_check.core.checks.terraform.extended import _cw_logs_checks
        plan = _plan([{
            "address": "aws_cloudwatch_log_group.g", "mode": "managed",
            "type": "aws_cloudwatch_log_group", "name": "g",
            "values": {"name_prefix": "/aws/codebuild/app-"},
        }])
        fs = [f for f in _cw_logs_checks(TerraformContext(plan))
              if f.check_id.startswith("CWL")]
        assert {f.check_id for f in fs} == {"CWL-001", "CWL-002"}
        assert all(f.passed is False for f in fs)


class TestS3002NonListRuleGuard:
    """2026-07 audit LOW: S3-002 crashed on a non-list ``rule`` value."""

    def test_scalar_and_dict_rule_do_not_crash(self):
        from pipeline_check.core.checks.terraform.s3 import _s3002_encryption
        # a bare string used to raise AttributeError, a dict KeyError.
        assert _s3002_encryption({"bucket": "b", "rule": "x"}, "b").passed is False
        assert _s3002_encryption(
            {"bucket": "b", "rule": {"apply_server_side_encryption_by_default": []}},
            "b").passed is False
        # the normal list form still evaluates correctly
        ok = _s3002_encryption({"bucket": "b", "rule": [
            {"apply_server_side_encryption_by_default": [
                {"sse_algorithm": "aws:kms"}]}]}, "b")
        assert ok.passed is True
