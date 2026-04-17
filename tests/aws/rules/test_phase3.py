"""Phase-3 deeper detections: ECR-006/007, SIGN-001/002, EB-001/002, CW-001, PBAC-003/005, CP-005/007."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

from pipeline_check.core.checks.aws.rules import (
    cp005_production_approval,
    cp007_v2_all_branches,
    cw001_failed_build_alarm,
    eb001_pipeline_failure_rule,
    eb002_wildcard_target,
    ecr006_pull_through_untrusted,
    ecr007_inspector_enhanced,
    pbac003_sg_egress,
    pbac005_stage_role_reuse,
    sign001_profile_exists,
    sign002_profile_revoked,
)
from tests.aws.rules.conftest import FakeClient

# ---------- ECR-006 ----------

def test_ecr006_untrusted_fails(make_catalog):
    client = FakeClient()
    client._responses["describe_pull_through_cache_rules"] = {
        "pullThroughCacheRules": [
            {"ecrRepositoryPrefix": "docker", "upstreamRegistryUrl": "registry-1.docker.io"},
        ]
    }
    cat = make_catalog(ecr=client)
    assert ecr006_pull_through_untrusted.check(cat)[0].passed is False


def test_ecr006_trusted_passes(make_catalog):
    client = FakeClient()
    client._responses["describe_pull_through_cache_rules"] = {
        "pullThroughCacheRules": [
            {"ecrRepositoryPrefix": "k8s", "upstreamRegistryUrl": "registry.k8s.io"},
        ]
    }
    cat = make_catalog(ecr=client)
    assert ecr006_pull_through_untrusted.check(cat)[0].passed is True


def test_ecr006_with_credential_passes(make_catalog):
    client = FakeClient()
    client._responses["describe_pull_through_cache_rules"] = {
        "pullThroughCacheRules": [{
            "ecrRepositoryPrefix": "private",
            "upstreamRegistryUrl": "my-registry.example",
            "credentialArn": "arn:aws:secretsmanager:::reg-creds",
        }]
    }
    cat = make_catalog(ecr=client)
    assert ecr006_pull_through_untrusted.check(cat)[0].passed is True


# ---------- ECR-007 ----------

def test_ecr007_disabled_fails(make_catalog):
    client = MagicMock()
    client.batch_get_account_status.return_value = {"accounts": [{
        "accountId": "1",
        "resourceState": {"ecr": {"status": "DISABLED"}},
    }]}
    cat = make_catalog(inspector2=client)
    assert ecr007_inspector_enhanced.check(cat)[0].passed is False


def test_ecr007_enabled_passes(make_catalog):
    client = MagicMock()
    client.batch_get_account_status.return_value = {"accounts": [{
        "accountId": "1",
        "resourceState": {"ecr": {"status": "ENABLED"}},
    }]}
    cat = make_catalog(inspector2=client)
    assert ecr007_inspector_enhanced.check(cat)[0].passed is True


# ---------- SIGN-001 ----------

def test_sign001_no_profiles_fails(make_catalog):
    client = MagicMock()
    client.list_signing_profiles.return_value = {"profiles": []}
    cat = make_catalog(signer=client)
    assert sign001_profile_exists.check(cat)[0].passed is False


def test_sign001_active_lambda_profile_passes(make_catalog):
    client = MagicMock()
    client.list_signing_profiles.return_value = {"profiles": [{
        "profileName": "p", "platformId": "AWSLambda-SHA384-ECDSA", "status": "Active",
    }]}
    cat = make_catalog(signer=client)
    assert sign001_profile_exists.check(cat)[0].passed is True


# ---------- SIGN-002 ----------

def test_sign002_revoked_fails(make_catalog):
    client = MagicMock()
    client.list_signing_profiles.return_value = {"profiles": [{
        "profileName": "p", "status": "Revoked",
    }]}
    cat = make_catalog(signer=client)
    assert sign002_profile_revoked.check(cat)[0].passed is False


def test_sign002_active_only_skipped(make_catalog):
    client = MagicMock()
    client.list_signing_profiles.return_value = {"profiles": [{
        "profileName": "p", "status": "Active",
    }]}
    cat = make_catalog(signer=client)
    assert sign002_profile_revoked.check(cat) == []


# ---------- EB-001 ----------

def test_eb001_no_rule_fails(make_catalog):
    client = FakeClient()
    client.set_paginator("list_rules", [{"Rules": []}])
    cat = make_catalog(events=client)
    assert eb001_pipeline_failure_rule.check(cat)[0].passed is False


def test_eb001_with_rule_passes(make_catalog):
    pattern = json.dumps({
        "detail-type": ["CodePipeline Pipeline Execution State Change"],
        "detail": {"state": ["FAILED"]},
    })
    client = FakeClient()
    client.set_paginator("list_rules", [{"Rules": [{"Name": "r", "EventPattern": pattern}]}])
    cat = make_catalog(events=client)
    assert eb001_pipeline_failure_rule.check(cat)[0].passed is True


# ---------- EB-002 ----------

def test_eb002_wildcard_target_fails(make_catalog):
    client = FakeClient()
    client.set_paginator("list_rules", [{"Rules": [{"Name": "r"}]}])
    client._responses["list_targets_by_rule"] = {"Targets": [
        {"Id": "t", "Arn": "arn:aws:lambda:us-east-1:1:function:*"},
    ]}
    cat = make_catalog(events=client)
    assert eb002_wildcard_target.check(cat)[0].passed is False


def test_eb002_specific_target_passes(make_catalog):
    client = FakeClient()
    client.set_paginator("list_rules", [{"Rules": [{"Name": "r"}]}])
    client._responses["list_targets_by_rule"] = {"Targets": [
        {"Id": "t", "Arn": "arn:aws:lambda:us-east-1:1:function:worker"},
    ]}
    cat = make_catalog(events=client)
    assert eb002_wildcard_target.check(cat) == []


# ---------- CW-001 ----------

def test_cw001_no_alarm_fails(make_catalog):
    client = MagicMock()
    client.describe_alarms.return_value = {"MetricAlarms": []}
    cat = make_catalog(cloudwatch=client)
    assert cw001_failed_build_alarm.check(cat)[0].passed is False


def test_cw001_has_alarm_passes(make_catalog):
    client = MagicMock()
    client.describe_alarms.return_value = {"MetricAlarms": [{
        "Namespace": "AWS/CodeBuild", "MetricName": "FailedBuilds",
    }]}
    cat = make_catalog(cloudwatch=client)
    assert cw001_failed_build_alarm.check(cat)[0].passed is True


# ---------- PBAC-003 ----------

def test_pbac003_open_egress_fails(make_catalog):
    cb = FakeClient(batch_get_projects={"projects": [
        {"name": "p", "vpcConfig": {"securityGroupIds": ["sg-1"]}},
    ]})
    cb.set_paginator("list_projects", [{"projects": ["p"]}])
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {"SecurityGroups": [{
        "GroupId": "sg-1",
        "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    }]}
    cat = make_catalog(codebuild=cb, ec2=ec2)
    findings = pbac003_sg_egress.check(cat)
    assert findings and findings[0].passed is False


def test_pbac003_scoped_egress_passes(make_catalog):
    cb = FakeClient(batch_get_projects={"projects": [
        {"name": "p", "vpcConfig": {"securityGroupIds": ["sg-1"]}},
    ]})
    cb.set_paginator("list_projects", [{"projects": ["p"]}])
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {"SecurityGroups": [{
        "GroupId": "sg-1",
        "IpPermissionsEgress": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                                  "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}],
    }]}
    cat = make_catalog(codebuild=cb, ec2=ec2)
    assert pbac003_sg_egress.check(cat) == []


# ---------- PBAC-005 ----------

def _pipeline_client(pipeline):
    client = FakeClient()
    client.set_paginator("list_pipelines", [{"pipelines": [{"name": pipeline.get("name", "p")}]}])
    client._responses["get_pipeline"] = {"pipeline": pipeline}
    return client


def test_pbac005_shared_role_fails(make_catalog):
    pipeline = {
        "name": "p", "roleArn": "arn:aws:iam::1:role/top",
        "stages": [{"actions": [{"name": "Build", "actionTypeId": {}, "roleArn": "arn:aws:iam::1:role/top"}]}],
    }
    cat = make_catalog(codepipeline=_pipeline_client(pipeline))
    assert pbac005_stage_role_reuse.check(cat)[0].passed is False


def test_pbac005_per_action_role_passes(make_catalog):
    pipeline = {
        "name": "p", "roleArn": "arn:aws:iam::1:role/top",
        "stages": [{"actions": [{"name": "Build", "actionTypeId": {}, "roleArn": "arn:aws:iam::1:role/build"}]}],
    }
    cat = make_catalog(codepipeline=_pipeline_client(pipeline))
    assert pbac005_stage_role_reuse.check(cat)[0].passed is True


# ---------- CP-005 ----------

def test_cp005_production_no_approval_fails(make_catalog):
    pipeline = {
        "name": "p",
        "stages": [
            {"name": "Source", "actions": [{"name": "Src", "actionTypeId": {}}]},
            {"name": "DeployProd", "actions": [{"name": "Deploy", "actionTypeId": {}}]},
        ],
    }
    cat = make_catalog(codepipeline=_pipeline_client(pipeline))
    findings = cp005_production_approval.check(cat)
    assert findings and findings[0].passed is False


def test_cp005_production_with_approval_skipped(make_catalog):
    pipeline = {
        "name": "p",
        "stages": [
            {"name": "Source", "actions": [{"name": "Src", "actionTypeId": {}}]},
            {"name": "Approve", "actions": [{
                "name": "Approve",
                "actionTypeId": {"category": "Approval", "provider": "Manual"},
            }]},
            {"name": "DeployProd", "actions": [{"name": "Deploy", "actionTypeId": {}}]},
        ],
    }
    cat = make_catalog(codepipeline=_pipeline_client(pipeline))
    assert cp005_production_approval.check(cat) == []


# ---------- CP-007 ----------

def test_cp007_v2_open_pr_fails(make_catalog):
    pipeline = {
        "name": "p", "pipelineType": "V2",
        "triggers": [{
            "providerType": "CodeStarSourceConnection",
            "gitConfiguration": {"pullRequest": [{"branches": {"includes": ["*"]}}]},
        }],
        "stages": [],
    }
    cat = make_catalog(codepipeline=_pipeline_client(pipeline))
    assert cp007_v2_all_branches.check(cat)[0].passed is False


def test_cp007_v2_scoped_pr_passes(make_catalog):
    pipeline = {
        "name": "p", "pipelineType": "V2",
        "triggers": [{
            "providerType": "CodeStarSourceConnection",
            "gitConfiguration": {"pullRequest": [{"branches": {"includes": ["main"]}}]},
        }],
        "stages": [],
    }
    cat = make_catalog(codepipeline=_pipeline_client(pipeline))
    assert cp007_v2_all_branches.check(cat) == []


def test_cp007_v1_pipeline_skipped(make_catalog):
    pipeline = {"name": "p", "pipelineType": "V1", "stages": []}
    cat = make_catalog(codepipeline=_pipeline_client(pipeline))
    assert cp007_v2_all_branches.check(cat) == []
