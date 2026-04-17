"""Phase-3 Terraform parity tests."""
from __future__ import annotations

import json

from pipeline_check.core.checks.terraform.base import TerraformContext
from pipeline_check.core.checks.terraform.phase3 import Phase3Checks


def _plan(resources):
    return {"planned_values": {"root_module": {"resources": resources, "child_modules": []}}}


def _r(addr, rtype, name, values):
    return {"address": addr, "mode": "managed", "type": rtype, "name": name, "values": values}


def _run(resources):
    return Phase3Checks(TerraformContext(_plan(resources))).run()


def test_ecr006_docker_hub_fails():
    r = _r("aws_ecr_pull_through_cache_rule.d", "aws_ecr_pull_through_cache_rule", "d", {
        "upstream_registry_url": "registry-1.docker.io",
    })
    f = next(x for x in _run([r]) if x.check_id == "ECR-006")
    assert not f.passed


def test_ecr006_k8s_passes():
    r = _r("aws_ecr_pull_through_cache_rule.k", "aws_ecr_pull_through_cache_rule", "k", {
        "upstream_registry_url": "registry.k8s.io",
    })
    f = next(x for x in _run([r]) if x.check_id == "ECR-006")
    assert f.passed


def test_pbac003_open_egress_fails():
    sg = _r("aws_security_group.sg", "aws_security_group", "sg", {
        "egress": [{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}],
    })
    f = next(x for x in _run([sg]) if x.check_id == "PBAC-003")
    assert not f.passed


def test_pbac003_scoped_egress_passes():
    sg = _r("aws_security_group.sg", "aws_security_group", "sg", {
        "egress": [{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["10.0.0.0/8"]}],
    })
    assert not any(x.check_id == "PBAC-003" for x in _run([sg]))


def test_pbac005_shared_role_fails():
    pipeline = _r("aws_codepipeline.p", "aws_codepipeline", "p", {
        "name": "p", "role_arn": "arn:aws:iam::1:role/top",
        "stage": [{"action": [{"name": "Build", "role_arn": "arn:aws:iam::1:role/top"}]}],
    })
    f = next(x for x in _run([pipeline]) if x.check_id == "PBAC-005")
    assert not f.passed


def test_pbac005_scoped_passes():
    pipeline = _r("aws_codepipeline.p", "aws_codepipeline", "p", {
        "name": "p", "role_arn": "arn:aws:iam::1:role/top",
        "stage": [{"action": [{"name": "Build", "role_arn": "arn:aws:iam::1:role/build"}]}],
    })
    f = next(x for x in _run([pipeline]) if x.check_id == "PBAC-005")
    assert f.passed


def test_cp005_prod_no_approval_fails():
    pipeline = _r("aws_codepipeline.p", "aws_codepipeline", "p", {
        "name": "p",
        "stage": [
            {"name": "Source", "action": [{"name": "s"}]},
            {"name": "DeployProd", "action": [{"name": "d", "category": "Deploy"}]},
        ],
    })
    assert any(x.check_id == "CP-005" for x in _run([pipeline]))


def test_cp005_prod_with_approval_skipped():
    pipeline = _r("aws_codepipeline.p", "aws_codepipeline", "p", {
        "name": "p",
        "stage": [
            {"name": "Source", "action": [{"name": "s"}]},
            {"name": "Approve", "action": [{"name": "a", "category": "Approval", "provider": "Manual"}]},
            {"name": "DeployProd", "action": [{"name": "d", "category": "Deploy"}]},
        ],
    })
    assert not any(x.check_id == "CP-005" for x in _run([pipeline]))


def test_cp007_v2_open_pr_fails():
    pipeline = _r("aws_codepipeline.p", "aws_codepipeline", "p", {
        "name": "p", "pipeline_type": "V2",
        "trigger": [{
            "provider_type": "CodeStarSourceConnection",
            "git_configuration": [{"pull_request": [{"branches": [{"includes": ["*"]}]}]}],
        }],
        "stage": [],
    })
    f = next(x for x in _run([pipeline]) if x.check_id == "CP-007")
    assert not f.passed


def test_eb001_with_matching_rule_passes():
    doc = json.dumps({"detail-type": ["CodePipeline Pipeline Execution State Change"], "detail": {"state": ["FAILED"]}})
    rule = _r("aws_cloudwatch_event_rule.r", "aws_cloudwatch_event_rule", "r", {"event_pattern": doc})
    f = next(x for x in _run([rule]) if x.check_id == "EB-001")
    assert f.passed


def test_eb001_no_matching_rule_fails():
    doc = json.dumps({"detail-type": ["EC2 Instance State-change Notification"]})
    rule = _r("aws_cloudwatch_event_rule.r", "aws_cloudwatch_event_rule", "r", {"event_pattern": doc})
    f = next(x for x in _run([rule]) if x.check_id == "EB-001")
    assert not f.passed


def test_eb001_no_event_rules_skipped():
    assert not any(x.check_id == "EB-001" for x in _run([]))
