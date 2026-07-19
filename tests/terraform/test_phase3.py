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


def _codebuild_vpc(sg_name):
    # A VPC-configured CodeBuild project that attaches ``sg_name``.
    return _r("aws_codebuild_project.p", "aws_codebuild_project", "p", {
        "name": "p",
        "vpc_config": [{
            "vpc_id": "vpc-1",
            "security_group_ids": [f"${{aws_security_group.{sg_name}.id}}"],
            "subnets": [],
        }],
    })


def test_pbac003_open_egress_fails():
    sg = _r("aws_security_group.build", "aws_security_group", "build", {
        "egress": [{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}],
    })
    f = next(
        x for x in _run([sg, _codebuild_vpc("build")])
        if x.check_id == "PBAC-003"
    )
    assert not f.passed


def test_pbac003_scoped_egress_passes():
    sg = _r("aws_security_group.build", "aws_security_group", "build", {
        "egress": [{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["10.0.0.0/8"]}],
    })
    assert not any(
        x.check_id == "PBAC-003"
        for x in _run([sg, _codebuild_vpc("build")])
    )


def test_pbac003_no_codebuild_does_not_fire():
    # Regression (2026-07 audit, PBAC-003): an open-egress SG on an
    # unrelated ALB/EC2 stack with no VPC-configured CodeBuild project
    # must NOT fire — the rule is CodeBuild-scoped.
    sg = _r("aws_security_group.alb", "aws_security_group", "alb", {
        "egress": [{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}],
    })
    assert not any(x.check_id == "PBAC-003" for x in _run([sg]))


def test_pbac003_unattached_sg_not_flagged():
    # When CodeBuild attaches a resolvable SG, an open-egress SG it does
    # NOT attach is out of scope.
    attached = _r("aws_security_group.build", "aws_security_group", "build", {
        "egress": [{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["10.0.0.0/8"]}],
    })
    other = _r("aws_security_group.alb", "aws_security_group", "alb", {
        "egress": [{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}],
    })
    findings = _run([attached, other, _codebuild_vpc("build")])
    assert not any(x.check_id == "PBAC-003" for x in findings)


def test_pbac005_shared_role_fails():
    pipeline = _r("aws_codepipeline.p", "aws_codepipeline", "p", {
        "name": "p", "role_arn": "arn:aws:iam::1:role/top",
        "stage": [{"action": [{"name": "Build", "role_arn": "arn:aws:iam::1:role/top"}]}],
    })
    f = next(x for x in _run([pipeline]) if x.check_id == "PBAC-005")
    assert not f.passed


def _plan_with_changes(resources, resource_changes):
    return {"planned_values": {"root_module": {
        "resources": resources, "child_modules": []}},
        "resource_changes": resource_changes}


def test_pbac005_unknown_action_role_arn_does_not_false_fire():
    # Regression (2026-07 audit, PBAC-005): per-action role_arn is a
    # computed value (aws_iam_role.x.arn) omitted from planned_values on
    # a fresh plan. after_unknown flags it, so it must read as scoped,
    # not as "all actions inherit the pipeline role".
    pipeline = _r("aws_codepipeline.p", "aws_codepipeline", "p", {
        "name": "p", "role_arn": "arn:aws:iam::1:role/top",
        "stage": [
            {"action": [{"name": "Build"}]},
            {"action": [{"name": "Deploy"}]},
        ],
    })
    changes = [{
        "address": "aws_codepipeline.p",
        "type": "aws_codepipeline",
        "change": {"after_unknown": {"stage": [
            {"action": [{"role_arn": True}]},
            {"action": [{"role_arn": True}]},
        ]}},
    }]
    ctx = TerraformContext(_plan_with_changes([pipeline], changes))
    f = next(x for x in Phase3Checks(ctx).run() if x.check_id == "PBAC-005")
    assert f.passed


def test_pbac005_genuinely_shared_role_still_fails_with_changes():
    # after_unknown present but role_arn known and == pipeline role:
    # the real misconfiguration must still fire.
    pipeline = _r("aws_codepipeline.p", "aws_codepipeline", "p", {
        "name": "p", "role_arn": "arn:aws:iam::1:role/top",
        "stage": [{"action": [
            {"name": "Build", "role_arn": "arn:aws:iam::1:role/top"}]}],
    })
    changes = [{
        "address": "aws_codepipeline.p", "type": "aws_codepipeline",
        "change": {"after_unknown": {"stage": [{"action": [{"name": False}]}]}},
    }]
    ctx = TerraformContext(_plan_with_changes([pipeline], changes))
    f = next(x for x in Phase3Checks(ctx).run() if x.check_id == "PBAC-005")
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
