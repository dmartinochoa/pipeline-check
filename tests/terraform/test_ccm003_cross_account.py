"""Terraform CCM-003 — a literal codecommit trigger destination_arn fires
only when it is provably cross-account.

Regression for the audit false positive where *every* literal ARN was
flagged, including same-account destinations (the rule title is
"different account").
"""
from __future__ import annotations

from pipeline_check.core.checks.terraform.base import TerraformContext
from pipeline_check.core.checks.terraform.services import ServiceChecks


def _r(addr, rtype, name, values, mode="managed"):
    return {"address": addr, "mode": mode, "type": rtype, "name": name,
            "values": values}


def _run(resources):
    plan = {"planned_values": {"root_module": {"resources": resources,
                                               "child_modules": []}}}
    return [f for f in ServiceChecks(TerraformContext(plan)).run()
            if f.check_id == "CCM-003"]


def _trigger(dest):
    return _r("aws_codecommit_trigger.t", "aws_codecommit_trigger", "t", {
        "trigger": [{"name": "on-push", "events": ["all"],
                     "destination_arn": dest}],
    })


def _caller_identity(account):
    return _r("data.aws_caller_identity.current", "aws_caller_identity",
              "current", {"account_id": account, "id": account}, mode="data")


def test_cross_account_literal_fires():
    # caller_identity resolves the home account to 111111111111; the
    # trigger destination is in 999988887777.
    out = _run([
        _caller_identity("111111111111"),
        _trigger("arn:aws:sns:us-east-1:999988887777:repo-events"),
    ])
    assert out and out[0].passed is False


def test_same_account_literal_passes():
    # The literal destination is in the same account caller_identity
    # reports — this is the false positive the old check produced.
    out = _run([
        _caller_identity("111111111111"),
        _trigger("arn:aws:sns:us-east-1:111111111111:repo-events"),
    ])
    assert out and out[0].passed is True


def test_same_account_via_sibling_arn_passes():
    # No caller_identity, but a sibling managed resource carries a literal
    # ARN in 111111111111, so the home account is derivable from the plan.
    out = _run([
        _r("aws_iam_role.build", "aws_iam_role", "build",
           {"arn": "arn:aws:iam::111111111111:role/build"}),
        _trigger("arn:aws:sns:us-east-1:111111111111:repo-events"),
    ])
    assert out and out[0].passed is True


def test_uncorrelatable_literal_passes():
    # No caller_identity and no in-account ARN anywhere: cross-account
    # membership can't be proven, so don't fail on the literal.
    out = _run([_trigger("arn:aws:sns:us-east-1:123456789012:my-topic")])
    assert out and out[0].passed is True


def test_reference_destination_passes():
    out = _run([_trigger("${aws_sns_topic.repo_events.arn}")])
    assert out and out[0].passed is True
