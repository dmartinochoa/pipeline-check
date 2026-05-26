"""Performance benchmark gate, replaces the older smoke test.

Two layered guards:

1. **Absolute ceilings.** Median wall time on a 1000-line synthetic
   GHA workflow and a 5000-line synthetic CFN template stays under
   a generously padded ceiling, so a catastrophic regression (a
   per-step regex compile, an O(n) rule that becomes O(n²)) trips
   the test even without a saved baseline. Ceilings are sized for
   slow CI runners; locally each scan completes in well under a
   second.

2. **pytest-benchmark statistical aggregation.** Each scan runs
   under the ``benchmark`` fixture, so the run output includes
   warmup-corrected median, ops/sec, and a baseline-comparison
   line that ``pytest --benchmark-compare`` can pick up.

To detect a 25% regression against a saved per-machine baseline:

    # First run: save the baseline JSON.
    pytest tests/perf/test_benchmark.py --benchmark-autosave

    # Later runs: fail if median regresses past 25% of baseline.
    pytest tests/perf/test_benchmark.py \\
        --benchmark-compare --benchmark-compare-fail=median:25%

CI doesn't save baselines (they'd be runner-specific and would
flap as GitHub-hosted runner hardware shifts); the absolute
ceilings above are what gate the build.

The synthetic input sizes (1000-line GHA, 5000-line CFN) match
the v0.4.0 roadmap commitment.
"""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.cloudformation.base import (
    CloudFormationContext,
)
from pipeline_check.core.checks.cloudformation.iam import IAMChecks
from pipeline_check.core.checks.cloudformation.s3 import S3Checks
from pipeline_check.core.checks.cloudformation.services import ServiceChecks
from pipeline_check.core.checks.github.base import GitHubContext, Workflow
from pipeline_check.core.checks.github.workflows import WorkflowChecks

# Generous ceilings, sized for slow CI. Local runs land an order of
# magnitude under these. The goal here is to catch order-of-magnitude
# regressions without taking on test flakiness; the linear-scaling
# guard below provides the tighter, runner-independent floor on
# algorithmic regressions.
_GHA_1000_LINES_CEILING_S = 5.0
_CFN_5000_LINES_CEILING_S = 8.0

# Each job in ``_synthetic_gha_workflow`` serializes to ~12 YAML
# lines (job name + runs-on + timeout + permissions + 4 steps with
# uses/with/run/env). 83 jobs ≈ 1000 lines of YAML; 250 jobs ≈
# 3000 lines for the scaling reference.
_GHA_LINES_PER_JOB = 12
_GHA_TARGET_LINES = 1000
_GHA_NUM_JOBS = _GHA_TARGET_LINES // _GHA_LINES_PER_JOB

# Each CFN resource serializes to ~10 YAML lines (logical id +
# Type + Properties block with 4-6 keys). 500 resources ≈ 5000
# lines of CFN; 167 resources ≈ 1670 lines for the scaling ref.
_CFN_LINES_PER_RESOURCE = 10
_CFN_TARGET_LINES = 5000
_CFN_NUM_RESOURCES = _CFN_TARGET_LINES // _CFN_LINES_PER_RESOURCE


def _synthetic_gha_workflow(num_jobs: int) -> dict[str, Any]:
    """Build a workflow doc with ``num_jobs`` jobs, each with 4 steps.

    Mix of pinned actions, run steps, env blocks. Exercises the
    canonical rule surface (pinning, secrets, OIDC, container
    options, package integrity).
    """
    jobs: dict[str, Any] = {}
    for i in range(num_jobs):
        jobs[f"job{i}"] = {
            "runs-on": "ubuntu-22.04",
            "timeout-minutes": 10,
            "permissions": {"contents": "read", "id-token": "write"},
            "steps": [
                {
                    "uses": (
                        "actions/checkout@"
                        "a5ac7e51b41094c92402da3b24376905380afc29"
                    ),
                },
                {
                    "uses": "actions/setup-python@v5.1.0",
                    "with": {"python-version": "3.12"},
                },
                {"run": "pip install --require-hashes -r requirements.txt"},
                {
                    "run": "pytest -q",
                    "env": {"PYTHONHASHSEED": "0"},
                },
            ],
        }
    return {
        "name": "synthetic",
        "on": {"push": {"branches": ["main"]}},
        "jobs": jobs,
    }


def _synthetic_cfn_template(num_resources: int) -> dict[str, Any]:
    """Build a CFN template doc with ``num_resources`` resources.

    Mix of IAM roles, S3 buckets, and Lambda functions. Each
    carries enough Properties to exercise the IAM, S3, and
    services rule packs without short-circuiting on missing
    fields.
    """
    resources: dict[str, Any] = {}
    for i in range(num_resources):
        kind = i % 3
        if kind == 0:
            resources[f"Role{i}"] = {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"role-{i}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/AWSLambdaBasicExecutionRole",
                    ],
                    "Tags": [{"Key": "env", "Value": "perf"}],
                },
            }
        elif kind == 1:
            resources[f"Bucket{i}"] = {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": f"perf-bucket-{i}",
                    "BucketEncryption": {
                        "ServerSideEncryptionConfiguration": [{
                            "ServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256",
                            },
                        }],
                    },
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True,
                    },
                    "Tags": [{"Key": "env", "Value": "perf"}],
                },
            }
        else:
            resources[f"Function{i}"] = {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": f"perf-fn-{i}",
                    "Runtime": "python3.12",
                    "Handler": "app.handler",
                    "Role": {"Fn::GetAtt": [f"Role{i - 1}", "Arn"]},
                    "Code": {"ZipFile": "def handler(e, c): return e"},
                    "Tags": [{"Key": "env", "Value": "perf"}],
                },
            }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "synthetic perf template",
        "Resources": resources,
    }


def _scan_gha(num_jobs: int) -> int:
    """Scan a synthetic GHA workflow; return finding count."""
    doc = _synthetic_gha_workflow(num_jobs)
    ctx = GitHubContext([Workflow(path="wf.yml", data=doc)])
    return len(WorkflowChecks(ctx).run())


def _scan_cfn(num_resources: int) -> int:
    """Scan a synthetic CFN template; return finding count.

    Runs a representative subset of CFN check classes (IAM, S3,
    services) rather than the full pack so the benchmark stays
    focused on rule-pack throughput, not wall-clock-bound network
    or filesystem work that other rule classes might add later.
    """
    doc = _synthetic_cfn_template(num_resources)
    ctx = CloudFormationContext([("template.yaml", doc)])
    findings = []
    for cls in (IAMChecks, S3Checks, ServiceChecks):
        findings.extend(cls(ctx).run())
    return len(findings)


def test_gha_1000_line_scan_under_ceiling(benchmark: Any) -> None:
    """Median time to scan a 1000-line GHA workflow stays under the ceiling."""
    benchmark.pedantic(
        _scan_gha,
        args=(_GHA_NUM_JOBS,),
        rounds=3,
        iterations=1,
        warmup_rounds=1,
    )
    if benchmark.stats is None:
        return
    median = benchmark.stats.stats.median
    assert median < _GHA_1000_LINES_CEILING_S, (
        f"GHA scan of {_GHA_NUM_JOBS} jobs (~{_GHA_TARGET_LINES} lines) "
        f"took median {median:.2f}s; ceiling is "
        f"{_GHA_1000_LINES_CEILING_S:.1f}s. Investigate which rule "
        f"regressed (try bisecting WorkflowChecks._discover_rules)."
    )


def test_cfn_5000_line_scan_under_ceiling(benchmark: Any) -> None:
    """Median time to scan a 5000-line CFN template stays under the ceiling."""
    benchmark.pedantic(
        _scan_cfn,
        args=(_CFN_NUM_RESOURCES,),
        rounds=3,
        iterations=1,
        warmup_rounds=1,
    )
    if benchmark.stats is None:
        return
    median = benchmark.stats.stats.median
    assert median < _CFN_5000_LINES_CEILING_S, (
        f"CFN scan of {_CFN_NUM_RESOURCES} resources (~{_CFN_TARGET_LINES} "
        f"lines) took median {median:.2f}s; ceiling is "
        f"{_CFN_5000_LINES_CEILING_S:.1f}s."
    )


