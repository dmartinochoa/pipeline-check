"""Integration-test fixtures for LocalStack-backed pytest suites.

Integration tests are gated by the ``AWS_ENDPOINT_URL`` environment variable.
When it is unset, every test in ``tests/integration/`` is skipped. Set it to
your LocalStack URL (typically ``http://localhost:4566``) to run the suite:

    AWS_ENDPOINT_URL=http://localhost:4566 \\
    AWS_ACCESS_KEY_ID=test \\
    AWS_SECRET_ACCESS_KEY=test \\
    AWS_DEFAULT_REGION=us-east-1 \\
    pytest tests/integration/ -v

boto3 >=1.28 honours ``AWS_ENDPOINT_URL`` automatically, so no boto3 client
in the scanner or in these tests needs explicit endpoint configuration.
"""

from __future__ import annotations

import json
import os
import uuid
from contextlib import suppress

import boto3
import pytest
from botocore.exceptions import ClientError

ENDPOINT_URL = os.environ.get("AWS_ENDPOINT_URL")
REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

_CB_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "codebuild.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}


def _safe(fn, *args, **kwargs):
    with suppress(ClientError):
        fn(*args, **kwargs)


def pytest_collection_modifyitems(config, items):
    """Skip every test under tests/integration/ when LocalStack isn't configured."""
    skip_marker = pytest.mark.skip(
        reason="AWS_ENDPOINT_URL not set — LocalStack is required for integration tests"
    )
    if ENDPOINT_URL:
        return
    for item in items:
        if "tests/integration" in str(item.fspath).replace("\\", "/"):
            item.add_marker(skip_marker)


@pytest.fixture(scope="session")
def run_id() -> str:
    """Short unique suffix so parallel runs don't collide on resource names."""
    return uuid.uuid4().hex[:8]


@pytest.fixture(scope="session")
def ls_session() -> boto3.Session:
    """A boto3 Session that resolves against LocalStack via AWS_ENDPOINT_URL."""
    return boto3.Session(
        region_name=REGION,
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
    )


# ---------------------------------------------------------------------------
# Shared resource fixtures — promoted here so both the per-service test classes
# and the end-to-end Scanner tests can request them.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def insecure_role(ls_session: boto3.Session, run_id: str):
    iam = ls_session.client("iam")
    role_name = f"pc-cb-bad-{run_id}"
    try:
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(_CB_TRUST),
        )
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="WildcardInline",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                }],
            }),
        )
        yield role_name
    finally:
        _safe(iam.delete_role_policy, RoleName=role_name, PolicyName="WildcardInline")
        _safe(iam.delete_role, RoleName=role_name)


@pytest.fixture(scope="session")
def insecure_repo(ls_session: boto3.Session, run_id: str):
    ecr = ls_session.client("ecr")
    name = f"pc-bad-{run_id}"
    try:
        ecr.create_repository(
            repositoryName=name,
            imageTagMutability="MUTABLE",
            imageScanningConfiguration={"scanOnPush": False},
        )
        yield name
    finally:
        _safe(ecr.delete_repository, repositoryName=name, force=True)


@pytest.fixture(scope="session")
def cb_role(ls_session: boto3.Session, run_id: str):
    iam = ls_session.client("iam")
    role_name = f"pc-cb-int-{run_id}"
    try:
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(_CB_TRUST),
        )
        resp = iam.get_role(RoleName=role_name)
        yield resp["Role"]["Arn"], role_name
    finally:
        _safe(iam.delete_role, RoleName=role_name)


@pytest.fixture(scope="session")
def bad_project(ls_session: boto3.Session, cb_role, run_id: str):
    cb = ls_session.client("codebuild")
    role_arn, _ = cb_role
    name = f"pc-cb-bad-{run_id}"
    try:
        cb.create_project(
            name=name,
            source={"type": "NO_SOURCE", "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo ok"},
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:1.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "privilegedMode": True,
                "environmentVariables": [
                    {"name": "SECRET_TOKEN", "value": "x", "type": "PLAINTEXT"},
                ],
            },
            serviceRole=role_arn,
            timeoutInMinutes=480,
            logsConfig={
                "cloudWatchLogs": {"status": "DISABLED"},
                "s3Logs": {"status": "DISABLED"},
            },
        )
        yield name
    finally:
        _safe(cb.delete_project, name=name)


@pytest.fixture(scope="session")
def shared_role_project(ls_session: boto3.Session, cb_role, bad_project, run_id: str):
    cb = ls_session.client("codebuild")
    role_arn, _ = cb_role
    name = f"pc-cb-bad2-{run_id}"
    try:
        cb.create_project(
            name=name,
            source={"type": "NO_SOURCE", "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo ok"},
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:7.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "privilegedMode": False,
            },
            serviceRole=role_arn,
            timeoutInMinutes=60,
            logsConfig={"cloudWatchLogs": {"status": "ENABLED"}},
        )
        yield name
    finally:
        _safe(cb.delete_project, name=name)
