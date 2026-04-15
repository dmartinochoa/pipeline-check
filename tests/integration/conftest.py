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

import os
import uuid

import boto3
import pytest

ENDPOINT_URL = os.environ.get("AWS_ENDPOINT_URL")
REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")


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
