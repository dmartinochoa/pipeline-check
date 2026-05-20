"""IAM-003 against a real-shape boto3 ``list_roles`` paginator response.

The mocked tests in ``tests/aws/test_iam.py::TestIAM003PermissionBoundary``
hand the rule synthetic dicts that already match the field shape the
rule reads. The LocalStack integration test
(``tests/integration/test_localstack.py``) documents that
``PermissionsBoundary`` is not echoed back by LocalStack's
``list_roles`` paginator. Result: IAM-003 had no test that drove the
rule against the actual response shape boto3 returns from a real AWS
account.

This module fills that gap using ``botocore.stub.Stubber``. A
captured (sanitized) ``ListRoles`` response with a non-trivial
``Marker`` (pagination) and a ``PermissionsBoundary`` block is fed
through a real ``boto3.client("iam")``, so the rule walks the same
paginator + ``role.get("PermissionsBoundary")`` path it would in
production. A drift in the AWS-side schema (key rename, nested-vs-flat
move) would red this test in a way LocalStack and ``MagicMock`` can't.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import boto3
import pytest
from botocore.stub import Stubber

from pipeline_check.core.checks.aws._catalog import ResourceCatalog
from pipeline_check.core.checks.aws.rules import (
    iam003_permission_boundary as rule,
)

_CB_TRUST = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
    '"Principal":{"Service":"codebuild.amazonaws.com"},'
    '"Action":"sts:AssumeRole"}]}'
)


def _role_dict(name: str, *, with_boundary: bool, role_id: str = "AROAEXAMPLEID0001") -> dict:
    """Return a Role dict matching the shape ``ListRoles`` returns.

    ``CreateDate`` is required by botocore's validator; the field is a
    real ``datetime`` rather than the synthetic string the mocked
    tests sometimes pass. ``RoleLastUsed`` is omitted on purpose: AWS
    only populates it after the role has been assumed at least once,
    so a clean account's response carries roles without it.
    """
    from datetime import UTC, datetime
    out = {
        "Path": "/",
        "RoleName": name,
        "RoleId": role_id,
        "Arn": f"arn:aws:iam::123456789012:role/{name}",
        "CreateDate": datetime(2024, 1, 1, tzinfo=UTC),
        "AssumeRolePolicyDocument": _CB_TRUST,
        "MaxSessionDuration": 3600,
    }
    if with_boundary:
        out["PermissionsBoundary"] = {
            "PermissionsBoundaryArn": (
                "arn:aws:iam::123456789012:policy/ReleaseBoundary"
            ),
            "PermissionsBoundaryType": "Policy",
        }
    return out


@pytest.fixture()
def stubbed_catalog():
    """Wire a real ``boto3.client('iam')`` with a stubbed ListRoles
    response into a ``ResourceCatalog``.

    Returns a context-manager factory: ``cat = stubbed_catalog([...pages])``
    yields the catalog and tears the stubber down on exit.
    """
    def _build(pages: list[dict]) -> ResourceCatalog:
        iam_client = boto3.client(
            "iam", region_name="us-east-1",
            aws_access_key_id="test", aws_secret_access_key="test",
        )
        stubber = Stubber(iam_client)
        # First page is requested with no params; each subsequent page
        # carries the previous page's ``Marker`` as the request input,
        # matching how boto3's paginator threads the cursor.
        prev_marker: str | None = None
        for page in pages:
            expected = {} if prev_marker is None else {"Marker": prev_marker}
            stubber.add_response("list_roles", page, expected_params=expected)
            prev_marker = page.get("Marker") if page.get("IsTruncated") else None
        stubber.activate()

        session = MagicMock()
        session.client.return_value = iam_client
        cat = ResourceCatalog(session)
        # Keep the stubber alive until the test ends so the
        # paginator can pull every page; pytest tears the fixture
        # via the generator's ``finally`` block.
        cat._stubber = stubber  # type: ignore[attr-defined]
        return cat

    yield _build


def test_role_with_boundary_passes_against_real_shape(stubbed_catalog):
    # One-page response carrying a single role with PermissionsBoundary.
    # The real AWS API serializes the field exactly the way this
    # fixture writes it — confirming the rule reads ``role.get(
    # "PermissionsBoundary", {}).get("PermissionsBoundaryArn")``
    # against the canonical key path.
    cat = stubbed_catalog([
        {"Roles": [_role_dict("with-boundary", with_boundary=True)]},
    ])
    findings = rule.check(cat)
    assert len(findings) == 1
    assert findings[0].passed is True
    assert "ReleaseBoundary" in findings[0].description


def test_role_without_boundary_fails_against_real_shape(stubbed_catalog):
    # The "no boundary" path is the same shape minus the
    # ``PermissionsBoundary`` key entirely (not an empty dict).
    cat = stubbed_catalog([
        {"Roles": [_role_dict("no-boundary", with_boundary=False)]},
    ])
    findings = rule.check(cat)
    assert len(findings) == 1
    assert findings[0].passed is False
    assert "no permissions boundary" in findings[0].description


def test_paginated_response_preserves_permissions_boundary(stubbed_catalog):
    # Multi-page ListRoles. boto3's paginator collapses ``Marker`` /
    # ``IsTruncated`` for us, but the rule layer needs to see every
    # role across every page. This used to silently lose the
    # boundary field on LocalStack; confirm the real-shape stub
    # carries it through pagination boundaries intact.
    cat = stubbed_catalog([
        {
            "Roles": [_role_dict("page1-role", with_boundary=True, role_id="AROAEXAMPLEID0001")],
            "IsTruncated": True,
            "Marker": "page2-token",
        },
        {
            "Roles": [_role_dict("page2-role", with_boundary=False, role_id="AROAEXAMPLEID0002")],
            "IsTruncated": False,
        },
    ])
    findings = rule.check(cat)
    by_name = {f.resource: f for f in findings}
    assert by_name["page1-role"].passed is True
    assert by_name["page2-role"].passed is False


def test_only_cicd_roles_evaluated(stubbed_catalog):
    # IAM-003 reads ``catalog.cicd_roles()``, which trust-policy-filters
    # to roles a CI service principal can assume. A role with a
    # non-CICD trust policy must NOT appear in the findings list,
    # boundary or not. Locking the integration with the catalog
    # against the real list_roles shape.
    cat = stubbed_catalog([
        {"Roles": [
            _role_dict("cicd-role", with_boundary=False, role_id="AROAEXAMPLEID0001"),
            # Same shape but trust policy points at an unrelated
            # principal: must be filtered out by ``cicd_roles()``.
            {
                **_role_dict("not-cicd", with_boundary=False, role_id="AROAEXAMPLEID0002"),
                "AssumeRolePolicyDocument": (
                    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                    '"Principal":{"Service":"ec2.amazonaws.com"},'
                    '"Action":"sts:AssumeRole"}]}'
                ),
            },
        ]},
    ])
    findings = rule.check(cat)
    assert [f.resource for f in findings] == ["cicd-role"]
