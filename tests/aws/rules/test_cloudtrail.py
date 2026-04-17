"""CT-001/002/003 — CloudTrail presence, validation, multi-region."""
from __future__ import annotations

from unittest.mock import MagicMock

from pipeline_check.core.checks.aws.rules import (
    ct001_trail_exists,
    ct002_log_file_validation,
    ct003_multi_region,
)


def _cloudtrail_client(trails, logging=True):
    client = MagicMock()
    client.describe_trails.return_value = {"trailList": trails}
    client.get_trail_status.return_value = {"IsLogging": logging}
    return client


def test_ct001_no_trail_fails(make_catalog):
    cat = make_catalog(cloudtrail=_cloudtrail_client([]))
    f = ct001_trail_exists.check(cat)[0]
    assert f.passed is False


def test_ct001_active_trail_passes(make_catalog):
    trail = {"Name": "t1", "TrailARN": "arn:aws:cloudtrail:us-east-1:1:trail/t1"}
    cat = make_catalog(cloudtrail=_cloudtrail_client([trail], logging=True))
    assert ct001_trail_exists.check(cat)[0].passed is True


def test_ct001_inactive_trail_fails(make_catalog):
    trail = {"Name": "t1", "TrailARN": "arn:aws:cloudtrail:us-east-1:1:trail/t1"}
    cat = make_catalog(cloudtrail=_cloudtrail_client([trail], logging=False))
    assert ct001_trail_exists.check(cat)[0].passed is False


def test_ct002_validation_enabled_passes(make_catalog):
    trail = {"Name": "t1", "LogFileValidationEnabled": True}
    cat = make_catalog(cloudtrail=_cloudtrail_client([trail]))
    assert ct002_log_file_validation.check(cat)[0].passed is True


def test_ct002_validation_disabled_fails(make_catalog):
    trail = {"Name": "t1", "LogFileValidationEnabled": False}
    cat = make_catalog(cloudtrail=_cloudtrail_client([trail]))
    assert ct002_log_file_validation.check(cat)[0].passed is False


def test_ct003_multi_region_passes(make_catalog):
    trail = {"Name": "t1", "IsMultiRegionTrail": True}
    cat = make_catalog(cloudtrail=_cloudtrail_client([trail]))
    assert ct003_multi_region.check(cat)[0].passed is True


def test_ct003_single_region_fails(make_catalog):
    trail = {"Name": "t1", "IsMultiRegionTrail": False}
    cat = make_catalog(cloudtrail=_cloudtrail_client([trail]))
    assert ct003_multi_region.check(cat)[0].passed is False
