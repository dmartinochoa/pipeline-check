"""GCS-001/002/003 -- Cloud Storage bucket checks."""
from __future__ import annotations

from pipeline_check.core.checks.gcp.rules import (
    gcs001_public_bucket,
    gcs002_uniform_access,
    gcs003_versioning,
)


def _bucket(
    name: str = "my-bucket",
    *,
    versioning: bool = False,
    ubla: bool = False,
    iam_policy: list[dict] | None = None,
) -> dict:
    return {
        "name": name,
        "location": "US",
        "storage_class": "STANDARD",
        "versioning_enabled": versioning,
        "iam_configuration": {
            "uniform_bucket_level_access": {"enabled": ubla},
        },
        "iam_policy": iam_policy or [],
    }


# -----------------------------------------------------------------------
# GCS-001: bucket is publicly accessible
# -----------------------------------------------------------------------

class TestGCS001:
    def test_public_allUsers_fails(self, make_catalog):
        cat = make_catalog(**{
            "storage:buckets": [
                _bucket(iam_policy=[
                    {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
                ]),
            ],
        })
        findings = gcs001_public_bucket.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert "publicly accessible" in findings[0].description

    def test_public_allAuthenticatedUsers_fails(self, make_catalog):
        cat = make_catalog(**{
            "storage:buckets": [
                _bucket(iam_policy=[
                    {"role": "roles/storage.objectViewer",
                     "members": ["allAuthenticatedUsers"]},
                ]),
            ],
        })
        findings = gcs001_public_bucket.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_private_bucket_passes(self, make_catalog):
        cat = make_catalog(**{
            "storage:buckets": [
                _bucket(iam_policy=[
                    {"role": "roles/storage.objectViewer",
                     "members": ["serviceAccount:reader@proj.iam.gserviceaccount.com"]},
                ]),
            ],
        })
        findings = gcs001_public_bucket.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_iam_policy_passes(self, make_catalog):
        cat = make_catalog(**{
            "storage:buckets": [_bucket()],
        })
        findings = gcs001_public_bucket.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_buckets_returns_empty(self, make_catalog):
        cat = make_catalog(**{"storage:buckets": []})
        assert gcs001_public_bucket.check(cat) == []

    def test_multiple_public_roles_listed(self, make_catalog):
        cat = make_catalog(**{
            "storage:buckets": [
                _bucket(iam_policy=[
                    {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
                    {"role": "roles/storage.admin", "members": ["allUsers"]},
                ]),
            ],
        })
        findings = gcs001_public_bucket.check(cat)
        assert findings[0].passed is False
        assert "storage.objectViewer" in findings[0].description
        assert "storage.admin" in findings[0].description


# -----------------------------------------------------------------------
# GCS-002: bucket does not enforce uniform bucket-level access
# -----------------------------------------------------------------------

class TestGCS002:
    def test_ubla_disabled_fails(self, make_catalog):
        cat = make_catalog(**{
            "storage:buckets": [_bucket(ubla=False)],
        })
        findings = gcs002_uniform_access.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_ubla_enabled_passes(self, make_catalog):
        cat = make_catalog(**{
            "storage:buckets": [_bucket(ubla=True)],
        })
        findings = gcs002_uniform_access.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_missing_iam_configuration_fails(self, make_catalog):
        """A bucket dict with no iam_configuration key defaults to False."""
        cat = make_catalog(**{
            "storage:buckets": [{"name": "bare-bucket"}],
        })
        findings = gcs002_uniform_access.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_buckets_returns_empty(self, make_catalog):
        cat = make_catalog(**{"storage:buckets": []})
        assert gcs002_uniform_access.check(cat) == []


# -----------------------------------------------------------------------
# GCS-003: bucket versioning not enabled
# -----------------------------------------------------------------------

class TestGCS003:
    def test_versioning_disabled_fails(self, make_catalog):
        cat = make_catalog(**{
            "storage:buckets": [_bucket(versioning=False)],
        })
        findings = gcs003_versioning.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert "not have versioning" in findings[0].description

    def test_versioning_enabled_passes(self, make_catalog):
        cat = make_catalog(**{
            "storage:buckets": [_bucket(versioning=True)],
        })
        findings = gcs003_versioning.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_missing_versioning_key_fails(self, make_catalog):
        """When versioning_enabled is absent, bucket defaults to unversioned."""
        cat = make_catalog(**{
            "storage:buckets": [{"name": "bare"}],
        })
        findings = gcs003_versioning.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_buckets_returns_empty(self, make_catalog):
        cat = make_catalog(**{"storage:buckets": []})
        assert gcs003_versioning.check(cat) == []


# -----------------------------------------------------------------------
# GCS-004: bucket not encrypted with CMEK
# -----------------------------------------------------------------------

from pipeline_check.core.checks.gcp.rules import gcs004_cmek_encryption


class TestGCS004:
    def test_no_cmek_fails(self, make_catalog):
        cat = make_catalog(**{
            "storage:buckets": [_bucket()],
        })
        findings = gcs004_cmek_encryption.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCS-004"

    def test_cmek_passes(self, make_catalog):
        b = _bucket()
        b["default_kms_key_name"] = "projects/p/locations/us/keyRings/kr/cryptoKeys/k"
        cat = make_catalog(**{"storage:buckets": [b]})
        findings = gcs004_cmek_encryption.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_buckets_returns_empty(self, make_catalog):
        cat = make_catalog(**{"storage:buckets": []})
        assert gcs004_cmek_encryption.check(cat) == []


# -----------------------------------------------------------------------
# GCS-005: bucket access logging not enabled
# -----------------------------------------------------------------------

from pipeline_check.core.checks.gcp.rules import gcs005_access_logging


class TestGCS005:
    def test_no_logging_fails(self, make_catalog):
        cat = make_catalog(**{
            "storage:buckets": [_bucket()],
        })
        findings = gcs005_access_logging.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCS-005"

    def test_logging_enabled_passes(self, make_catalog):
        b = _bucket()
        b["logging"] = {"log_bucket": "log-bucket"}
        cat = make_catalog(**{"storage:buckets": [b]})
        findings = gcs005_access_logging.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_empty_log_bucket_fails(self, make_catalog):
        b = _bucket()
        b["logging"] = {"log_bucket": ""}
        cat = make_catalog(**{"storage:buckets": [b]})
        findings = gcs005_access_logging.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_buckets_returns_empty(self, make_catalog):
        cat = make_catalog(**{"storage:buckets": []})
        assert gcs005_access_logging.check(cat) == []
