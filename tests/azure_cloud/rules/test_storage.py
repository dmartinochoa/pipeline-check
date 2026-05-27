"""Tests for AZST-001, AZST-002, and AZST-003 rules."""
from __future__ import annotations

from unittest.mock import MagicMock

from pipeline_check.core.checks.azure_cloud.rules import (
    azst001_public_blob as azst001,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azst002_https_only as azst002,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azst003_cmk_encryption as azst003,
)

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _storage_account(
    name: str = "sa1",
    allow_public: bool | None = True,
    https_only: bool = True,
    key_source: str = "Microsoft.Storage",
) -> MagicMock:
    account = MagicMock()
    account.name = name
    account.allow_blob_public_access = allow_public
    account.enable_https_traffic_only = https_only
    account.encryption.key_source = key_source
    return account


# -----------------------------------------------------------------------
# AZST-001  Storage account allows public blob access
# -----------------------------------------------------------------------

class TestAzst001:
    def test_public_access_enabled_fails(self, make_catalog):
        acct = _storage_account(allow_public=True)
        catalog = make_catalog(**{"storage:accounts": [acct]})
        findings = azst001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZST-001"

    def test_public_access_disabled_passes(self, make_catalog):
        acct = _storage_account(allow_public=False)
        catalog = make_catalog(**{"storage:accounts": [acct]})
        findings = azst001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_public_access_none_defaults_to_fail(self, make_catalog):
        """When allow_blob_public_access is None, it defaults to True."""
        acct = _storage_account(allow_public=None)
        catalog = make_catalog(**{"storage:accounts": [acct]})
        findings = azst001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_accounts(self, make_catalog):
        catalog = make_catalog(**{"storage:accounts": []})
        findings = azst001.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZST-002  Storage account allows non-HTTPS traffic
# -----------------------------------------------------------------------

class TestAzst002:
    def test_https_disabled_fails(self, make_catalog):
        acct = _storage_account(https_only=False)
        catalog = make_catalog(**{"storage:accounts": [acct]})
        findings = azst002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZST-002"

    def test_https_enabled_passes(self, make_catalog):
        acct = _storage_account(https_only=True)
        catalog = make_catalog(**{"storage:accounts": [acct]})
        findings = azst002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_empty_accounts(self, make_catalog):
        catalog = make_catalog(**{"storage:accounts": []})
        findings = azst002.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZST-003  Storage account not encrypted with CMK
# -----------------------------------------------------------------------

class TestAzst003:
    def test_microsoft_managed_key_fails(self, make_catalog):
        acct = _storage_account(key_source="Microsoft.Storage")
        catalog = make_catalog(**{"storage:accounts": [acct]})
        findings = azst003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZST-003"

    def test_customer_managed_key_passes(self, make_catalog):
        acct = _storage_account(key_source="Microsoft.Keyvault")
        catalog = make_catalog(**{"storage:accounts": [acct]})
        findings = azst003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_encryption_attr_defaults_to_fail(self, make_catalog):
        """Account with no encryption attribute defaults to Microsoft.Storage."""
        acct = MagicMock()
        acct.name = "bare-sa"
        acct.encryption = None
        catalog = make_catalog(**{"storage:accounts": [acct]})
        findings = azst003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_accounts(self, make_catalog):
        catalog = make_catalog(**{"storage:accounts": []})
        findings = azst003.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZST-004  Storage account minimum TLS version below 1.2
# -----------------------------------------------------------------------

from pipeline_check.core.checks.azure_cloud.rules import (
    azst004_min_tls as azst004,
)


class TestAzst004:
    def test_tls10_fails(self, make_catalog):
        acct = _storage_account()
        acct.minimum_tls_version = "TLS1_0"
        catalog = make_catalog(**{"storage:accounts": [acct]})
        findings = azst004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZST-004"

    def test_tls12_passes(self, make_catalog):
        acct = _storage_account()
        acct.minimum_tls_version = "TLS1_2"
        catalog = make_catalog(**{"storage:accounts": [acct]})
        findings = azst004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_none_defaults_to_fail(self, make_catalog):
        acct = _storage_account()
        acct.minimum_tls_version = None
        catalog = make_catalog(**{"storage:accounts": [acct]})
        findings = azst004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_accounts(self, make_catalog):
        catalog = make_catalog(**{"storage:accounts": []})
        findings = azst004.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZST-005  Storage account has no blob lifecycle management policy
# -----------------------------------------------------------------------

from pipeline_check.core.checks.azure_cloud.rules import (
    azst005_blob_lifecycle as azst005,
)


class TestAzst005:
    def test_blob_capable_account_fails(self, make_catalog):
        acct = _storage_account()
        acct.kind = "StorageV2"
        catalog = make_catalog(**{"storage:accounts": [acct]})
        findings = azst005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZST-005"

    def test_non_blob_kind_skipped(self, make_catalog):
        acct = _storage_account()
        acct.kind = "FileStorage"
        catalog = make_catalog(**{"storage:accounts": [acct]})
        findings = azst005.check(catalog)
        assert findings == []

    def test_empty_accounts(self, make_catalog):
        catalog = make_catalog(**{"storage:accounts": []})
        findings = azst005.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZST-006  Storage account access keys not rotated within 90 days
# -----------------------------------------------------------------------

from datetime import UTC, datetime, timedelta

from pipeline_check.core.checks.azure_cloud.rules import (
    azst006_key_rotation as azst006,
)


class TestAzst006:
    def test_stale_keys_fail(self, make_catalog):
        acct = _storage_account()
        old = datetime.now(tz=UTC) - timedelta(days=120)
        acct.key_creation_time.key1 = old
        acct.key_creation_time.key2 = old
        catalog = make_catalog(**{"storage:accounts": [acct]})
        findings = azst006.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZST-006"

    def test_fresh_keys_pass(self, make_catalog):
        acct = _storage_account()
        recent = datetime.now(tz=UTC) - timedelta(days=30)
        acct.key_creation_time.key1 = recent
        acct.key_creation_time.key2 = recent
        catalog = make_catalog(**{"storage:accounts": [acct]})
        findings = azst006.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_key_creation_time_fails(self, make_catalog):
        acct = _storage_account()
        acct.key_creation_time = None
        catalog = make_catalog(**{"storage:accounts": [acct]})
        findings = azst006.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_accounts(self, make_catalog):
        catalog = make_catalog(**{"storage:accounts": []})
        findings = azst006.check(catalog)
        assert findings == []
