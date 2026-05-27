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
