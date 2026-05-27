"""Tests for AKV-001, AKV-002, and AKV-003 rules."""
from __future__ import annotations

from unittest.mock import MagicMock

from pipeline_check.core.checks.azure_cloud.rules import (
    akv001_soft_delete as akv001,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    akv002_purge_protection as akv002,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    akv003_network_acl as akv003,
)

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _key_vault(
    name: str = "kv1",
    soft_delete: bool | None = True,
    purge_protection: bool | None = True,
    default_action: str = "Deny",
) -> MagicMock:
    vault = MagicMock()
    vault.name = name
    vault.properties.enable_soft_delete = soft_delete
    vault.properties.enable_purge_protection = purge_protection
    vault.properties.network_acls.default_action = default_action
    return vault


# -----------------------------------------------------------------------
# AKV-001  Key Vault soft delete not enabled
# -----------------------------------------------------------------------

class TestAkv001:
    def test_soft_delete_disabled_fails(self, make_catalog):
        vault = _key_vault(soft_delete=False)
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AKV-001"

    def test_soft_delete_enabled_passes(self, make_catalog):
        vault = _key_vault(soft_delete=True)
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_soft_delete_none_defaults_to_true(self, make_catalog):
        """When enable_soft_delete is None, rule defaults to True (pass)."""
        vault = _key_vault(soft_delete=None)
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_empty_vaults(self, make_catalog):
        catalog = make_catalog(**{"keyvault:vaults": []})
        findings = akv001.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AKV-002  Key Vault purge protection not enabled
# -----------------------------------------------------------------------

class TestAkv002:
    def test_purge_protection_disabled_fails(self, make_catalog):
        vault = _key_vault(purge_protection=False)
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AKV-002"

    def test_purge_protection_enabled_passes(self, make_catalog):
        vault = _key_vault(purge_protection=True)
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_purge_protection_none_fails(self, make_catalog):
        """When enable_purge_protection is None, bool(None) is False."""
        vault = _key_vault(purge_protection=None)
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_vaults(self, make_catalog):
        catalog = make_catalog(**{"keyvault:vaults": []})
        findings = akv002.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AKV-003  Key Vault allows access from all networks
# -----------------------------------------------------------------------

class TestAkv003:
    def test_allow_default_action_fails(self, make_catalog):
        vault = _key_vault(default_action="Allow")
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AKV-003"

    def test_deny_default_action_passes(self, make_catalog):
        vault = _key_vault(default_action="Deny")
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_network_acls_defaults_to_allow(self, make_catalog):
        """Vault with no network_acls attribute defaults to Allow (fail)."""
        vault = MagicMock()
        vault.name = "bare-kv"
        vault.properties.network_acls = None
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_properties_defaults_to_fail(self, make_catalog):
        """Vault with properties=None falls through to fail."""
        vault = MagicMock()
        vault.name = "no-props-kv"
        vault.properties = None
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_vaults(self, make_catalog):
        catalog = make_catalog(**{"keyvault:vaults": []})
        findings = akv003.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AKV-004  Key Vault key has no expiration date
# -----------------------------------------------------------------------

from pipeline_check.core.checks.azure_cloud.rules import (
    akv004_key_expiry as akv004,
)


class TestAkv004:
    def test_key_without_expiry_fails(self, make_catalog):
        vault = _key_vault()
        catalog = make_catalog(**{
            "keyvault:vaults": [vault],
            "keyvault:keys:kv1": [
                {"kid": "https://kv1.vault.azure.net/keys/mykey/abc123",
                 "attributes": {"enabled": True, "exp": None}},
            ],
        })
        findings = akv004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AKV-004"

    def test_key_with_expiry_passes(self, make_catalog):
        vault = _key_vault()
        catalog = make_catalog(**{
            "keyvault:vaults": [vault],
            "keyvault:keys:kv1": [
                {"kid": "https://kv1.vault.azure.net/keys/mykey/abc123",
                 "attributes": {"enabled": True, "exp": 1735689600}},
            ],
        })
        findings = akv004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_disabled_key_skipped(self, make_catalog):
        vault = _key_vault()
        catalog = make_catalog(**{
            "keyvault:vaults": [vault],
            "keyvault:keys:kv1": [
                {"kid": "https://kv1.vault.azure.net/keys/mykey/abc123",
                 "attributes": {"enabled": False, "exp": None}},
            ],
        })
        findings = akv004.check(catalog)
        assert findings == []

    def test_empty_vaults(self, make_catalog):
        catalog = make_catalog(**{"keyvault:vaults": []})
        findings = akv004.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AKV-005  Key Vault secret has no expiration date
# -----------------------------------------------------------------------

from pipeline_check.core.checks.azure_cloud.rules import (
    akv005_secret_expiry as akv005,
)


class TestAkv005:
    def test_secret_without_expiry_fails(self, make_catalog):
        vault = _key_vault()
        catalog = make_catalog(**{
            "keyvault:vaults": [vault],
            "keyvault:secrets:kv1": [
                {"id": "https://kv1.vault.azure.net/secrets/mysecret",
                 "attributes": {"enabled": True, "exp": None}},
            ],
        })
        findings = akv005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AKV-005"

    def test_secret_with_expiry_passes(self, make_catalog):
        vault = _key_vault()
        catalog = make_catalog(**{
            "keyvault:vaults": [vault],
            "keyvault:secrets:kv1": [
                {"id": "https://kv1.vault.azure.net/secrets/mysecret",
                 "attributes": {"enabled": True, "exp": 1735689600}},
            ],
        })
        findings = akv005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_disabled_secret_skipped(self, make_catalog):
        vault = _key_vault()
        catalog = make_catalog(**{
            "keyvault:vaults": [vault],
            "keyvault:secrets:kv1": [
                {"id": "https://kv1.vault.azure.net/secrets/mysecret",
                 "attributes": {"enabled": False, "exp": None}},
            ],
        })
        findings = akv005.check(catalog)
        assert findings == []

    def test_empty_vaults(self, make_catalog):
        catalog = make_catalog(**{"keyvault:vaults": []})
        findings = akv005.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AKV-006  Key Vault uses vault access policies instead of RBAC
# -----------------------------------------------------------------------

from pipeline_check.core.checks.azure_cloud.rules import (
    akv006_rbac_access as akv006,
)


class TestAkv006:
    def test_rbac_disabled_fails(self, make_catalog):
        vault = _key_vault()
        vault.properties.enable_rbac_authorization = False
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv006.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AKV-006"

    def test_rbac_enabled_passes(self, make_catalog):
        vault = _key_vault()
        vault.properties.enable_rbac_authorization = True
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv006.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_rbac_none_fails(self, make_catalog):
        vault = _key_vault()
        vault.properties.enable_rbac_authorization = None
        catalog = make_catalog(**{"keyvault:vaults": [vault]})
        findings = akv006.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_vaults(self, make_catalog):
        catalog = make_catalog(**{"keyvault:vaults": []})
        findings = akv006.check(catalog)
        assert findings == []
