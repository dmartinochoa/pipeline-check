"""Tests for ACR-001, ACR-002, and ACR-003 rules."""
from __future__ import annotations

from unittest.mock import MagicMock

from pipeline_check.core.checks.azure_cloud.rules import (
    acr001_admin_user as acr001,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    acr002_public_access as acr002,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    acr003_content_trust as acr003,
)

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _registry(
    name: str = "myacr",
    admin_user_enabled: bool = False,
    public_network_access: str = "Enabled",
    trust_status: str = "disabled",
) -> MagicMock:
    reg = MagicMock()
    reg.name = name
    reg.admin_user_enabled = admin_user_enabled
    reg.public_network_access = public_network_access
    reg.policies.trust_policy.status = trust_status
    return reg


# -----------------------------------------------------------------------
# ACR-001  Container registry admin user enabled
# -----------------------------------------------------------------------

class TestAcr001:
    def test_admin_enabled_fails(self, make_catalog):
        reg = _registry(admin_user_enabled=True)
        catalog = make_catalog(**{"acr:registries": [reg]})
        findings = acr001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "ACR-001"

    def test_admin_disabled_passes(self, make_catalog):
        reg = _registry(admin_user_enabled=False)
        catalog = make_catalog(**{"acr:registries": [reg]})
        findings = acr001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_empty_registries(self, make_catalog):
        catalog = make_catalog(**{"acr:registries": []})
        findings = acr001.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# ACR-002  Container registry allows public network access
# -----------------------------------------------------------------------

class TestAcr002:
    def test_public_access_enabled_fails(self, make_catalog):
        reg = _registry(public_network_access="Enabled")
        catalog = make_catalog(**{"acr:registries": [reg]})
        findings = acr002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "ACR-002"

    def test_public_access_disabled_passes(self, make_catalog):
        reg = _registry(public_network_access="Disabled")
        catalog = make_catalog(**{"acr:registries": [reg]})
        findings = acr002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_default_attr_value_fails(self, make_catalog):
        """When public_network_access is missing, getattr defaults to 'Enabled'."""
        reg = MagicMock()
        reg.name = "bare-acr"
        # Simulate missing attr by using a spec that doesn't have it
        del reg.public_network_access
        catalog = make_catalog(**{"acr:registries": [reg]})
        findings = acr002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_registries(self, make_catalog):
        catalog = make_catalog(**{"acr:registries": []})
        findings = acr002.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# ACR-003  Container registry content trust not enabled
# -----------------------------------------------------------------------

class TestAcr003:
    def test_content_trust_disabled_fails(self, make_catalog):
        reg = _registry(trust_status="disabled")
        catalog = make_catalog(**{"acr:registries": [reg]})
        findings = acr003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "ACR-003"

    def test_content_trust_enabled_passes(self, make_catalog):
        reg = _registry(trust_status="enabled")
        catalog = make_catalog(**{"acr:registries": [reg]})
        findings = acr003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_policies_attr_defaults_to_disabled(self, make_catalog):
        """Registry with policies=None defaults to disabled (fail)."""
        reg = MagicMock()
        reg.name = "bare-acr"
        reg.policies = None
        catalog = make_catalog(**{"acr:registries": [reg]})
        findings = acr003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_trust_policy_defaults_to_disabled(self, make_catalog):
        """Registry with policies but no trust_policy defaults to disabled."""
        reg = MagicMock()
        reg.name = "partial-acr"
        reg.policies.trust_policy = None
        catalog = make_catalog(**{"acr:registries": [reg]})
        findings = acr003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_registries(self, make_catalog):
        catalog = make_catalog(**{"acr:registries": []})
        findings = acr003.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# ACR-004  Container registry Defender scanning not enabled
# -----------------------------------------------------------------------

from pipeline_check.core.checks.azure_cloud.rules import (
    acr004_defender_scanning as acr004,
)


class TestAcr004:
    def test_premium_with_quarantine_passes(self, make_catalog):
        reg = _registry()
        reg.sku.name = "Premium"
        reg.policies.quarantine_policy.status = "enabled"
        catalog = make_catalog(**{"acr:registries": [reg]})
        findings = acr004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "ACR-004"

    def test_premium_without_quarantine_fails(self, make_catalog):
        reg = _registry()
        reg.sku.name = "Premium"
        reg.policies.quarantine_policy.status = "disabled"
        catalog = make_catalog(**{"acr:registries": [reg]})
        findings = acr004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_standard_sku_fails(self, make_catalog):
        reg = _registry()
        reg.sku.name = "Standard"
        catalog = make_catalog(**{"acr:registries": [reg]})
        findings = acr004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_registries(self, make_catalog):
        catalog = make_catalog(**{"acr:registries": []})
        findings = acr004.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# ACR-005  Container registry does not enforce tag immutability
# -----------------------------------------------------------------------

from pipeline_check.core.checks.azure_cloud.rules import (
    acr005_tag_immutability as acr005,
)


class TestAcr005:
    def test_quarantine_enabled_passes(self, make_catalog):
        reg = _registry()
        reg.policies.quarantine_policy.status = "enabled"
        reg.policies.export_policy.status = "enabled"
        catalog = make_catalog(**{"acr:registries": [reg]})
        findings = acr005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "ACR-005"

    def test_export_disabled_passes(self, make_catalog):
        reg = _registry()
        reg.policies.quarantine_policy.status = "disabled"
        reg.policies.export_policy.status = "disabled"
        catalog = make_catalog(**{"acr:registries": [reg]})
        findings = acr005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_policies_fails(self, make_catalog):
        reg = MagicMock()
        reg.name = "bare-acr"
        reg.policies = None
        catalog = make_catalog(**{"acr:registries": [reg]})
        findings = acr005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_all_disabled_fails(self, make_catalog):
        reg = _registry()
        reg.policies.quarantine_policy.status = "disabled"
        reg.policies.export_policy.status = "enabled"
        catalog = make_catalog(**{"acr:registries": [reg]})
        findings = acr005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_registries(self, make_catalog):
        catalog = make_catalog(**{"acr:registries": []})
        findings = acr005.check(catalog)
        assert findings == []
