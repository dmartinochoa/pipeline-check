"""Tests for AZVM-001..005 Compute VM rules."""
from __future__ import annotations

from unittest.mock import MagicMock

from pipeline_check.core.checks.azure_cloud.rules import (
    azvm001_disk_encryption as azvm001,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azvm002_public_ip as azvm002,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azvm003_jit_access as azvm003,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azvm004_auto_os_patching as azvm004,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azvm005_managed_identity as azvm005,
)

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _vm(
    name: str = "vm1",
    *,
    os_disk_enc_set_id: str | None = None,
    os_disk_enc_enabled: bool = False,
    data_disks: list | None = None,
    nic_ids: list[str] | None = None,
    security_profile: object | None = None,
    tags: dict | None = None,
    win_auto_updates: bool = False,
    linux_patch_mode: str | None = None,
    identity_type: str = "None",
) -> MagicMock:
    vm = MagicMock()
    vm.name = name
    vm.tags = tags or {}

    # Storage profile
    os_disk = MagicMock()
    if os_disk_enc_set_id:
        os_disk.managed_disk.disk_encryption_set.id = os_disk_enc_set_id
    else:
        os_disk.managed_disk.disk_encryption_set = None
    enc_settings = MagicMock()
    enc_settings.enabled = os_disk_enc_enabled
    os_disk.encryption_settings = enc_settings if os_disk_enc_enabled else None

    vm.storage_profile.os_disk = os_disk
    vm.storage_profile.data_disks = data_disks or []

    # Network profile
    nic_refs = []
    for nic_id in (nic_ids or []):
        ref = MagicMock()
        ref.id = nic_id
        nic_refs.append(ref)
    vm.network_profile.network_interfaces = nic_refs

    # Security / JIT
    vm.security_profile = security_profile

    # OS profile
    os_profile = MagicMock()
    win_config = MagicMock()
    win_config.enable_automatic_updates = win_auto_updates
    os_profile.windows_configuration = win_config if win_auto_updates else None
    if linux_patch_mode:
        linux_config = MagicMock()
        linux_config.patch_settings.patch_mode = linux_patch_mode
        os_profile.linux_configuration = linux_config
    else:
        os_profile.linux_configuration = None
    vm.os_profile = os_profile

    # Identity
    if identity_type != "None":
        identity = MagicMock()
        identity.type = identity_type
        vm.identity = identity
    else:
        vm.identity = None

    return vm


# -----------------------------------------------------------------------
# AZVM-001  Virtual machine disks are not encrypted
# -----------------------------------------------------------------------

class TestAzvm001:
    def test_unencrypted_os_disk_fails(self, make_catalog):
        vm = _vm()
        catalog = make_catalog(**{"compute:vms": [vm]})
        findings = azvm001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZVM-001"

    def test_encrypted_os_disk_passes(self, make_catalog):
        vm = _vm(os_disk_enc_set_id="/des/123")
        catalog = make_catalog(**{"compute:vms": [vm]})
        findings = azvm001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_enc_settings_enabled_passes(self, make_catalog):
        vm = _vm(os_disk_enc_enabled=True)
        catalog = make_catalog(**{"compute:vms": [vm]})
        findings = azvm001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_unencrypted_data_disk_fails(self, make_catalog):
        dd = MagicMock()
        dd.name = "data-disk-1"
        dd.managed_disk.disk_encryption_set = None
        vm = _vm(os_disk_enc_set_id="/des/123", data_disks=[dd])
        catalog = make_catalog(**{"compute:vms": [vm]})
        findings = azvm001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_vms(self, make_catalog):
        catalog = make_catalog(**{"compute:vms": []})
        findings = azvm001.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZVM-002  Virtual machine has a public IP address
# -----------------------------------------------------------------------

class TestAzvm002:
    def test_vm_with_public_ip_fails(self, make_catalog):
        pip = MagicMock()
        pip.ip_configuration.id = (
            "/subscriptions/sub/resourceGroups/rg/providers/"
            "Microsoft.Network/networkInterfaces/nic1/ipConfigurations/ipconfig1"
        )
        nic_id = "/subscriptions/sub/resourcegroups/rg/providers/microsoft.network/networkinterfaces/nic1"
        vm = _vm(nic_ids=[nic_id])
        catalog = make_catalog(**{
            "compute:vms": [vm],
            "network:public_ips": [pip],
        })
        findings = azvm002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZVM-002"

    def test_vm_without_public_ip_passes(self, make_catalog):
        vm = _vm(nic_ids=["/subscriptions/sub/resourcegroups/rg/providers/microsoft.network/networkinterfaces/nic-priv"])
        catalog = make_catalog(**{
            "compute:vms": [vm],
            "network:public_ips": [],
        })
        findings = azvm002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_empty_vms(self, make_catalog):
        catalog = make_catalog(**{
            "compute:vms": [],
            "network:public_ips": [],
        })
        findings = azvm002.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZVM-003  Virtual machine does not have JIT network access
# -----------------------------------------------------------------------

class TestAzvm003:
    def test_no_jit_fails(self, make_catalog):
        vm = _vm()
        catalog = make_catalog(**{"compute:vms": [vm]})
        findings = azvm003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZVM-003"

    def test_security_profile_passes(self, make_catalog):
        vm = _vm(security_profile=MagicMock())
        catalog = make_catalog(**{"compute:vms": [vm]})
        findings = azvm003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_jit_tag_passes(self, make_catalog):
        vm = _vm(tags={"jit-enabled": "true"})
        catalog = make_catalog(**{"compute:vms": [vm]})
        findings = azvm003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_empty_vms(self, make_catalog):
        catalog = make_catalog(**{"compute:vms": []})
        findings = azvm003.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZVM-004  Virtual machine automatic OS patching not enabled
# -----------------------------------------------------------------------

class TestAzvm004:
    def test_no_auto_patch_fails(self, make_catalog):
        vm = _vm()
        catalog = make_catalog(**{"compute:vms": [vm]})
        findings = azvm004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZVM-004"

    def test_windows_auto_updates_passes(self, make_catalog):
        vm = _vm(win_auto_updates=True)
        catalog = make_catalog(**{"compute:vms": [vm]})
        findings = azvm004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_linux_automatic_by_platform_passes(self, make_catalog):
        vm = _vm(linux_patch_mode="AutomaticByPlatform")
        catalog = make_catalog(**{"compute:vms": [vm]})
        findings = azvm004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_linux_manual_fails(self, make_catalog):
        vm = _vm(linux_patch_mode="ImageDefault")
        catalog = make_catalog(**{"compute:vms": [vm]})
        findings = azvm004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_vms(self, make_catalog):
        catalog = make_catalog(**{"compute:vms": []})
        findings = azvm004.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZVM-005  Virtual machine does not use a managed identity
# -----------------------------------------------------------------------

class TestAzvm005:
    def test_no_identity_fails(self, make_catalog):
        vm = _vm(identity_type="None")
        catalog = make_catalog(**{"compute:vms": [vm]})
        findings = azvm005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZVM-005"

    def test_system_assigned_passes(self, make_catalog):
        vm = _vm(identity_type="SystemAssigned")
        catalog = make_catalog(**{"compute:vms": [vm]})
        findings = azvm005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_user_assigned_passes(self, make_catalog):
        vm = _vm(identity_type="UserAssigned")
        catalog = make_catalog(**{"compute:vms": [vm]})
        findings = azvm005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_empty_vms(self, make_catalog):
        catalog = make_catalog(**{"compute:vms": []})
        findings = azvm005.check(catalog)
        assert findings == []
