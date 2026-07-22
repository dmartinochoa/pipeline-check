"""Regression tests from the rule audit (Entra crash / FN fixes)."""
from __future__ import annotations

from unittest.mock import MagicMock

from pipeline_check.core.checks.azure_cloud.rules import (
    aznw002_flow_logs as aznw002,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azvm003_jit_access as azvm003,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    entra002_app_long_credential as entra002,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    entra004_conditional_access_mfa as entra004,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    entra006_risky_signin_policy as entra006,
)


def _catalog(method, value):
    cat = MagicMock()
    getattr(cat, method).return_value = value
    return cat


class TestENTRA002AppLongCredential:
    def test_mixed_naive_and_aware_datetimes_do_not_crash(self):
        # endDateTime carries a "Z" (tz-aware) while startDateTime does
        # not (naive); subtracting the two used to raise TypeError.
        cat = _catalog("applications", [{"displayName": "a", "appId": "id",
            "passwordCredentials": [{
                "startDateTime": "2026-01-01T00:00:00",
                "endDateTime": "2027-01-01T00:00:00Z"}]}])
        res = entra002.check(cat)
        assert res and res[0].passed is False  # ~365 days > 180

    def test_null_credential_arrays_do_not_crash(self):
        # Graph can return passwordCredentials / keyCredentials
        # present-but-null; iterating None used to raise TypeError.
        cat = _catalog("applications", [{"displayName": "a", "appId": "id",
            "passwordCredentials": None, "keyCredentials": None}])
        # No creds to evaluate; the point is it returns cleanly, no crash.
        assert entra002.check(cat) == []


class TestENTRA004ConditionalAccessMFA:
    def test_null_builtin_controls_do_not_crash(self):
        cat = _catalog("conditional_access_policies", [{"state": "enabled",
            "grantControls": {"builtInControls": None},
            "conditions": {"users": {"includeUsers": ["All"]}}}])
        assert entra004.check(cat)[0].passed is False

    def test_authentication_strength_satisfies_mfa(self):
        # Modern policies enforce MFA via authenticationStrength, not the
        # legacy builtInControls "mfa" grant.
        cat = _catalog("conditional_access_policies", [{"state": "enabled",
            "grantControls": {"builtInControls": [],
                "authenticationStrength": {"id": "strength-id"}},
            "conditions": {"users": {"includeUsers": ["All"]}}}])
        assert entra004.check(cat)[0].passed is True


class TestENTRA006RiskySigninPolicy:
    def test_non_string_risk_level_does_not_crash(self):
        cat = _catalog("conditional_access_policies", [{"state": "enabled",
            "conditions": {"signInRiskLevels": [None]}}])
        assert entra006.check(cat)[0].passed is False


# ---------------------------------------------------------------------------
# Batch 5 — false-negative fixes
# ---------------------------------------------------------------------------

def _nsg(name="nsg1", nsg_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1"):
    obj = MagicMock()
    obj.name = name
    obj.id = nsg_id
    obj.security_rules = []
    return obj


def _flow_log(target_id: str, enabled: bool = True) -> MagicMock:
    fl = MagicMock()
    fl.target_resource_id = target_id
    fl.enabled = enabled
    return fl


def _vm(name="vm1", security_profile=None, tags=None):
    vm = MagicMock()
    vm.name = name
    vm.security_profile = security_profile
    vm.tags = tags or {}
    return vm


class TestAZNW002FlowLogEnabledFlag:
    """AZNW-002: a flow log with enabled=False must not credit the NSG."""

    _NSG_ID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1"

    def test_disabled_flow_log_fires(self):
        # Previously missed: flow log exists but is disabled — NSG must fail.
        cat = MagicMock()
        cat.network_security_groups.return_value = [_nsg(nsg_id=self._NSG_ID)]
        cat.nsg_flow_logs.return_value = [_flow_log(self._NSG_ID, enabled=False)]
        result = aznw002.check(cat)
        assert len(result) == 1
        assert result[0].passed is False, "disabled flow log must not satisfy logging requirement"

    def test_enabled_flow_log_passes(self):
        # True-positive: enabled flow log correctly credits the NSG.
        cat = MagicMock()
        cat.network_security_groups.return_value = [_nsg(nsg_id=self._NSG_ID)]
        cat.nsg_flow_logs.return_value = [_flow_log(self._NSG_ID, enabled=True)]
        result = aznw002.check(cat)
        assert len(result) == 1
        assert result[0].passed is True

    def test_no_flow_log_fires(self):
        # Existing true-positive: no flow log at all still fires.
        cat = MagicMock()
        cat.network_security_groups.return_value = [_nsg(nsg_id=self._NSG_ID)]
        cat.nsg_flow_logs.return_value = []
        result = aznw002.check(cat)
        assert len(result) == 1
        assert result[0].passed is False


class TestAZVM003JITAccessSecurityProfile:
    """AZVM-003: security_profile (Trusted Launch) must not masquerade as JIT."""

    def test_trusted_launch_vm_no_jit_tag_fires(self):
        # Previously missed: Gen2 VM with security_profile but no jit tag
        # was wrongly passing. It must now fire.
        vm = _vm(security_profile=MagicMock(), tags={})
        cat = MagicMock()
        cat.virtual_machines.return_value = [vm]
        result = azvm003.check(cat)
        assert len(result) == 1
        assert result[0].passed is False, "Trusted Launch VM without jit tag must fire"

    def test_jit_tag_passes(self):
        # A VM with an explicit jit tag should still pass.
        vm = _vm(security_profile=MagicMock(), tags={"jit-enabled": "true"})
        cat = MagicMock()
        cat.virtual_machines.return_value = [vm]
        result = azvm003.check(cat)
        assert len(result) == 1
        assert result[0].passed is True

    def test_no_profile_no_tag_fires(self):
        # Existing true-positive: plain VM with no markers must fire.
        vm = _vm(security_profile=None, tags={})
        cat = MagicMock()
        cat.virtual_machines.return_value = [vm]
        result = azvm003.check(cat)
        assert len(result) == 1
        assert result[0].passed is False


class TestAudit202607LowAzureCloud:
    """2026-07 audit LOW findings on the Azure-cloud rules."""

    def test_azst006_naive_key_creation_time_does_not_crash(self):
        from datetime import datetime, timedelta
        from types import SimpleNamespace as NS

        from pipeline_check.core.checks.azure_cloud.rules import (
            azst006_key_rotation as s6,
        )
        naive_old = datetime.now() - timedelta(days=200)  # tz-naive
        acct = NS(name="a", key_creation_time=NS(key1=naive_old, key2=None))
        res = s6.check(_catalog("storage_accounts", [acct]))
        assert res and res[0].passed is False

    def test_azsql003_secured_by_perimeter_is_not_public(self):
        from types import SimpleNamespace as NS

        from pipeline_check.core.checks.azure_cloud.rules import (
            azsql003_public_access as sq3,
        )
        srv = NS(name="s", public_network_access="SecuredByPerimeter")
        res = sq3.check(_catalog("sql_servers", [{"server": srv}]))
        assert res and res[0].passed is True
        srv2 = NS(name="s", public_network_access="Enabled")
        res = sq3.check(_catalog("sql_servers", [{"server": srv2}]))
        assert res and res[0].passed is False

    def test_azvm004_windows_automatic_by_platform_is_auto_patched(self):
        from types import SimpleNamespace as NS

        from pipeline_check.core.checks.azure_cloud.rules import (
            azvm004_auto_os_patching as v4,
        )
        vm = NS(name="v", os_profile=NS(
            windows_configuration=NS(
                enable_automatic_updates=False,
                patch_settings=NS(patch_mode="AutomaticByPlatform")),
            linux_configuration=None))
        res = v4.check(_catalog("virtual_machines", [vm]))
        assert res and res[0].passed is True


class TestAudit202607LowAzureCloudC1C2:
    """2026-07 audit LOW findings (azure_cloud_c1/c2 chunks)."""

    def test_akv004_none_kid_does_not_crash(self):
        from types import SimpleNamespace as NS

        from pipeline_check.core.checks.azure_cloud.rules import (
            akv004_key_expiry as k4,
        )
        cat = _catalog("key_vaults", [NS(name="v")])
        cat.key_vault_keys.return_value = [
            {"kid": None, "attributes": {"enabled": True, "exp": None}}]
        assert k4.check(cat) is not None  # no TypeError

    def test_acr002_deny_default_action_is_restricted(self):
        from types import SimpleNamespace as NS

        from pipeline_check.core.checks.azure_cloud.rules import (
            acr002_public_access as acr2,
        )
        reg = NS(name="r", public_network_access="Enabled",
                 network_rule_set=NS(default_action="Deny"))
        assert acr2.check(_catalog("container_registries", [reg]))[0].passed is True
        reg2 = NS(name="r", public_network_access="Enabled",
                  network_rule_set=NS(default_action="Allow"))
        assert acr2.check(_catalog("container_registries", [reg2]))[0].passed is False

    def test_azmon002_indefinite_does_not_mask_short_retention(self):
        from types import SimpleNamespace as NS

        from pipeline_check.core.checks.azure_cloud.rules import (
            azmon002_log_retention as mon2,
        )
        s = NS(name="s", logs=[
            NS(retention_policy=NS(enabled=True, days=0)),
            NS(retention_policy=NS(enabled=True, days=30))])
        assert mon2.check(_catalog("diagnostic_settings", [s]))[0].passed is False

    def test_aznw001_ipv6_any_source_detected(self):
        from types import SimpleNamespace as NS

        from pipeline_check.core.checks.azure_cloud.rules import (
            aznw001_ssh_rdp_internet as nw1,
        )
        rule = NS(direction="Inbound", access="Allow",
                  source_address_prefix="::/0", source_address_prefixes=[],
                  destination_port_range="22", destination_port_ranges=[])
        nsg = NS(name="n", security_rules=[rule])
        assert nw1.check(_catalog("network_security_groups", [nsg]))[0].passed is False
