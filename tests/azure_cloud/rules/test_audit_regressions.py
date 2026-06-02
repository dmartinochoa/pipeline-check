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
