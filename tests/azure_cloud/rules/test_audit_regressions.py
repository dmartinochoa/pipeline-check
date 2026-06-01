"""Regression tests from the rule audit (Entra crash / FN fixes)."""
from __future__ import annotations

from unittest.mock import MagicMock

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
