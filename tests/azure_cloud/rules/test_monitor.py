"""Tests for AZMON-001, AZMON-002, and AZMON-003 rules."""
from __future__ import annotations

from unittest.mock import MagicMock

from pipeline_check.core.checks.azure_cloud.rules import (
    azmon001_diagnostic_setting as azmon001,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azmon002_log_retention as azmon002,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azmon003_alert_rule as azmon003,
)

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _diagnostic_setting(
    name: str = "diag-1",
    log_entries: list[tuple[bool, int]] | None = None,
) -> MagicMock:
    """Build a mock diagnostic setting.

    Each tuple in *log_entries* is ``(retention_enabled, retention_days)``.
    Pass ``None`` for no logs attribute.
    """
    setting = MagicMock()
    setting.name = name
    if log_entries is None:
        setting.logs = []
    else:
        logs = []
        for enabled, days in log_entries:
            log = MagicMock()
            log.retention_policy.enabled = enabled
            log.retention_policy.days = days
            logs.append(log)
        setting.logs = logs
    return setting


# -----------------------------------------------------------------------
# AZMON-001  No diagnostic setting for subscription Activity Log
# -----------------------------------------------------------------------

class TestAzmon001:
    def test_no_settings_fails(self, make_catalog):
        catalog = make_catalog(**{"monitor:diagnostic_settings": []})
        findings = azmon001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZMON-001"

    def test_has_settings_passes(self, make_catalog):
        setting = _diagnostic_setting()
        catalog = make_catalog(**{"monitor:diagnostic_settings": [setting]})
        findings = azmon001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_multiple_settings_passes(self, make_catalog):
        s1 = _diagnostic_setting(name="diag-1")
        s2 = _diagnostic_setting(name="diag-2")
        catalog = make_catalog(**{"monitor:diagnostic_settings": [s1, s2]})
        findings = azmon001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert "2" in findings[0].description


# -----------------------------------------------------------------------
# AZMON-002  Activity Log retention less than 365 days
# -----------------------------------------------------------------------

class TestAzmon002:
    def test_short_retention_fails(self, make_catalog):
        setting = _diagnostic_setting(
            name="short-diag",
            log_entries=[(True, 30)],
        )
        catalog = make_catalog(**{"monitor:diagnostic_settings": [setting]})
        findings = azmon002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZMON-002"

    def test_365_day_retention_passes(self, make_catalog):
        setting = _diagnostic_setting(
            name="compliant-diag",
            log_entries=[(True, 365)],
        )
        catalog = make_catalog(**{"monitor:diagnostic_settings": [setting]})
        findings = azmon002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_retention_policy_passes(self, make_catalog):
        """No explicit retention policy means managed at the destination."""
        setting = _diagnostic_setting(name="no-rp-diag", log_entries=[])
        catalog = make_catalog(**{"monitor:diagnostic_settings": [setting]})
        findings = azmon002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_retention_not_enabled_passes(self, make_catalog):
        """Retention policy exists but enabled=False: treated as no retention."""
        setting = _diagnostic_setting(
            name="off-diag",
            log_entries=[(False, 7)],
        )
        catalog = make_catalog(**{"monitor:diagnostic_settings": [setting]})
        findings = azmon002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_diagnostic_settings_returns_empty(self, make_catalog):
        catalog = make_catalog(**{"monitor:diagnostic_settings": []})
        findings = azmon002.check(catalog)
        assert findings == []

    def test_min_across_multiple_logs(self, make_catalog):
        """When multiple log categories exist, the minimum retention drives the finding."""
        setting = _diagnostic_setting(
            name="multi-diag",
            log_entries=[(True, 400), (True, 100)],
        )
        catalog = make_catalog(**{"monitor:diagnostic_settings": [setting]})
        findings = azmon002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False


# -----------------------------------------------------------------------
# AZMON-003  No alert rule for critical administrative operations
# -----------------------------------------------------------------------

class TestAzmon003:
    def test_no_alerts_fails(self, make_catalog):
        catalog = make_catalog(**{"monitor:activity_log_alerts": []})
        findings = azmon003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZMON-003"

    def test_has_alerts_passes(self, make_catalog):
        alert = MagicMock()
        catalog = make_catalog(**{"monitor:activity_log_alerts": [alert]})
        findings = azmon003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_multiple_alerts_passes(self, make_catalog):
        alerts = [MagicMock(), MagicMock(), MagicMock()]
        catalog = make_catalog(**{"monitor:activity_log_alerts": alerts})
        findings = azmon003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert "3" in findings[0].description
