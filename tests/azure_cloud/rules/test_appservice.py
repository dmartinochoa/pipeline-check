"""Tests for AZAPP-001..005 App Service rules."""
from __future__ import annotations

from unittest.mock import MagicMock

from pipeline_check.core.checks.azure_cloud.rules import (
    azapp001_https_only as azapp001,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azapp002_min_tls as azapp002,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azapp003_managed_identity as azapp003,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azapp004_remote_debugging as azapp004,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azapp005_ftp_disabled as azapp005,
)

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _web_app(
    name: str = "myapp",
    *,
    https_only: bool = True,
    min_tls: str = "1.2",
    identity_type: str = "SystemAssigned",
    remote_debugging: bool = False,
    ftp_state: str = "Disabled",
) -> dict:
    app = MagicMock()
    app.name = name
    app.https_only = https_only
    identity = MagicMock()
    identity.type = identity_type
    app.identity = identity if identity_type != "None" else None

    config = MagicMock()
    config.min_tls_version = min_tls
    config.remote_debugging_enabled = remote_debugging
    config.ftp_state = ftp_state

    return {"app": app, "config": config}


# -----------------------------------------------------------------------
# AZAPP-001  App Service does not enforce HTTPS
# -----------------------------------------------------------------------

class TestAzapp001:
    def test_https_disabled_fails(self, make_catalog):
        entry = _web_app(https_only=False)
        catalog = make_catalog(**{"appservice:web_apps": [entry]})
        findings = azapp001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZAPP-001"

    def test_https_enabled_passes(self, make_catalog):
        entry = _web_app(https_only=True)
        catalog = make_catalog(**{"appservice:web_apps": [entry]})
        findings = azapp001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_empty_apps(self, make_catalog):
        catalog = make_catalog(**{"appservice:web_apps": []})
        findings = azapp001.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZAPP-002  App Service minimum TLS version below 1.2
# -----------------------------------------------------------------------

class TestAzapp002:
    def test_tls10_fails(self, make_catalog):
        entry = _web_app(min_tls="1.0")
        catalog = make_catalog(**{"appservice:web_apps": [entry]})
        findings = azapp002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZAPP-002"

    def test_tls12_passes(self, make_catalog):
        entry = _web_app(min_tls="1.2")
        catalog = make_catalog(**{"appservice:web_apps": [entry]})
        findings = azapp002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_config_defaults_fail(self, make_catalog):
        app = MagicMock()
        app.name = "noconfig"
        catalog = make_catalog(**{"appservice:web_apps": [{"app": app, "config": None}]})
        findings = azapp002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_apps(self, make_catalog):
        catalog = make_catalog(**{"appservice:web_apps": []})
        findings = azapp002.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZAPP-003  App Service does not use a managed identity
# -----------------------------------------------------------------------

class TestAzapp003:
    def test_no_identity_fails(self, make_catalog):
        entry = _web_app(identity_type="None")
        catalog = make_catalog(**{"appservice:web_apps": [entry]})
        findings = azapp003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZAPP-003"

    def test_system_assigned_passes(self, make_catalog):
        entry = _web_app(identity_type="SystemAssigned")
        catalog = make_catalog(**{"appservice:web_apps": [entry]})
        findings = azapp003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_user_assigned_passes(self, make_catalog):
        entry = _web_app(identity_type="UserAssigned")
        catalog = make_catalog(**{"appservice:web_apps": [entry]})
        findings = azapp003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_empty_apps(self, make_catalog):
        catalog = make_catalog(**{"appservice:web_apps": []})
        findings = azapp003.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZAPP-004  App Service has remote debugging enabled
# -----------------------------------------------------------------------

class TestAzapp004:
    def test_remote_debug_enabled_fails(self, make_catalog):
        entry = _web_app(remote_debugging=True)
        catalog = make_catalog(**{"appservice:web_apps": [entry]})
        findings = azapp004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZAPP-004"

    def test_remote_debug_disabled_passes(self, make_catalog):
        entry = _web_app(remote_debugging=False)
        catalog = make_catalog(**{"appservice:web_apps": [entry]})
        findings = azapp004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_config_passes(self, make_catalog):
        app = MagicMock()
        app.name = "noconfig"
        catalog = make_catalog(**{"appservice:web_apps": [{"app": app, "config": None}]})
        findings = azapp004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_empty_apps(self, make_catalog):
        catalog = make_catalog(**{"appservice:web_apps": []})
        findings = azapp004.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZAPP-005  App Service FTP access not disabled
# -----------------------------------------------------------------------

class TestAzapp005:
    def test_ftp_allallowed_fails(self, make_catalog):
        entry = _web_app(ftp_state="AllAllowed")
        catalog = make_catalog(**{"appservice:web_apps": [entry]})
        findings = azapp005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZAPP-005"

    def test_ftp_disabled_passes(self, make_catalog):
        entry = _web_app(ftp_state="Disabled")
        catalog = make_catalog(**{"appservice:web_apps": [entry]})
        findings = azapp005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_ftps_only_passes(self, make_catalog):
        entry = _web_app(ftp_state="FtpsOnly")
        catalog = make_catalog(**{"appservice:web_apps": [entry]})
        findings = azapp005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_config_defaults_fail(self, make_catalog):
        app = MagicMock()
        app.name = "noconfig"
        catalog = make_catalog(**{"appservice:web_apps": [{"app": app, "config": None}]})
        findings = azapp005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_apps(self, make_catalog):
        catalog = make_catalog(**{"appservice:web_apps": []})
        findings = azapp005.check(catalog)
        assert findings == []
