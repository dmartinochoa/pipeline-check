"""Regression tests — azure_cloud rule audit batch 4 (false positive fixes).

Each class covers one rule.  For every fix there are two tests:
  - a *_passes test: the documented-safe input no longer triggers a finding
  - a *_fires test: a genuinely violating input still produces passed=False
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from pipeline_check.core.checks.azure_cloud._catalog import ResourceCatalog
from pipeline_check.core.checks.azure_cloud._session import AzureCloudSession
from pipeline_check.core.checks.azure_cloud.rules import (
    azmon002_log_retention as azmon002,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azmon005_nsg_flow_retention as azmon005,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    aznw004_deny_all_inbound as aznw004,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azsql001_tde_cmk as azsql001,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azst005_blob_lifecycle as azst005,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    azst006_key_rotation as azst006,
)
from pipeline_check.core.checks.base import Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_catalog(cache: dict) -> ResourceCatalog:
    session = AzureCloudSession(
        credential=MagicMock(), subscription_id="sub-test-123",
    )
    catalog = ResourceCatalog(session)
    catalog._cache.update(cache)
    return catalog


def _sql_server(key_id: str | None) -> dict:
    server = MagicMock()
    server.name = "test-sql"
    server.key_id = key_id
    server.public_network_access = "Disabled"
    auditing = MagicMock()
    auditing.state = "Enabled"
    threat = MagicMock()
    threat.state = "Enabled"
    return {"server": server, "auditing": auditing, "threat_detection": threat, "ad_admin": MagicMock()}


def _nsg_with_rule(
    direction: str,
    access: str,
    source_prefix: str = "",
    source_prefixes: list[str] | None = None,
    dest_port: str = "",
    dest_ports: list[str] | None = None,
) -> MagicMock:
    nsg = MagicMock()
    nsg.name = "test-nsg"
    nsg.id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/test-nsg"
    rule = MagicMock()
    rule.direction = direction
    rule.access = access
    rule.source_address_prefix = source_prefix
    rule.source_address_prefixes = source_prefixes or []
    rule.destination_port_range = dest_port
    rule.destination_port_ranges = dest_ports or []
    nsg.security_rules = [rule]
    return nsg


def _storage_account(kind: str = "StorageV2", key_creation_time=None) -> MagicMock:
    acct = MagicMock()
    acct.name = "testsa"
    acct.kind = kind
    acct.key_creation_time = key_creation_time
    acct.allow_blob_public_access = False
    acct.enable_https_traffic_only = True
    acct.minimum_tls_version = "TLS1_2"
    acct.encryption.key_source = "Microsoft.Storage"
    return acct


def _diagnostic_setting(days: int, enabled: bool = True) -> MagicMock:
    setting = MagicMock()
    setting.name = "diag1"
    log = MagicMock()
    log.retention_policy.enabled = enabled
    log.retention_policy.days = days
    setting.logs = [log]
    return setting


def _flow_log(days: int, enabled: bool = True) -> MagicMock:
    fl = MagicMock()
    fl.name = "fl-test"
    fl.target_resource_id = "/subscriptions/sub/rg/nsg1"
    fl.retention_policy.enabled = enabled
    fl.retention_policy.days = days
    return fl


# ---------------------------------------------------------------------------
# AZSQL-001 — TDE customer-managed key host suffix
# ---------------------------------------------------------------------------

class TestAZSQL001TdeCmk:
    """Broaden accepted Key Vault host suffixes."""

    def test_commercial_vault_passes(self):
        """Standard .vault.azure.net key passes (baseline)."""
        catalog = _make_catalog({"sql:servers": [
            _sql_server("https://myvault.vault.azure.net/keys/mykey/abc123"),
        ]})
        findings = azsql001.check(catalog)
        assert findings[0].passed is True

    def test_managed_hsm_passes(self):
        """Azure Managed HSM (.managedhsm.azure.net) is a valid CMK host."""
        catalog = _make_catalog({"sql:servers": [
            _sql_server("https://myhsm.managedhsm.azure.net/keys/mykey/abc123"),
        ]})
        findings = azsql001.check(catalog)
        assert findings[0].passed is True, (
            "Managed HSM key URI should be accepted as a valid CMK"
        )

    def test_us_gov_vault_passes(self):
        """US Government cloud vault (.vault.usgovcloudapi.net) passes."""
        catalog = _make_catalog({"sql:servers": [
            _sql_server("https://myvault.vault.usgovcloudapi.net/keys/mykey/v1"),
        ]})
        findings = azsql001.check(catalog)
        assert findings[0].passed is True

    def test_china_vault_passes(self):
        """Azure China cloud vault (.vault.azure.cn) passes."""
        catalog = _make_catalog({"sql:servers": [
            _sql_server("https://myvault.vault.azure.cn/keys/mykey/v1"),
        ]})
        findings = azsql001.check(catalog)
        assert findings[0].passed is True

    def test_no_cmk_fires(self):
        """A server with no key_id (service-managed TDE) still fires."""
        catalog = _make_catalog({"sql:servers": [_sql_server(None)]})
        findings = azsql001.check(catalog)
        assert findings[0].passed is False

    def test_invalid_host_fires(self):
        """An HTTPS URI with an unrecognized host is still rejected."""
        catalog = _make_catalog({"sql:servers": [
            _sql_server("https://myvault.evil.example.com/keys/mykey/v1"),
        ]})
        findings = azsql001.check(catalog)
        assert findings[0].passed is False

    def test_missing_keys_segment_fires(self):
        """A valid host but no /keys/ path segment is rejected."""
        catalog = _make_catalog({"sql:servers": [
            _sql_server("https://myvault.vault.azure.net/secrets/mykey/v1"),
        ]})
        findings = azsql001.check(catalog)
        assert findings[0].passed is False


# ---------------------------------------------------------------------------
# AZNW-004 — deny-all inbound NSG rule recognition
# ---------------------------------------------------------------------------

class TestAZNW004DenyAllInbound:
    """List forms and 0-65535 port range must be recognized."""

    def test_wildcard_star_passes(self):
        """Classic deny-all with src=* and dest=* passes (baseline)."""
        nsg = _nsg_with_rule("Inbound", "Deny", source_prefix="*", dest_port="*")
        catalog = _make_catalog({"network:nsgs": [nsg]})
        findings = aznw004.check(catalog)
        assert findings[0].passed is True

    def test_zero_65535_port_range_passes(self):
        """A deny-all written with dest port '0-65535' is accepted."""
        nsg = _nsg_with_rule("Inbound", "Deny", source_prefix="*", dest_port="0-65535")
        catalog = _make_catalog({"network:nsgs": [nsg]})
        findings = aznw004.check(catalog)
        assert findings[0].passed is True, (
            "destination_port_range='0-65535' should be treated as full-range"
        )

    def test_source_prefixes_list_passes(self):
        """A deny-all using source_address_prefixes=['*'] is accepted."""
        nsg = _nsg_with_rule(
            "Inbound", "Deny",
            source_prefix="",
            source_prefixes=["*"],
            dest_port="*",
        )
        catalog = _make_catalog({"network:nsgs": [nsg]})
        findings = aznw004.check(catalog)
        assert findings[0].passed is True, (
            "source_address_prefixes=['*'] should be accepted as wildcard"
        )

    def test_dest_ports_list_star_passes(self):
        """A deny-all using destination_port_ranges=['*'] is accepted."""
        nsg = _nsg_with_rule(
            "Inbound", "Deny",
            source_prefix="*",
            dest_port="",
            dest_ports=["*"],
        )
        catalog = _make_catalog({"network:nsgs": [nsg]})
        findings = aznw004.check(catalog)
        assert findings[0].passed is True

    def test_dest_ports_list_0_65535_passes(self):
        """A deny-all using destination_port_ranges=['0-65535'] is accepted."""
        nsg = _nsg_with_rule(
            "Inbound", "Deny",
            source_prefix="*",
            dest_port="",
            dest_ports=["0-65535"],
        )
        catalog = _make_catalog({"network:nsgs": [nsg]})
        findings = aznw004.check(catalog)
        assert findings[0].passed is True

    def test_missing_deny_all_fires(self):
        """An NSG with only an allow rule and no deny-all still fires."""
        nsg = _nsg_with_rule("Inbound", "Allow", source_prefix="*", dest_port="22")
        catalog = _make_catalog({"network:nsgs": [nsg]})
        findings = aznw004.check(catalog)
        assert findings[0].passed is False

    def test_outbound_deny_does_not_satisfy(self):
        """A deny-all on Outbound does not satisfy the Inbound requirement."""
        nsg = _nsg_with_rule("Outbound", "Deny", source_prefix="*", dest_port="*")
        catalog = _make_catalog({"network:nsgs": [nsg]})
        findings = aznw004.check(catalog)
        assert findings[0].passed is False


# ---------------------------------------------------------------------------
# AZST-005 — blob lifecycle title is advisory
# ---------------------------------------------------------------------------

class TestAZST005BlobLifecycle:
    """The title must reflect advisory (review) language, not definite absence."""

    def test_title_is_advisory(self):
        """The rule title must say 'should be reviewed', not assert absence."""
        assert "should be reviewed" in azst005.RULE.title.lower(), (
            f"Title should be advisory; got: '{azst005.RULE.title}'"
        )

    def test_blob_capable_account_fires(self):
        """A StorageV2 account always produces a finding (advisory)."""
        acct = _storage_account(kind="StorageV2")
        catalog = _make_catalog({"storage:accounts": [acct]})
        findings = azst005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_non_blob_kind_skipped(self):
        """Non-blob-capable account kinds are not flagged."""
        acct = _storage_account(kind="FileStorage")
        catalog = _make_catalog({"storage:accounts": [acct]})
        findings = azst005.check(catalog)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# AZST-006 — key_creation_time=None is advisory, not HIGH failure
# ---------------------------------------------------------------------------

class TestAZST006KeyRotation:
    """None key_creation_time must produce INFO/passed=True, not HIGH/passed=False."""

    def test_none_key_creation_time_passes(self):
        """No key_creation_time (no rotation policy set) must not be a hard failure."""
        acct = _storage_account(key_creation_time=None)
        catalog = _make_catalog({"storage:accounts": [acct]})
        findings = azst006.check(catalog)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.passed is True, (
            "key_creation_time=None should yield passed=True (advisory)"
        )
        assert finding.severity == Severity.INFO, (
            "key_creation_time=None advisory must be INFO severity"
        )

    def test_stale_keys_fires(self):
        """Keys older than 90 days must still produce a failed finding."""
        now = datetime.now(tz=UTC)
        key_creation = MagicMock()
        key_creation.key1 = now - timedelta(days=120)
        key_creation.key2 = now - timedelta(days=120)
        acct = _storage_account(key_creation_time=key_creation)
        catalog = _make_catalog({"storage:accounts": [acct]})
        findings = azst006.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_fresh_keys_passes(self):
        """Keys rotated within 90 days must pass."""
        now = datetime.now(tz=UTC)
        key_creation = MagicMock()
        key_creation.key1 = now - timedelta(days=10)
        key_creation.key2 = now - timedelta(days=10)
        acct = _storage_account(key_creation_time=key_creation)
        catalog = _make_catalog({"storage:accounts": [acct]})
        findings = azst006.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True


# ---------------------------------------------------------------------------
# AZMON-002 — days=0 with retention enabled means indefinite
# ---------------------------------------------------------------------------

class TestAZMON002LogRetention:
    """days=0 + enabled must be treated as indefinite/compliant."""

    def test_indefinite_retention_passes(self):
        """days=0 with retention enabled must pass (retain forever)."""
        catalog = _make_catalog({
            "monitor:diagnostic_settings": [_diagnostic_setting(days=0, enabled=True)],
        })
        findings = azmon002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True, (
            "days=0 + enabled means indefinite retention — should pass"
        )

    def test_adequate_retention_passes(self):
        """days=365 passes (baseline)."""
        catalog = _make_catalog({
            "monitor:diagnostic_settings": [_diagnostic_setting(days=365, enabled=True)],
        })
        findings = azmon002.check(catalog)
        assert findings[0].passed is True

    def test_short_retention_fires(self):
        """days=30 with enabled=True still fires."""
        catalog = _make_catalog({
            "monitor:diagnostic_settings": [_diagnostic_setting(days=30, enabled=True)],
        })
        findings = azmon002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_days_zero_retention_disabled_ignored(self):
        """days=0 with enabled=False is not treated as a retention policy."""
        catalog = _make_catalog({
            "monitor:diagnostic_settings": [_diagnostic_setting(days=0, enabled=False)],
        })
        findings = azmon002.check(catalog)
        # enabled=False means the policy is not applied; min_retention stays None → passed
        assert findings[0].passed is True


# ---------------------------------------------------------------------------
# AZMON-005 — NSG flow log days=0 with retention enabled means indefinite
# ---------------------------------------------------------------------------

class TestAZMON005NsgFlowRetention:
    """days=0 + enabled must be treated as indefinite/compliant."""

    def test_indefinite_retention_passes(self):
        """days=0 with retention enabled must pass (retain forever)."""
        catalog = _make_catalog({
            "network:flow_logs": [_flow_log(days=0, enabled=True)],
        })
        findings = azmon005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True, (
            "days=0 + enabled means indefinite retention — should pass"
        )

    def test_adequate_retention_passes(self):
        """days=90 passes (baseline)."""
        catalog = _make_catalog({
            "network:flow_logs": [_flow_log(days=90, enabled=True)],
        })
        findings = azmon005.check(catalog)
        assert findings[0].passed is True

    def test_short_retention_fires(self):
        """days=30 with enabled=True still fires."""
        catalog = _make_catalog({
            "network:flow_logs": [_flow_log(days=30, enabled=True)],
        })
        findings = azmon005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_retention_disabled_fires(self):
        """No retention policy enabled still fires."""
        catalog = _make_catalog({
            "network:flow_logs": [_flow_log(days=0, enabled=False)],
        })
        findings = azmon005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
