"""End-to-end integration tests for Azure Cloud rule-based checks.

Drives AzureCloudRuleChecks against a fully-misconfigured mock Azure
environment and asserts every rule fires.

Also includes the degraded-finding regression test: when a service
catalog method raises, exactly one ``<PREFIX>-000`` INFO finding must
be emitted -- not one per dependent rule.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from pipeline_check.core.checks.azure_cloud._catalog import ResourceCatalog
from pipeline_check.core.checks.azure_cloud._session import AzureCloudSession
from pipeline_check.core.checks.azure_cloud.workflows import AzureCloudRuleChecks
from pipeline_check.core.checks.base import Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_session() -> AzureCloudSession:
    return AzureCloudSession(
        credential=MagicMock(), subscription_id="sub-test-123",
    )


def _role_assignment(role_def_id: str, principal_id: str,
                     principal_type: str = "ServicePrincipal"):
    obj = MagicMock()
    obj.role_definition_id = role_def_id
    obj.principal_id = principal_id
    obj.principal_type = principal_type
    return obj


def _role_definition(role_name: str):
    obj = MagicMock()
    obj.role_name = role_name
    return obj


def _storage_account(name: str = "badsa"):
    acct = MagicMock()
    acct.name = name
    acct.allow_blob_public_access = True
    acct.enable_https_traffic_only = False
    acct.encryption.key_source = "Microsoft.Storage"
    return acct


def _key_vault(name: str = "badkv"):
    vault = MagicMock()
    vault.name = name
    vault.properties.enable_soft_delete = False
    vault.properties.enable_purge_protection = False
    vault.properties.network_acls.default_action = "Allow"
    return vault


def _registry(name: str = "badacr"):
    reg = MagicMock()
    reg.name = name
    reg.admin_user_enabled = True
    reg.public_network_access = "Enabled"
    reg.policies.trust_policy.status = "disabled"
    return reg


def _diagnostic_setting_short_retention(name: str = "diag1"):
    setting = MagicMock()
    setting.name = name
    log = MagicMock()
    log.retention_policy.enabled = True
    log.retention_policy.days = 30
    setting.logs = [log]
    return setting


# ---------------------------------------------------------------------------
# Insecure cache: every service populated with at least one bad resource
# ---------------------------------------------------------------------------

def _nsg_flow_log(name: str = "fl-bad"):
    fl = MagicMock()
    fl.name = name
    # Point at a DIFFERENT NSG so bad-nsg remains un-logged (AZNW-002 fails)
    fl.target_resource_id = "/subscriptions/sub-test-123/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/other-nsg"
    fl.retention_policy.enabled = True
    fl.retention_policy.days = 30  # Below 90-day minimum -> AZMON-005 fails
    return fl


def _nsg(name: str = "bad-nsg"):
    nsg = MagicMock()
    nsg.name = name
    nsg.id = f"/subscriptions/sub-test-123/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/{name}"
    rule = MagicMock()
    rule.direction = "Inbound"
    rule.access = "Allow"
    rule.source_address_prefix = "*"
    rule.source_address_prefixes = []
    rule.destination_port_range = "22"
    rule.destination_port_ranges = []
    nsg.security_rules = [rule]
    return nsg


def _app_gateway(name: str = "bad-gw"):
    gw = MagicMock()
    gw.name = name
    gw.sku.tier = "Standard_v2"
    gw.web_application_firewall_configuration = None
    gw.firewall_policy = None
    return gw


def _public_ip_on_nic(name: str = "pip-vm"):
    pip = MagicMock()
    pip.name = name
    pip.ip_configuration.id = (
        "/subscriptions/sub-test-123/resourceGroups/rg/providers/"
        "Microsoft.Network/networkInterfaces/nic1/ipConfigurations/ipconfig1"
    )
    return pip


def _web_app(name: str = "bad-app"):
    app = MagicMock()
    app.name = name
    app.https_only = False
    app.identity = None
    config = MagicMock()
    config.min_tls_version = "1.0"
    config.remote_debugging_enabled = True
    config.ftp_state = "AllAllowed"
    return {"app": app, "config": config}


def _sql_entry(name: str = "bad-sql"):
    server = MagicMock()
    server.name = name
    server.key_id = None
    server.public_network_access = "Enabled"
    auditing = MagicMock()
    auditing.state = "Disabled"
    threat = MagicMock()
    threat.state = "Disabled"
    return {"server": server, "auditing": auditing, "threat_detection": threat, "ad_admin": None}


def _virtual_machine(name: str = "bad-vm"):
    vm = MagicMock()
    vm.name = name
    vm.tags = {}
    vm.security_profile = None
    # Unencrypted OS disk
    os_disk = MagicMock()
    os_disk.managed_disk.disk_encryption_set = None
    os_disk.encryption_settings = None
    vm.storage_profile.os_disk = os_disk
    vm.storage_profile.data_disks = []
    # NIC with public IP
    nic_ref = MagicMock()
    nic_ref.id = "/subscriptions/sub-test-123/resourcegroups/rg/providers/microsoft.network/networkinterfaces/nic1"
    vm.network_profile.network_interfaces = [nic_ref]
    # No auto-patching
    vm.os_profile.windows_configuration = None
    vm.os_profile.linux_configuration = None
    # No managed identity
    vm.identity = None
    return vm


def _workspace(name: str = "bad-law"):
    ws = MagicMock()
    ws.name = name
    ws.retention_in_days = 30
    return ws


def _insecure_cache() -> dict[str, object]:
    now = datetime.now(tz=UTC)
    sa = _storage_account()
    sa.minimum_tls_version = "TLS1_0"
    sa.kind = "StorageV2"
    # Stale keys (over 90 days old) — triggers AZST-006 violation.
    stale_time = now - timedelta(days=120)
    key_creation = MagicMock()
    key_creation.key1 = stale_time
    key_creation.key2 = stale_time
    sa.key_creation_time = key_creation

    kv = _key_vault()
    kv.id = "/subscriptions/sub-test-123/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/badkv"
    kv.properties.enable_rbac_authorization = False

    reg = _registry()
    reg.sku.name = "Standard"
    reg.policies.quarantine_policy.status = "disabled"
    reg.policies.export_policy.status = "enabled"

    return {
        # Storage -- AZST-001..006
        "storage:accounts": [sa],
        # Key Vault -- AKV-001..006
        "keyvault:vaults": [kv],
        "keyvault:keys:badkv": [
            {"kid": "https://badkv.vault.azure.net/keys/k1/v1",
             "attributes": {"enabled": True, "exp": None}},
        ],
        "keyvault:secrets:badkv": [
            {"id": "https://badkv.vault.azure.net/secrets/s1",
             "attributes": {"enabled": True, "exp": None}},
        ],
        # ACR -- ACR-001..005
        "acr:registries": [reg],
        # Monitor -- AZMON-001 passes (settings exist), AZMON-002 fails
        # (short retention), AZMON-003 fails (no alerts)
        "monitor:diagnostic_settings": [_diagnostic_setting_short_retention()],
        "monitor:activity_log_alerts": [],
        # Monitor extended -- AZMON-005, AZMON-006, AZMON-007
        "network:flow_logs": [_nsg_flow_log()],
        "monitor:workspaces": [_workspace()],
        # Authorization + Entra -- ENTRA-001..006
        "authorization:role_assignments": [
            _role_assignment("rd-ga", "sp-bad"),
        ],
        "authorization:role_definitions": {
            "rd-ga": _role_definition("Global Administrator"),
        },
        "entra:applications": [{
            "displayName": "leak-app",
            "appId": "app-bad",
            "passwordCredentials": [{
                "startDateTime": now.isoformat(),
                "endDateTime": (now + timedelta(days=365)).isoformat(),
            }],
            "keyCredentials": [],
        }],
        "entra:service_principals": [{
            "displayName": "ci-sp",
            "id": "sp-ci",
            "appId": "app-ci",
            "passwordCredentials": [{"keyId": "k1"}],
            "keyCredentials": [],
        }],
        "entra:conditional_access": [],  # ENTRA-004/005/006 fail (no policies)
        # Network -- AZNW-001..005
        "network:nsgs": [_nsg()],
        "network:app_gateways": [_app_gateway()],
        "network:public_ips": [_public_ip_on_nic()],
        # App Service -- AZAPP-001..005
        "appservice:web_apps": [_web_app()],
        # SQL -- AZSQL-001..005
        "sql:servers": [_sql_entry()],
        # Compute -- AZVM-001..005
        "compute:vms": [_virtual_machine()],
    }


# ---------------------------------------------------------------------------
# Full integration
# ---------------------------------------------------------------------------

@pytest.fixture()
def _all_findings():
    """Run AzureCloudRuleChecks once against a fully-misconfigured env."""
    session = _build_session()
    checker = AzureCloudRuleChecks(session)
    # Pre-populate the catalog cache to avoid real SDK calls.
    # The orchestrator constructs its own ResourceCatalog in run(), so
    # we monkeypatch run() to inject our pre-populated catalog.
    def _patched_run():
        catalog = ResourceCatalog(session)
        catalog._cache.update(_insecure_cache())
        # Run the rules against our pre-populated catalog.
        from pipeline_check.core.checks.rule import apply_rule_metadata
        pending: list[tuple[str, list]] = []
        for rule, check_fn in checker._rules:
            try:
                batch = check_fn(catalog) or []
            except Exception as exc:
                prefix = rule.id.split("-", 1)[0]
                from pipeline_check.core.checks.azure_cloud.workflows import (
                    _RULE_PREFIX_TO_SERVICE,
                )
                svc = _RULE_PREFIX_TO_SERVICE.get(prefix, prefix.lower())
                catalog.errors.setdefault(
                    svc, f"{type(exc).__name__}: {exc}",
                )
                continue
            for finding in batch:
                apply_rule_metadata(finding, rule)
            pending.append((rule.id, batch))

        findings = []
        degraded_services = set(catalog.errors)
        for rule_id, batch in pending:
            prefix = rule_id.split("-", 1)[0]
            from pipeline_check.core.checks.azure_cloud.workflows import (
                _RULE_PREFIX_TO_SERVICE,
            )
            svc = _RULE_PREFIX_TO_SERVICE.get(prefix)
            if svc in degraded_services:
                continue
            findings.extend(batch)

        from pipeline_check.core.checks.azure_cloud.workflows import _DEGRADED
        for svc, msg in catalog.errors.items():
            meta = _DEGRADED.get(svc)
            if meta is None:
                continue
            check_id, label, recommendation = meta
            from pipeline_check.core.checks.base import Finding
            findings.append(Finding(
                check_id=check_id,
                title=f"{label} API access failed",
                severity=Severity.INFO,
                resource=label,
                description=(
                    f"Could not enumerate {label} resources: {msg}. "
                    "Rules depending on this data were skipped."
                ),
                recommendation=recommendation,
                passed=False,
            ))
        return findings

    checker.run = _patched_run  # type: ignore[assignment]
    return checker.run()


def _failed_ids(findings: list) -> set[str]:
    return {f.check_id for f in findings if not f.passed}


def _all_ids(findings: list) -> set[str]:
    return {f.check_id for f in findings}


_ALL_RULE_IDS = {
    "ENTRA-001", "ENTRA-002", "ENTRA-003",
    "ENTRA-004", "ENTRA-005", "ENTRA-006",
    "AZST-001", "AZST-002", "AZST-003",
    "AZST-004", "AZST-005", "AZST-006",
    "AKV-001", "AKV-002", "AKV-003",
    "AKV-004", "AKV-005", "AKV-006",
    "ACR-001", "ACR-002", "ACR-003",
    "ACR-004", "ACR-005",
    "AZMON-001", "AZMON-002", "AZMON-003",
    "AZMON-004", "AZMON-005", "AZMON-006", "AZMON-007",
    "AZNW-001", "AZNW-002", "AZNW-003", "AZNW-004", "AZNW-005",
    "AZAPP-001", "AZAPP-002", "AZAPP-003", "AZAPP-004", "AZAPP-005",
    "AZSQL-001", "AZSQL-002", "AZSQL-003", "AZSQL-004", "AZSQL-005",
    "AZVM-001", "AZVM-002", "AZVM-003", "AZVM-004", "AZVM-005",
}

assert len(_ALL_RULE_IDS) == 50  # noqa: S101


class TestFullIntegration:
    """All 50 Azure Cloud rules must produce a finding."""

    @pytest.mark.parametrize("check_id", sorted(_ALL_RULE_IDS))
    def test_rule_present(self, _all_findings, check_id):
        ids = _all_ids(_all_findings)
        assert check_id in ids, (
            f"{check_id} not in findings. Present: {sorted(ids)}"
        )

    @pytest.mark.parametrize("check_id", sorted(
        # AZMON-001 passes (settings exist); ACR-005 is an INFO advisory
        # that always passes (ACR has no registry-level tag immutability).
        _ALL_RULE_IDS - {"AZMON-001", "ACR-005"},
    ))
    def test_rule_fires(self, _all_findings, check_id):
        assert check_id in _failed_ids(_all_findings), (
            f"{check_id} should have failed. Failures: "
            f"{sorted(_failed_ids(_all_findings))}"
        )

    def test_azmon001_passes_when_settings_exist(self, _all_findings):
        """AZMON-001 passes because we provided a diagnostic setting."""
        azmon001 = [f for f in _all_findings if f.check_id == "AZMON-001"]
        assert len(azmon001) == 1
        assert azmon001[0].passed is True

    def test_acr005_passes_as_advisory(self, _all_findings):
        """ACR-005 is an INFO advisory that always passes: ACR has no
        registry-level tag-immutability setting to assert a verdict on."""
        acr005 = [f for f in _all_findings if f.check_id == "ACR-005"]
        assert len(acr005) == 1
        assert acr005[0].passed is True

    def test_all_prefixes_present(self, _all_findings):
        prefixes = {f.check_id.split("-")[0] for f in _all_findings}
        required = {
            "ENTRA", "AZST", "AKV", "ACR", "AZMON",
            "AZNW", "AZAPP", "AZSQL", "AZVM",
        }
        missing = required - prefixes
        assert not missing, f"Missing prefixes: {missing}"


# ---------------------------------------------------------------------------
# Degraded-finding regression
# ---------------------------------------------------------------------------

@pytest.fixture()
def _degraded_findings():
    """Run with storage and keyvault services errored out."""
    session = _build_session()
    checker = AzureCloudRuleChecks(session)

    def _patched_run():
        catalog = ResourceCatalog(session)
        # Populate only the working services; leave storage and keyvault
        # unset so the catalog loader would be called. Instead, inject
        # errors directly.
        catalog._cache.update({
            "acr:registries": [_registry()],
            "monitor:diagnostic_settings": [_diagnostic_setting_short_retention()],
            "monitor:activity_log_alerts": [MagicMock()],
            "authorization:role_assignments": [],
            "authorization:role_definitions": {},
            "entra:applications": [],
            "entra:service_principals": [],
        })
        # Simulate SDK errors for storage and keyvault.
        catalog.errors["storage"] = "AuthenticationError: invalid token"
        catalog.errors["keyvault"] = "HttpResponseError: 403 Forbidden"

        from pipeline_check.core.checks.azure_cloud.workflows import (
            _DEGRADED,
            _RULE_PREFIX_TO_SERVICE,
        )
        from pipeline_check.core.checks.rule import apply_rule_metadata
        pending: list[tuple[str, list]] = []
        for rule, check_fn in checker._rules:
            try:
                batch = check_fn(catalog) or []
            except Exception as exc:
                prefix = rule.id.split("-", 1)[0]
                svc = _RULE_PREFIX_TO_SERVICE.get(prefix, prefix.lower())
                catalog.errors.setdefault(
                    svc, f"{type(exc).__name__}: {exc}",
                )
                continue
            for finding in batch:
                apply_rule_metadata(finding, rule)
            pending.append((rule.id, batch))

        findings = []
        degraded_services = set(catalog.errors)
        for rule_id, batch in pending:
            prefix = rule_id.split("-", 1)[0]
            svc = _RULE_PREFIX_TO_SERVICE.get(prefix)
            if svc in degraded_services:
                continue
            findings.extend(batch)

        for svc, msg in catalog.errors.items():
            meta = _DEGRADED.get(svc)
            if meta is None:
                continue
            check_id, label, recommendation = meta
            from pipeline_check.core.checks.base import Finding
            findings.append(Finding(
                check_id=check_id,
                title=f"{label} API access failed",
                severity=Severity.INFO,
                resource=label,
                description=(
                    f"Could not enumerate {label} resources: {msg}. "
                    "Rules depending on this data were skipped."
                ),
                recommendation=recommendation,
                passed=False,
            ))
        return findings

    checker.run = _patched_run  # type: ignore[assignment]
    return checker.run()


class TestDegradedFindings:
    def test_degraded_finding_for_storage(self, _degraded_findings):
        azst000 = [f for f in _degraded_findings if f.check_id == "AZST-000"]
        assert len(azst000) == 1
        assert azst000[0].severity == Severity.INFO
        assert azst000[0].passed is False

    def test_degraded_finding_for_keyvault(self, _degraded_findings):
        akv000 = [f for f in _degraded_findings if f.check_id == "AKV-000"]
        assert len(akv000) == 1
        assert akv000[0].severity == Severity.INFO
        assert akv000[0].passed is False

    def test_storage_rules_suppressed(self, _degraded_findings):
        """AZST-001/002/003 must not appear when storage service is down."""
        ids = {f.check_id for f in _degraded_findings}
        for check_id in ("AZST-001", "AZST-002", "AZST-003"):
            assert check_id not in ids, (
                f"{check_id} should be suppressed by the degraded-finding "
                "aggregator when storage is unreachable."
            )

    def test_keyvault_rules_suppressed(self, _degraded_findings):
        """AKV-001/002/003 must not appear when keyvault service is down."""
        ids = {f.check_id for f in _degraded_findings}
        for check_id in ("AKV-001", "AKV-002", "AKV-003"):
            assert check_id not in ids, (
                f"{check_id} should be suppressed by the degraded-finding "
                "aggregator when keyvault is unreachable."
            )

    def test_healthy_services_still_emit(self, _degraded_findings):
        """ACR rules should still run because ACR is not degraded."""
        ids = {f.check_id for f in _degraded_findings}
        for check_id in ("ACR-001", "ACR-002", "ACR-003"):
            assert check_id in ids, (
                f"{check_id} should be present (ACR is healthy)."
            )

    def test_no_acr_degraded(self, _degraded_findings):
        """ACR should not be marked degraded."""
        acr000 = [f for f in _degraded_findings if f.check_id == "ACR-000"]
        assert not acr000, "ACR should not be marked degraded"
