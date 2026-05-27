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

def _insecure_cache() -> dict[str, object]:
    now = datetime.now(tz=UTC)
    return {
        # Storage -- AZST-001, AZST-002, AZST-003
        "storage:accounts": [_storage_account()],
        # Key Vault -- AKV-001, AKV-002, AKV-003
        "keyvault:vaults": [_key_vault()],
        # ACR -- ACR-001, ACR-002, ACR-003
        "acr:registries": [_registry()],
        # Monitor -- AZMON-001 passes (settings exist), AZMON-002 fails
        # (short retention), AZMON-003 fails (no alerts)
        "monitor:diagnostic_settings": [_diagnostic_setting_short_retention()],
        "monitor:activity_log_alerts": [],
        # Authorization + Entra -- ENTRA-001, ENTRA-002, ENTRA-003
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
    "AZST-001", "AZST-002", "AZST-003",
    "AKV-001", "AKV-002", "AKV-003",
    "ACR-001", "ACR-002", "ACR-003",
    "AZMON-001", "AZMON-002", "AZMON-003",
}


class TestFullIntegration:
    """All 15 Azure Cloud rules must produce a finding."""

    @pytest.mark.parametrize("check_id", sorted(_ALL_RULE_IDS))
    def test_rule_present(self, _all_findings, check_id):
        ids = _all_ids(_all_findings)
        assert check_id in ids, (
            f"{check_id} not in findings. Present: {sorted(ids)}"
        )

    @pytest.mark.parametrize("check_id", sorted(
        _ALL_RULE_IDS - {"AZMON-001"},  # AZMON-001 passes (settings exist)
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

    def test_all_prefixes_present(self, _all_findings):
        prefixes = {f.check_id.split("-")[0] for f in _all_findings}
        required = {"ENTRA", "AZST", "AKV", "ACR", "AZMON"}
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
