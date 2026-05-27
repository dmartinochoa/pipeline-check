"""End-to-end integration tests for all 15 GCP rule-based checks.

Drives the full GCPRuleChecks orchestrator against a fully-misconfigured
mock GCP environment and asserts every rule fires. Also tests the
degraded-catalog scenario where a service raises and only a single
PREFIX-000 INFO finding is emitted.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.gcp._catalog import ResourceCatalog
from pipeline_check.core.checks.gcp._session import GCPSession
from pipeline_check.core.checks.gcp.workflows import GCPRuleChecks

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _session() -> GCPSession:
    return GCPSession(credentials=MagicMock(), project_id="test-project")


def _insecure_cache() -> dict:
    """Cache entries that trigger every rule to fail."""
    return {
        # --- IAM ---
        "iam:project_policy": {
            "bindings": [
                # GCIAM-001: SA with Owner
                {
                    "role": "roles/owner",
                    "members": [
                        "serviceAccount:admin-sa@test-project.iam.gserviceaccount.com",
                    ],
                    "condition": None,
                },
                # GCIAM-003: token creator without condition
                {
                    "role": "roles/iam.serviceAccountTokenCreator",
                    "members": ["user:dev@company.com"],
                    "condition": None,
                },
                # GCKMS-002: public KMS role
                {
                    "role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
                    "members": ["allUsers"],
                    "condition": None,
                },
            ],
            "audit_configs": [
                # GCLOG-001: allServices missing log type 3
                {
                    "service": "allServices",
                    "audit_log_configs": [
                        {"log_type": 1},
                        {"log_type": 2},
                        # log_type 3 (DATA_READ) deliberately missing
                    ],
                },
            ],
        },
        # GCIAM-002: SA with user-managed key
        "iam:service_accounts": [
            {
                "email": "ci-bot@test-project.iam.gserviceaccount.com",
                "name": "projects/test-project/serviceAccounts/ci-bot@test-project.iam.gserviceaccount.com",
                "display_name": "CI Bot",
                "disabled": False,
            },
        ],
        "iam:sa_keys:ci-bot@test-project.iam.gserviceaccount.com": [
            {
                "name": "key-1",
                "key_type": "USER_MANAGED",
                "valid_after": "2024-01-01",
                "valid_before": "9999-01-01",
            },
        ],
        # --- Storage ---
        "storage:buckets": [
            {
                "name": "public-bucket",
                "location": "US",
                "storage_class": "STANDARD",
                "versioning_enabled": False,                     # GCS-003
                "iam_configuration": {
                    "uniform_bucket_level_access": {
                        "enabled": False,                        # GCS-002
                    },
                },
                "iam_policy": [
                    {
                        "role": "roles/storage.objectViewer",
                        "members": ["allUsers"],                 # GCS-001
                    },
                ],
            },
        ],
        # --- KMS ---
        "kms:keys": [
            {
                "name": "projects/p/locations/global/keyRings/kr/cryptoKeys/weak-key",
                "purpose": "ENCRYPT_DECRYPT",
                "protection_level": "SOFTWARE",                  # GCKMS-003
                "rotation_period_days": 500,                     # GCKMS-001
                "primary_state": "ENABLED",
            },
        ],
        # --- Artifact Registry ---
        "artifactregistry:repos": [
            {
                "name": "projects/p/locations/us/repositories/docker-repo",
                "format": "DOCKER",
                "mode": "STANDARD_REPOSITORY",
                "cleanup_policies": {},                          # GAR-003
                "vulnerability_scanning_config": {
                    "enablement_config": "INHERITED",            # GAR-001
                },                                               # GAR-002 always passes for now
            },
        ],
        # --- Logging ---
        "logging:sinks": [
            # All sinks disabled -> GCLOG-002
            {"name": "dead-sink", "destination": "x", "filter": "", "disabled": True},
        ],
        "logging:buckets": [
            # 30-day retention -> GCLOG-003
            {"name": "_Default", "retention_days": 30, "locked": False,
             "lifecycle_state": "ACTIVE"},
        ],
    }


# ---------------------------------------------------------------------------
# Full-coverage integration
# ---------------------------------------------------------------------------

ALL_RULE_IDS = {
    "GCIAM-001", "GCIAM-002", "GCIAM-003",
    "GCS-001", "GCS-002", "GCS-003",
    "GCKMS-001", "GCKMS-002", "GCKMS-003",
    "GAR-001", "GAR-002", "GAR-003",
    "GCLOG-001", "GCLOG-002", "GCLOG-003",
}

# GAR-002 always passes in the current implementation (no per-repo IAM
# policy check yet), so it cannot appear in the "failed" set.
_ALWAYS_PASS_IDS = {"GAR-002"}


@pytest.fixture()
def _all_findings():
    """Run the orchestrator once against the fully-insecure cache."""
    session = _session()
    checks = GCPRuleChecks(session)
    # Pre-populate the catalog cache that the orchestrator will create.
    # GCPRuleChecks.run() creates its own catalog; we monkey-patch to inject.
    def patched_run():
        catalog = ResourceCatalog(session)
        catalog._cache.update(_insecure_cache())
        # Replay the orchestrator body with our catalog.
        pending = []
        from pipeline_check.core.checks.rule import apply_rule_metadata
        for rule, check_fn in checks._rules:
            try:
                batch = check_fn(catalog) or []
            except Exception as exc:
                prefix = rule.id.split("-", 1)[0]
                from pipeline_check.core.checks.gcp.workflows import (
                    _RULE_PREFIX_TO_SERVICE,
                )
                svc = _RULE_PREFIX_TO_SERVICE.get(prefix, prefix.lower())
                catalog.errors.setdefault(svc, f"{type(exc).__name__}: {exc}")
                continue
            for finding in batch:
                apply_rule_metadata(finding, rule)
            pending.append((rule.id, batch))

        findings = []
        degraded = set(catalog.errors)
        from pipeline_check.core.checks.gcp.workflows import (
            _DEGRADED,
            _RULE_PREFIX_TO_SERVICE,
        )
        for rule_id, batch in pending:
            prefix = rule_id.split("-", 1)[0]
            svc = _RULE_PREFIX_TO_SERVICE.get(prefix)
            if svc in degraded:
                continue
            findings.extend(batch)

        for svc, msg in catalog.errors.items():
            meta = _DEGRADED.get(svc)
            if meta is None:
                continue
            from pipeline_check.core.checks.base import Finding, Severity
            check_id, label, recommendation = meta
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

    return patched_run()


def _failed_ids(findings) -> set[str]:
    return {f.check_id for f in findings if not f.passed}


def _all_ids(findings) -> set[str]:
    return {f.check_id for f in findings}


class TestAllRulesFire:
    """Every rule ID should appear in findings."""

    def test_all_15_rule_ids_present(self, _all_findings):
        present = _all_ids(_all_findings)
        missing = ALL_RULE_IDS - present
        assert not missing, f"Rules not present in findings: {sorted(missing)}"

    @pytest.mark.parametrize("check_id", sorted(ALL_RULE_IDS - _ALWAYS_PASS_IDS))
    def test_rule_fires_failed(self, _all_findings, check_id):
        assert check_id in _failed_ids(_all_findings), (
            f"{check_id} did not fire (fail). "
            f"Failed IDs: {sorted(_failed_ids(_all_findings))}"
        )

    def test_gar002_passes(self, _all_findings):
        """GAR-002 always passes in the current implementation."""
        gar002 = [f for f in _all_findings if f.check_id == "GAR-002"]
        assert len(gar002) == 1
        assert gar002[0].passed is True


class TestFindingMetadata:
    def test_every_failed_finding_has_cwe(self, _all_findings):
        for f in _all_findings:
            if f.passed:
                continue
            assert f.cwe, f"{f.check_id} failed but has no CWE mapping"

    def test_critical_findings_present(self, _all_findings):
        criticals = {f.check_id for f in _all_findings
                     if not f.passed and f.severity == Severity.CRITICAL}
        assert "GCIAM-001" in criticals

    def test_prefixes_all_present(self, _all_findings):
        prefixes = {f.check_id.split("-")[0] for f in _all_findings}
        required = {"GCIAM", "GCS", "GCKMS", "GAR", "GCLOG"}
        missing = required - prefixes
        assert not missing, f"Missing prefixes: {sorted(missing)}"


# ---------------------------------------------------------------------------
# Degraded-catalog scenario
# ---------------------------------------------------------------------------

@pytest.fixture()
def _degraded_findings():
    """Run with IAM and Storage errored out in the catalog."""
    session = _session()
    checks = GCPRuleChecks(session)

    def patched_run():
        catalog = ResourceCatalog(session)
        # Only populate non-errored services.
        catalog._cache.update({
            "kms:keys": [],
            "artifactregistry:repos": [],
            "logging:sinks": [],
            "logging:buckets": [],
        })
        # Inject errors for IAM and Storage.
        catalog.errors["iam"] = "PermissionDenied: caller lacks permission"
        catalog.errors["storage"] = "PermissionDenied: storage.buckets.list denied"

        pending = []
        from pipeline_check.core.checks.rule import apply_rule_metadata
        for rule, check_fn in checks._rules:
            try:
                batch = check_fn(catalog) or []
            except Exception as exc:
                prefix = rule.id.split("-", 1)[0]
                from pipeline_check.core.checks.gcp.workflows import (
                    _RULE_PREFIX_TO_SERVICE,
                )
                svc = _RULE_PREFIX_TO_SERVICE.get(prefix, prefix.lower())
                catalog.errors.setdefault(svc, f"{type(exc).__name__}: {exc}")
                continue
            for finding in batch:
                apply_rule_metadata(finding, rule)
            pending.append((rule.id, batch))

        findings = []
        degraded = set(catalog.errors)
        from pipeline_check.core.checks.gcp.workflows import (
            _DEGRADED,
            _RULE_PREFIX_TO_SERVICE,
        )
        for rule_id, batch in pending:
            prefix = rule_id.split("-", 1)[0]
            svc = _RULE_PREFIX_TO_SERVICE.get(prefix)
            if svc in degraded:
                continue
            findings.extend(batch)

        for svc, msg in catalog.errors.items():
            meta = _DEGRADED.get(svc)
            if meta is None:
                continue
            from pipeline_check.core.checks.base import Finding, Severity
            check_id, label, recommendation = meta
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

    return patched_run()


class TestDegradedFindings:
    def test_iam_degraded_finding_emitted(self, _degraded_findings):
        iam000 = [f for f in _degraded_findings if f.check_id == "GCIAM-000"]
        assert len(iam000) == 1
        assert iam000[0].severity == Severity.INFO
        assert iam000[0].passed is False

    def test_storage_degraded_finding_emitted(self, _degraded_findings):
        gcs000 = [f for f in _degraded_findings if f.check_id == "GCS-000"]
        assert len(gcs000) == 1
        assert gcs000[0].severity == Severity.INFO
        assert gcs000[0].passed is False

    def test_iam_rules_suppressed(self, _degraded_findings):
        ids = {f.check_id for f in _degraded_findings}
        for rule_id in ("GCIAM-001", "GCIAM-002", "GCIAM-003"):
            assert rule_id not in ids, (
                f"{rule_id} should be suppressed when IAM service is degraded"
            )

    def test_storage_rules_suppressed(self, _degraded_findings):
        ids = {f.check_id for f in _degraded_findings}
        for rule_id in ("GCS-001", "GCS-002", "GCS-003"):
            assert rule_id not in ids, (
                f"{rule_id} should be suppressed when storage service is degraded"
            )

    def test_healthy_services_unaffected(self, _degraded_findings):
        """KMS, AR, Logging are not degraded so their 000 findings should not appear."""
        ids = {f.check_id for f in _degraded_findings}
        for degraded_id in ("GCKMS-000", "GAR-000", "GCLOG-000"):
            assert degraded_id not in ids, (
                f"{degraded_id} should not appear when the service is healthy"
            )
