"""GCLOG-001/002/003 -- Cloud Logging checks."""
from __future__ import annotations

from pipeline_check.core.checks.gcp.rules import (
    gclog001_audit_config,
    gclog002_log_sink,
    gclog003_retention,
)

# -----------------------------------------------------------------------
# GCLOG-001: Cloud Audit Logs not enabled for all services
# -----------------------------------------------------------------------

class TestGCLOG001:
    def test_all_log_types_enabled_passes(self, make_catalog):
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [],
                "audit_configs": [
                    {
                        "service": "allServices",
                        "audit_log_configs": [
                            {"log_type": 1},  # ADMIN_READ
                            {"log_type": 2},  # DATA_WRITE
                            {"log_type": 3},  # DATA_READ
                        ],
                    },
                ],
            },
        })
        findings = gclog001_audit_config.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_missing_log_type_fails(self, make_catalog):
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [],
                "audit_configs": [
                    {
                        "service": "allServices",
                        "audit_log_configs": [
                            {"log_type": 1},  # ADMIN_READ only
                        ],
                    },
                ],
            },
        })
        findings = gclog001_audit_config.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert "missing" in findings[0].description.lower()

    def test_no_allservices_config_fails(self, make_catalog):
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [],
                "audit_configs": [
                    {
                        "service": "bigquery.googleapis.com",
                        "audit_log_configs": [
                            {"log_type": 1}, {"log_type": 2}, {"log_type": 3},
                        ],
                    },
                ],
            },
        })
        findings = gclog001_audit_config.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert "No allServices" in findings[0].description

    def test_empty_audit_configs_fails(self, make_catalog):
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [],
                "audit_configs": [],
            },
        })
        findings = gclog001_audit_config.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_policy_returns_empty(self, make_catalog):
        """Falsy policy (empty dict) returns no findings."""
        cat = make_catalog(**{"iam:project_policy": {}})
        findings = gclog001_audit_config.check(cat)
        assert findings == []

    def test_resource_includes_project_id(self, make_catalog):
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [],
                "audit_configs": [],
            },
        })
        findings = gclog001_audit_config.check(cat)
        assert findings[0].resource == "projects/my-project"


# -----------------------------------------------------------------------
# GCLOG-002: no log sink configured for audit logs
# -----------------------------------------------------------------------

class TestGCLOG002:
    def test_active_sink_passes(self, make_catalog):
        cat = make_catalog(**{
            "logging:sinks": [
                {"name": "audit-export", "destination": "bigquery.googleapis.com/...",
                 "filter": "", "disabled": False},
            ],
        })
        findings = gclog002_log_sink.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert "1 active log sink" in findings[0].description

    def test_only_disabled_sink_fails(self, make_catalog):
        cat = make_catalog(**{
            "logging:sinks": [
                {"name": "old-export", "destination": "storage.googleapis.com/...",
                 "filter": "", "disabled": True},
            ],
        })
        findings = gclog002_log_sink.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_sinks_fails(self, make_catalog):
        cat = make_catalog(**{"logging:sinks": []})
        findings = gclog002_log_sink.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert "No active log sinks" in findings[0].description

    def test_mixed_active_disabled_passes(self, make_catalog):
        """At least one active sink is enough to pass."""
        cat = make_catalog(**{
            "logging:sinks": [
                {"name": "dead", "destination": "x", "filter": "", "disabled": True},
                {"name": "live", "destination": "y", "filter": "", "disabled": False},
            ],
        })
        findings = gclog002_log_sink.check(cat)
        assert findings[0].passed is True

    def test_resource_includes_project_id(self, make_catalog):
        cat = make_catalog(**{"logging:sinks": []})
        findings = gclog002_log_sink.check(cat)
        assert findings[0].resource == "projects/my-project"


# -----------------------------------------------------------------------
# GCLOG-003: log bucket retention less than 365 days
# -----------------------------------------------------------------------

class TestGCLOG003:
    def test_retention_30_days_fails(self, make_catalog):
        cat = make_catalog(**{
            "logging:buckets": [
                {"name": "_Default", "retention_days": 30,
                 "locked": False, "lifecycle_state": "ACTIVE"},
            ],
        })
        findings = gclog003_retention.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert "30 days" in findings[0].description

    def test_retention_365_days_passes(self, make_catalog):
        cat = make_catalog(**{
            "logging:buckets": [
                {"name": "_Default", "retention_days": 365,
                 "locked": True, "lifecycle_state": "ACTIVE"},
            ],
        })
        findings = gclog003_retention.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_retention_400_days_passes(self, make_catalog):
        cat = make_catalog(**{
            "logging:buckets": [
                {"name": "custom", "retention_days": 400,
                 "locked": False, "lifecycle_state": "ACTIVE"},
            ],
        })
        findings = gclog003_retention.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_missing_retention_defaults_to_30_fails(self, make_catalog):
        """When retention_days is absent, the rule defaults to 30."""
        cat = make_catalog(**{
            "logging:buckets": [{"name": "_Default"}],
        })
        findings = gclog003_retention.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_buckets_returns_empty(self, make_catalog):
        cat = make_catalog(**{"logging:buckets": []})
        assert gclog003_retention.check(cat) == []

    def test_multiple_buckets(self, make_catalog):
        cat = make_catalog(**{
            "logging:buckets": [
                {"name": "_Default", "retention_days": 30,
                 "locked": False, "lifecycle_state": "ACTIVE"},
                {"name": "long-term", "retention_days": 730,
                 "locked": True, "lifecycle_state": "ACTIVE"},
            ],
        })
        findings = gclog003_retention.check(cat)
        assert len(findings) == 2
        passed_map = {f.resource: f.passed for f in findings}
        assert passed_map["_Default"] is False
        assert passed_map["long-term"] is True
