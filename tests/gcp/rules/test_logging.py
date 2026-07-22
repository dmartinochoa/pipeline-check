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


# -----------------------------------------------------------------------
# GCLOG-004: VPC Flow Logs not enabled on subnet
# -----------------------------------------------------------------------

from pipeline_check.core.checks.gcp.rules import gclog004_vpc_flow_logs


class TestGCLOG004:
    def test_flow_logs_enabled_passes(self, make_catalog):
        cat = make_catalog(**{
            "network:subnetworks": [
                {"name": "sub-1", "region": "us-central1",
                 "log_config": {"enable": True}},
            ],
        })
        findings = gclog004_vpc_flow_logs.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "GCLOG-004"

    def test_flow_logs_disabled_fails(self, make_catalog):
        cat = make_catalog(**{
            "network:subnetworks": [
                {"name": "sub-2", "region": "us-east1",
                 "log_config": {"enable": False}},
            ],
        })
        findings = gclog004_vpc_flow_logs.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_subnets_returns_empty(self, make_catalog):
        cat = make_catalog(**{"network:subnetworks": []})
        assert gclog004_vpc_flow_logs.check(cat) == []


# -----------------------------------------------------------------------
# GCLOG-005: Firewall rule logging not enabled
# -----------------------------------------------------------------------

from pipeline_check.core.checks.gcp.rules import gclog005_firewall_logging


class TestGCLOG005:
    def test_logging_enabled_passes(self, make_catalog):
        cat = make_catalog(**{
            "network:firewalls": [
                {"name": "fw-1", "disabled": False,
                 "direction": "INGRESS", "source_ranges": [],
                 "allowed": [], "log_config": {"enable": True}},
            ],
        })
        findings = gclog005_firewall_logging.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "GCLOG-005"

    def test_logging_disabled_fails(self, make_catalog):
        cat = make_catalog(**{
            "network:firewalls": [
                {"name": "fw-2", "disabled": False,
                 "direction": "INGRESS", "source_ranges": [],
                 "allowed": [], "log_config": {"enable": False}},
            ],
        })
        findings = gclog005_firewall_logging.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_disabled_rule_skipped(self, make_catalog):
        cat = make_catalog(**{
            "network:firewalls": [
                {"name": "fw-off", "disabled": True,
                 "direction": "INGRESS", "source_ranges": [],
                 "allowed": [], "log_config": {"enable": False}},
            ],
        })
        findings = gclog005_firewall_logging.check(cat)
        assert findings == []

    def test_no_firewalls_returns_empty(self, make_catalog):
        cat = make_catalog(**{"network:firewalls": []})
        assert gclog005_firewall_logging.check(cat) == []


# -----------------------------------------------------------------------
# GCLOG-006: Critical service missing Data Access audit log types
# -----------------------------------------------------------------------

from pipeline_check.core.checks.gcp.rules import gclog006_data_access_specific


class TestGCLOG006:
    def test_all_types_for_all_services_passes(self, make_catalog):
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [],
                "audit_configs": [
                    {"service": "allServices",
                     "audit_log_configs": [
                         {"log_type": 1}, {"log_type": 2}, {"log_type": 3},
                     ]},
                ],
            },
        })
        findings = gclog006_data_access_specific.check(cat)
        assert len(findings) == 3  # One per critical service
        assert all(f.passed for f in findings)

    def test_missing_type_for_service_fails(self, make_catalog):
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [],
                "audit_configs": [
                    {"service": "storage.googleapis.com",
                     "audit_log_configs": [{"log_type": 1}]},
                ],
            },
        })
        findings = gclog006_data_access_specific.check(cat)
        # storage has types {1}, missing {2,3}; iam and compute have none
        failed = [f for f in findings if not f.passed]
        assert len(failed) == 3  # All 3 services missing something

    def test_empty_policy_returns_empty(self, make_catalog):
        cat = make_catalog(**{"iam:project_policy": {}})
        assert gclog006_data_access_specific.check(cat) == []


# -----------------------------------------------------------------------
# GCLOG-007: No log metric filter for IAM policy changes
# -----------------------------------------------------------------------

from pipeline_check.core.checks.gcp.rules import gclog007_metric_filter_iam


class TestGCLOG007:
    def test_metric_with_setiam_passes(self, make_catalog):
        cat = make_catalog(**{
            "logging:metrics": [
                {"name": "iam-changes", "filter": 'protoPayload.methodName="SetIamPolicy"',
                 "description": ""},
            ],
        })
        findings = gclog007_metric_filter_iam.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "GCLOG-007"

    def test_no_metric_fails(self, make_catalog):
        cat = make_catalog(**{"logging:metrics": []})
        findings = gclog007_metric_filter_iam.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_unrelated_metric_fails(self, make_catalog):
        cat = make_catalog(**{
            "logging:metrics": [
                {"name": "other", "filter": "resource.type=gce_instance",
                 "description": ""},
            ],
        })
        findings = gclog007_metric_filter_iam.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False


# -----------------------------------------------------------------------
# GCLOG-008: No log metric filter for firewall rule changes
# -----------------------------------------------------------------------

from pipeline_check.core.checks.gcp.rules import gclog008_metric_filter_firewall


class TestGCLOG008:
    def test_metric_with_firewall_passes(self, make_catalog):
        cat = make_catalog(**{
            "logging:metrics": [
                {"name": "fw-changes", "filter": 'resource.type="gce_firewall_rule"',
                 "description": ""},
            ],
        })
        findings = gclog008_metric_filter_firewall.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "GCLOG-008"

    def test_no_metric_fails(self, make_catalog):
        cat = make_catalog(**{"logging:metrics": []})
        findings = gclog008_metric_filter_firewall.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False


# -----------------------------------------------------------------------
# GCLOG-009: No log metric filter for route changes
# -----------------------------------------------------------------------

from pipeline_check.core.checks.gcp.rules import gclog009_metric_filter_route


class TestGCLOG009:
    def test_metric_with_route_passes(self, make_catalog):
        cat = make_catalog(**{
            "logging:metrics": [
                {"name": "route-changes", "filter": 'resource.type="gce_route"',
                 "description": ""},
            ],
        })
        findings = gclog009_metric_filter_route.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "GCLOG-009"

    def test_no_metric_fails(self, make_catalog):
        cat = make_catalog(**{"logging:metrics": []})
        findings = gclog009_metric_filter_route.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False


# -----------------------------------------------------------------------
# GCLOG-010: No log metric filter for Cloud SQL config changes
# -----------------------------------------------------------------------

from pipeline_check.core.checks.gcp.rules import gclog010_metric_filter_sql


class TestGCLOG010:
    def test_metric_with_sql_passes(self, make_catalog):
        cat = make_catalog(**{
            "logging:metrics": [
                {"name": "sql-changes",
                 "filter": 'protoPayload.methodName="cloudsql.instances.update"',
                 "description": ""},
            ],
        })
        findings = gclog010_metric_filter_sql.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "GCLOG-010"

    def test_no_metric_fails(self, make_catalog):
        cat = make_catalog(**{"logging:metrics": []})
        findings = gclog010_metric_filter_sql.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False


# -----------------------------------------------------------------------
# GCLOG-011: No log metric filter for custom role changes
# -----------------------------------------------------------------------

from pipeline_check.core.checks.gcp.rules import gclog011_metric_filter_custom_role


class TestGCLOG011:
    def test_metric_with_iam_role_passes(self, make_catalog):
        cat = make_catalog(**{
            "logging:metrics": [
                {"name": "role-changes", "filter": 'resource.type="iam_role"',
                 "description": ""},
            ],
        })
        findings = gclog011_metric_filter_custom_role.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "GCLOG-011"

    def test_no_metric_fails(self, make_catalog):
        cat = make_catalog(**{"logging:metrics": []})
        findings = gclog011_metric_filter_custom_role.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False


class TestAudit202607LowLogging:
    """2026-07 audit LOW findings on the GCLOG metric-filter / audit rules."""

    def test_gclog001_exempted_members_fail(self, make_catalog):
        # FN: an allServices config with all three log types but a broad
        # exemption lets those principals bypass Data Access logging.
        cat = make_catalog(**{"iam:project_policy": {"bindings": [],
            "audit_configs": [{"service": "allServices", "audit_log_configs": [
                {"log_type": 1, "exempted_members": ["user:svc@example.com"]},
                {"log_type": 2}, {"log_type": 3}]}]}})
        f = gclog001_audit_config.check(cat)
        assert f[0].passed is False
        assert "exempt" in f[0].description.lower()

    def test_gclog007_camelcase_setiampolicy_passes(self, make_catalog):
        # FP: compute methodNames are camelCase setIamPolicy.
        cat = make_catalog(**{"logging:metrics": [
            {"filter": 'protoPayload.methodName="v1.compute.instances.setIamPolicy"'}]})
        assert gclog007_metric_filter_iam.check(cat)[0].passed is True

    def test_gclog008_methodname_firewall_passes(self, make_catalog):
        cat = make_catalog(**{"logging:metrics": [
            {"filter": 'protoPayload.methodName:("compute.firewalls.insert")'}]})
        assert gclog008_metric_filter_firewall.check(cat)[0].passed is True

    def test_gclog009_methodname_route_passes(self, make_catalog):
        cat = make_catalog(**{"logging:metrics": [
            {"filter": 'protoPayload.methodName:("compute.routes.insert")'}]})
        assert gclog009_metric_filter_route.check(cat)[0].passed is True

    def test_gclog010_has_operator_cloudsql_passes(self, make_catalog):
        cat = make_catalog(**{"logging:metrics": [
            {"filter": 'protoPayload.methodName:"cloudsql.instances"'}]})
        assert gclog010_metric_filter_sql.check(cat)[0].passed is True

    def test_gclog007_unrelated_filter_still_fails(self, make_catalog):
        cat = make_catalog(**{"logging:metrics": [
            {"filter": 'resource.type="gce_instance"'}]})
        assert gclog007_metric_filter_iam.check(cat)[0].passed is False


class TestAudit202607Gclog011:
    """GCLOG-011 affirmative role-change filter match (not bare substring)."""

    def test_methodname_only_filter_passes(self, make_catalog):
        cat = make_catalog(**{"logging:metrics": [{"filter":
            'protoPayload.methodName="google.iam.admin.v1.CreateRole" OR '
            'protoPayload.methodName="google.iam.admin.v1.DeleteRole"'}]})
        assert gclog011_metric_filter_custom_role.check(cat)[0].passed is True

    def test_negated_resource_type_does_not_satisfy(self, make_catalog):
        cat = make_catalog(**{"logging:metrics": [
            {"filter": 'resource.type!="iam_role" AND severity>=ERROR'}]})
        assert gclog011_metric_filter_custom_role.check(cat)[0].passed is False
