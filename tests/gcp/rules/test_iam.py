"""GCIAM-001/002/003 -- IAM service account checks."""
from __future__ import annotations

from pipeline_check.core.checks.gcp.rules import (
    gciam001_sa_admin,
    gciam002_user_managed_key,
    gciam003_sa_impersonation,
)

# -----------------------------------------------------------------------
# GCIAM-001: SA has Owner or Editor role
# -----------------------------------------------------------------------

class TestGCIAM001:
    def test_sa_with_owner_fails(self, make_catalog):
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [
                    {
                        "role": "roles/owner",
                        "members": ["serviceAccount:admin@my-project.iam.gserviceaccount.com"],
                        "condition": None,
                    },
                ],
                "audit_configs": [],
            },
        })
        findings = gciam001_sa_admin.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert "admin@my-project" in findings[0].resource

    def test_sa_with_editor_fails(self, make_catalog):
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [
                    {
                        "role": "roles/editor",
                        "members": ["serviceAccount:ci@my-project.iam.gserviceaccount.com"],
                        "condition": None,
                    },
                ],
                "audit_configs": [],
            },
        })
        findings = gciam001_sa_admin.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_sa_with_viewer_passes(self, make_catalog):
        """A scoped role should not fire the rule."""
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [
                    {
                        "role": "roles/viewer",
                        "members": ["serviceAccount:reader@my-project.iam.gserviceaccount.com"],
                        "condition": None,
                    },
                ],
                "audit_configs": [],
            },
        })
        findings = gciam001_sa_admin.check(cat)
        assert findings == []

    def test_human_owner_ignored(self, make_catalog):
        """Human users with Owner are not flagged by this SA-specific rule."""
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [
                    {
                        "role": "roles/owner",
                        "members": ["user:admin@company.com"],
                        "condition": None,
                    },
                ],
                "audit_configs": [],
            },
        })
        findings = gciam001_sa_admin.check(cat)
        assert findings == []

    def test_empty_policy_returns_empty(self, make_catalog):
        cat = make_catalog(**{"iam:project_policy": {}})
        findings = gciam001_sa_admin.check(cat)
        assert findings == []

    def test_no_policy_returns_empty(self, make_catalog):
        """When catalog returns falsy (e.g. empty dict), no findings."""
        cat = make_catalog(**{"iam:project_policy": {}})
        assert gciam001_sa_admin.check(cat) == []


# -----------------------------------------------------------------------
# GCIAM-002: SA has user-managed key
# -----------------------------------------------------------------------

class TestGCIAM002:
    def test_user_managed_key_fails(self, make_catalog):
        cat = make_catalog(**{
            "iam:service_accounts": [
                {"email": "ci@my-project.iam.gserviceaccount.com",
                 "name": "projects/my-project/serviceAccounts/ci@my-project.iam.gserviceaccount.com",
                 "display_name": "CI Bot", "disabled": False},
            ],
            "iam:sa_keys:ci@my-project.iam.gserviceaccount.com": [
                {"name": "key-1", "key_type": "USER_MANAGED",
                 "valid_after": "2024-01-01", "valid_before": "9999-01-01"},
            ],
        })
        findings = gciam002_user_managed_key.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert "1 user-managed key" in findings[0].description

    def test_system_managed_only_passes(self, make_catalog):
        cat = make_catalog(**{
            "iam:service_accounts": [
                {"email": "ci@my-project.iam.gserviceaccount.com",
                 "name": "n", "display_name": "", "disabled": False},
            ],
            "iam:sa_keys:ci@my-project.iam.gserviceaccount.com": [
                {"name": "key-1", "key_type": "SYSTEM_MANAGED",
                 "valid_after": "2024-01-01", "valid_before": "9999-01-01"},
            ],
        })
        findings = gciam002_user_managed_key.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_disabled_sa_skipped(self, make_catalog):
        """Disabled service accounts should be ignored entirely."""
        cat = make_catalog(**{
            "iam:service_accounts": [
                {"email": "old@my-project.iam.gserviceaccount.com",
                 "name": "n", "display_name": "", "disabled": True},
            ],
            "iam:sa_keys:old@my-project.iam.gserviceaccount.com": [
                {"name": "key-1", "key_type": "USER_MANAGED",
                 "valid_after": "2024-01-01", "valid_before": "9999-01-01"},
            ],
        })
        findings = gciam002_user_managed_key.check(cat)
        assert findings == []

    def test_no_service_accounts_returns_empty(self, make_catalog):
        cat = make_catalog(**{"iam:service_accounts": []})
        findings = gciam002_user_managed_key.check(cat)
        assert findings == []

    def test_multiple_user_keys_counted(self, make_catalog):
        cat = make_catalog(**{
            "iam:service_accounts": [
                {"email": "ci@proj.iam.gserviceaccount.com",
                 "name": "n", "display_name": "", "disabled": False},
            ],
            "iam:sa_keys:ci@proj.iam.gserviceaccount.com": [
                {"name": "k1", "key_type": "USER_MANAGED",
                 "valid_after": "2024-01-01", "valid_before": "9999-01-01"},
                {"name": "k2", "key_type": "USER_MANAGED",
                 "valid_after": "2024-06-01", "valid_before": "9999-01-01"},
            ],
        })
        findings = gciam002_user_managed_key.check(cat)
        assert findings[0].passed is False
        assert "2 user-managed key" in findings[0].description


# -----------------------------------------------------------------------
# GCIAM-003: SA token creator granted without constraint
# -----------------------------------------------------------------------

class TestGCIAM003:
    def test_token_creator_without_condition_fails(self, make_catalog):
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [
                    {
                        "role": "roles/iam.serviceAccountTokenCreator",
                        "members": ["user:dev@company.com"],
                        "condition": None,
                    },
                ],
                "audit_configs": [],
            },
        })
        findings = gciam003_sa_impersonation.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_sa_user_without_condition_fails(self, make_catalog):
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [
                    {
                        "role": "roles/iam.serviceAccountUser",
                        "members": ["serviceAccount:ci@proj.iam.gserviceaccount.com"],
                        "condition": None,
                    },
                ],
                "audit_configs": [],
            },
        })
        findings = gciam003_sa_impersonation.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_token_creator_with_condition_passes(self, make_catalog):
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [
                    {
                        "role": "roles/iam.serviceAccountTokenCreator",
                        "members": ["user:dev@company.com"],
                        "condition": {
                            "title": "restrict-sa",
                            "expression": "resource.name == 'projects/-/serviceAccounts/target@proj.iam.gserviceaccount.com'",
                        },
                    },
                ],
                "audit_configs": [],
            },
        })
        findings = gciam003_sa_impersonation.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_unrelated_role_ignored(self, make_catalog):
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [
                    {
                        "role": "roles/viewer",
                        "members": ["user:dev@company.com"],
                        "condition": None,
                    },
                ],
                "audit_configs": [],
            },
        })
        findings = gciam003_sa_impersonation.check(cat)
        assert findings == []

    def test_empty_condition_expression_fails(self, make_catalog):
        """A condition with an empty expression string should be treated as no condition."""
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [
                    {
                        "role": "roles/iam.serviceAccountTokenCreator",
                        "members": ["user:dev@company.com"],
                        "condition": {"title": "", "expression": ""},
                    },
                ],
                "audit_configs": [],
            },
        })
        findings = gciam003_sa_impersonation.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False


# -----------------------------------------------------------------------
# GCIAM-004: Compute instance uses default service account
# -----------------------------------------------------------------------

from pipeline_check.core.checks.gcp.rules import gciam004_default_sa_instances


class TestGCIAM004:
    def test_default_sa_fails(self, make_catalog):
        cat = make_catalog(**{
            "compute:instances": [
                {"name": "vm-1",
                 "service_accounts": ["12345-compute@developer.gserviceaccount.com"]},
            ],
        })
        findings = gciam004_default_sa_instances.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCIAM-004"

    def test_custom_sa_passes(self, make_catalog):
        cat = make_catalog(**{
            "compute:instances": [
                {"name": "vm-2",
                 "service_accounts": ["my-sa@my-project.iam.gserviceaccount.com"]},
            ],
        })
        findings = gciam004_default_sa_instances.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_instances_returns_empty(self, make_catalog):
        cat = make_catalog(**{"compute:instances": []})
        assert gciam004_default_sa_instances.check(cat) == []


# -----------------------------------------------------------------------
# GCIAM-005: Domain-restricted sharing constraint not enforced
# -----------------------------------------------------------------------

from pipeline_check.core.checks.gcp.rules import gciam005_domain_restricted_sharing


class TestGCIAM005:
    def test_constraint_with_rules_passes(self, make_catalog):
        cat = make_catalog(**{
            "iam:org_policies": [
                {"name": "projects/my-project/policies/iam.allowedPolicyMemberDomains",
                 "spec": {"rules": [{"values": {"allowedValues": ["C12345"]}}]}},
            ],
        })
        findings = gciam005_domain_restricted_sharing.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "GCIAM-005"

    def test_constraint_without_rules_fails(self, make_catalog):
        cat = make_catalog(**{
            "iam:org_policies": [
                {"name": "projects/my-project/policies/iam.allowedPolicyMemberDomains",
                 "spec": {"rules": []}},
            ],
        })
        findings = gciam005_domain_restricted_sharing.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_constraint_fails(self, make_catalog):
        cat = make_catalog(**{"iam:org_policies": []})
        findings = gciam005_domain_restricted_sharing.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False


# -----------------------------------------------------------------------
# GCIAM-006: Service account key older than 90 days
# -----------------------------------------------------------------------

from pipeline_check.core.checks.gcp.rules import gciam006_sa_key_age


class TestGCIAM006:
    def test_old_key_fails(self, make_catalog):
        cat = make_catalog(**{
            "iam:service_accounts": [
                {"email": "ci@proj.iam.gserviceaccount.com",
                 "name": "n", "display_name": "", "disabled": False},
            ],
            "iam:sa_keys:ci@proj.iam.gserviceaccount.com": [
                {"name": "old-key", "key_type": "USER_MANAGED",
                 "valid_after": "2024-01-01T00:00:00Z", "valid_before": "9999-01-01"},
            ],
        })
        findings = gciam006_sa_key_age.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCIAM-006"

    def test_fresh_key_passes(self, make_catalog):
        from datetime import UTC, datetime, timedelta
        recent = (datetime.now(tz=UTC) - timedelta(days=10)).isoformat()
        cat = make_catalog(**{
            "iam:service_accounts": [
                {"email": "ci@proj.iam.gserviceaccount.com",
                 "name": "n", "display_name": "", "disabled": False},
            ],
            "iam:sa_keys:ci@proj.iam.gserviceaccount.com": [
                {"name": "new-key", "key_type": "USER_MANAGED",
                 "valid_after": recent, "valid_before": "9999-01-01"},
            ],
        })
        findings = gciam006_sa_key_age.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_system_managed_skipped(self, make_catalog):
        cat = make_catalog(**{
            "iam:service_accounts": [
                {"email": "ci@proj.iam.gserviceaccount.com",
                 "name": "n", "display_name": "", "disabled": False},
            ],
            "iam:sa_keys:ci@proj.iam.gserviceaccount.com": [
                {"name": "sys-key", "key_type": "SYSTEM_MANAGED",
                 "valid_after": "2024-01-01", "valid_before": "9999-01-01"},
            ],
        })
        findings = gciam006_sa_key_age.check(cat)
        assert findings == []

    def test_disabled_sa_skipped(self, make_catalog):
        cat = make_catalog(**{
            "iam:service_accounts": [
                {"email": "old@proj.iam.gserviceaccount.com",
                 "name": "n", "display_name": "", "disabled": True},
            ],
            "iam:sa_keys:old@proj.iam.gserviceaccount.com": [
                {"name": "old-key", "key_type": "USER_MANAGED",
                 "valid_after": "2024-01-01T00:00:00Z", "valid_before": "9999-01-01"},
            ],
        })
        findings = gciam006_sa_key_age.check(cat)
        assert findings == []
