"""GCSQL-001..005 -- Cloud SQL instance checks."""
from __future__ import annotations

from pipeline_check.core.checks.gcp.rules import (
    gcsql001_public_ip,
    gcsql002_automated_backups,
    gcsql003_ssl_required,
    gcsql004_iam_auth,
    gcsql005_pitr,
)


def _sql_instance(
    name: str = "db-1",
    *,
    ipv4_enabled: bool = False,
    backup_enabled: bool = False,
    require_ssl: bool = False,
    iam_auth: bool = False,
    pitr: bool = False,
) -> dict:
    flags = []
    if iam_auth:
        flags.append({"name": "cloudsql.iam_authentication", "value": "on"})
    return {
        "name": name,
        "settings": {
            "ipConfiguration": {
                "ipv4Enabled": ipv4_enabled,
                "requireSsl": require_ssl,
            },
            "backupConfiguration": {
                "enabled": backup_enabled,
                "pointInTimeRecoveryEnabled": pitr,
            },
            "databaseFlags": flags,
        },
    }


# -----------------------------------------------------------------------
# GCSQL-001: Public IP
# -----------------------------------------------------------------------

class TestGCSQL001:
    def test_public_ip_enabled_fails(self, make_catalog):
        cat = make_catalog(**{
            "cloudsql:instances": [_sql_instance(ipv4_enabled=True)],
        })
        findings = gcsql001_public_ip.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCSQL-001"

    def test_private_ip_passes(self, make_catalog):
        cat = make_catalog(**{
            "cloudsql:instances": [_sql_instance(ipv4_enabled=False)],
        })
        findings = gcsql001_public_ip.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_instances_returns_empty(self, make_catalog):
        cat = make_catalog(**{"cloudsql:instances": []})
        assert gcsql001_public_ip.check(cat) == []


# -----------------------------------------------------------------------
# GCSQL-002: Automated backups
# -----------------------------------------------------------------------

class TestGCSQL002:
    def test_backups_disabled_fails(self, make_catalog):
        cat = make_catalog(**{
            "cloudsql:instances": [_sql_instance(backup_enabled=False)],
        })
        findings = gcsql002_automated_backups.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCSQL-002"

    def test_backups_enabled_passes(self, make_catalog):
        cat = make_catalog(**{
            "cloudsql:instances": [_sql_instance(backup_enabled=True)],
        })
        findings = gcsql002_automated_backups.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_instances_returns_empty(self, make_catalog):
        cat = make_catalog(**{"cloudsql:instances": []})
        assert gcsql002_automated_backups.check(cat) == []


# -----------------------------------------------------------------------
# GCSQL-003: SSL required
# -----------------------------------------------------------------------

class TestGCSQL003:
    def test_ssl_not_required_fails(self, make_catalog):
        cat = make_catalog(**{
            "cloudsql:instances": [_sql_instance(require_ssl=False)],
        })
        findings = gcsql003_ssl_required.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCSQL-003"

    def test_ssl_required_passes(self, make_catalog):
        cat = make_catalog(**{
            "cloudsql:instances": [_sql_instance(require_ssl=True)],
        })
        findings = gcsql003_ssl_required.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_instances_returns_empty(self, make_catalog):
        cat = make_catalog(**{"cloudsql:instances": []})
        assert gcsql003_ssl_required.check(cat) == []

    # Regression (2026-07 audit, GCSQL-003): modern instances enforce
    # TLS via sslMode, which supersedes the legacy requireSsl boolean.
    def test_ssl_mode_encrypted_only_passes(self, make_catalog):
        inst = {"name": "db", "settings": {"ipConfiguration": {
            "ipv4Enabled": False, "sslMode": "ENCRYPTED_ONLY"}}}
        cat = make_catalog(**{"cloudsql:instances": [inst]})
        findings = gcsql003_ssl_required.check(cat)
        assert findings[0].passed is True

    def test_ssl_mode_trusted_cert_passes(self, make_catalog):
        inst = {"name": "db", "settings": {"ipConfiguration": {
            "sslMode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}}}
        cat = make_catalog(**{"cloudsql:instances": [inst]})
        assert gcsql003_ssl_required.check(cat)[0].passed is True

    def test_ssl_mode_allow_unencrypted_fails(self, make_catalog):
        inst = {"name": "db", "settings": {"ipConfiguration": {
            "sslMode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}}}
        cat = make_catalog(**{"cloudsql:instances": [inst]})
        assert gcsql003_ssl_required.check(cat)[0].passed is False


# -----------------------------------------------------------------------
# GCSQL-004: IAM authentication
# -----------------------------------------------------------------------

class TestGCSQL004:
    def test_no_iam_auth_fails(self, make_catalog):
        cat = make_catalog(**{
            "cloudsql:instances": [_sql_instance(iam_auth=False)],
        })
        findings = gcsql004_iam_auth.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCSQL-004"

    def test_iam_auth_enabled_passes(self, make_catalog):
        cat = make_catalog(**{
            "cloudsql:instances": [_sql_instance(iam_auth=True)],
        })
        findings = gcsql004_iam_auth.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_instances_returns_empty(self, make_catalog):
        cat = make_catalog(**{"cloudsql:instances": []})
        assert gcsql004_iam_auth.check(cat) == []


# -----------------------------------------------------------------------
# GCSQL-005: Point-in-time recovery
# -----------------------------------------------------------------------

class TestGCSQL005:
    def test_pitr_disabled_fails(self, make_catalog):
        cat = make_catalog(**{
            "cloudsql:instances": [_sql_instance(pitr=False)],
        })
        findings = gcsql005_pitr.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCSQL-005"

    def test_pitr_enabled_passes(self, make_catalog):
        cat = make_catalog(**{
            "cloudsql:instances": [_sql_instance(pitr=True)],
        })
        findings = gcsql005_pitr.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_instances_returns_empty(self, make_catalog):
        cat = make_catalog(**{"cloudsql:instances": []})
        assert gcsql005_pitr.check(cat) == []

    # Regression (2026-07 audit, GCSQL-005): MySQL surfaces PITR as
    # binaryLogEnabled, not pointInTimeRecoveryEnabled.
    def test_mysql_binary_log_enabled_passes(self, make_catalog):
        inst = {"name": "db", "settings": {"backupConfiguration": {
            "enabled": True, "binaryLogEnabled": True}}}
        cat = make_catalog(**{"cloudsql:instances": [inst]})
        findings = gcsql005_pitr.check(cat)
        assert findings[0].passed is True
