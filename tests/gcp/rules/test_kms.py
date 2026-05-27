"""GCKMS-001/002/003 -- Cloud KMS checks."""
from __future__ import annotations

from pipeline_check.core.checks.gcp.rules import (
    gckms001_rotation,
    gckms002_public_key,
    gckms003_hsm,
)


def _key(
    name: str = "projects/p/locations/global/keyRings/kr/cryptoKeys/k",
    *,
    purpose: str = "ENCRYPT_DECRYPT",
    protection: str = "SOFTWARE",
    rotation_days: float | None = 90,
    primary_state: str = "ENABLED",
) -> dict:
    return {
        "name": name,
        "purpose": purpose,
        "protection_level": protection,
        "rotation_period_days": rotation_days,
        "primary_state": primary_state,
    }


# -----------------------------------------------------------------------
# GCKMS-001: key rotation period exceeds 365 days
# -----------------------------------------------------------------------

class TestGCKMS001:
    def test_rotation_within_365_passes(self, make_catalog):
        cat = make_catalog(**{
            "kms:keys": [_key(rotation_days=90)],
        })
        findings = gckms001_rotation.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_rotation_exactly_365_passes(self, make_catalog):
        cat = make_catalog(**{
            "kms:keys": [_key(rotation_days=365)],
        })
        findings = gckms001_rotation.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_rotation_over_365_fails(self, make_catalog):
        cat = make_catalog(**{
            "kms:keys": [_key(rotation_days=400)],
        })
        findings = gckms001_rotation.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert "400 days" in findings[0].description

    def test_no_rotation_period_fails(self, make_catalog):
        cat = make_catalog(**{
            "kms:keys": [_key(rotation_days=None)],
        })
        findings = gckms001_rotation.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert "no automatic rotation" in findings[0].description

    def test_asymmetric_key_skipped(self, make_catalog):
        """Only ENCRYPT_DECRYPT keys are checked for rotation."""
        cat = make_catalog(**{
            "kms:keys": [_key(purpose="ASYMMETRIC_SIGN", rotation_days=None)],
        })
        findings = gckms001_rotation.check(cat)
        assert findings == []

    def test_no_keys_returns_empty(self, make_catalog):
        cat = make_catalog(**{"kms:keys": []})
        assert gckms001_rotation.check(cat) == []


# -----------------------------------------------------------------------
# GCKMS-002: KMS key IAM policy grants public access
# -----------------------------------------------------------------------

class TestGCKMS002:
    def test_cloudkms_role_allUsers_fails(self, make_catalog):
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [
                    {
                        "role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
                        "members": ["allUsers"],
                        "condition": None,
                    },
                ],
                "audit_configs": [],
            },
        })
        findings = gckms002_public_key.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_cloudkms_role_allAuthenticatedUsers_fails(self, make_catalog):
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [
                    {
                        "role": "roles/cloudkms.admin",
                        "members": ["allAuthenticatedUsers", "user:admin@co.com"],
                        "condition": None,
                    },
                ],
                "audit_configs": [],
            },
        })
        findings = gckms002_public_key.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert "allAuthenticatedUsers" in findings[0].description

    def test_non_kms_role_with_allUsers_ignored(self, make_catalog):
        """allUsers on a non-KMS role does not fire GCKMS-002."""
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [
                    {
                        "role": "roles/storage.objectViewer",
                        "members": ["allUsers"],
                        "condition": None,
                    },
                ],
                "audit_configs": [],
            },
        })
        findings = gckms002_public_key.check(cat)
        assert findings == []

    def test_private_kms_binding_no_finding(self, make_catalog):
        """A KMS binding without public members emits nothing."""
        cat = make_catalog(**{
            "iam:project_policy": {
                "bindings": [
                    {
                        "role": "roles/cloudkms.cryptoKeyDecrypter",
                        "members": ["serviceAccount:ci@proj.iam.gserviceaccount.com"],
                        "condition": None,
                    },
                ],
                "audit_configs": [],
            },
        })
        findings = gckms002_public_key.check(cat)
        assert findings == []

    def test_empty_policy_returns_empty(self, make_catalog):
        cat = make_catalog(**{"iam:project_policy": {}})
        assert gckms002_public_key.check(cat) == []


# -----------------------------------------------------------------------
# GCKMS-003: KMS key not using HSM protection level
# -----------------------------------------------------------------------

class TestGCKMS003:
    def test_software_protection_fails(self, make_catalog):
        cat = make_catalog(**{
            "kms:keys": [_key(protection="SOFTWARE")],
        })
        findings = gckms003_hsm.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert "SOFTWARE" in findings[0].description

    def test_hsm_protection_passes(self, make_catalog):
        cat = make_catalog(**{
            "kms:keys": [_key(protection="HSM")],
        })
        findings = gckms003_hsm.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_external_protection_fails(self, make_catalog):
        cat = make_catalog(**{
            "kms:keys": [_key(protection="EXTERNAL")],
        })
        findings = gckms003_hsm.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert "EXTERNAL" in findings[0].description

    def test_no_keys_returns_empty(self, make_catalog):
        cat = make_catalog(**{"kms:keys": []})
        assert gckms003_hsm.check(cat) == []


# -----------------------------------------------------------------------
# GCKMS-004: KMS key ring IAM has overly broad bindings
# -----------------------------------------------------------------------

from pipeline_check.core.checks.gcp.rules import gckms004_keyring_iam


class TestGCKMS004:
    def test_allUsers_binding_fails(self, make_catalog):
        cat = make_catalog(**{
            "kms:key_rings": [
                {"name": "kr1", "iam_policy": [
                    {"role": "roles/cloudkms.cryptoKeyDecrypter",
                     "members": ["allUsers"]},
                ]},
            ],
        })
        findings = gckms004_keyring_iam.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCKMS-004"

    def test_allAuthenticatedUsers_fails(self, make_catalog):
        cat = make_catalog(**{
            "kms:key_rings": [
                {"name": "kr2", "iam_policy": [
                    {"role": "roles/cloudkms.admin",
                     "members": ["allAuthenticatedUsers", "user:admin@co.com"]},
                ]},
            ],
        })
        findings = gckms004_keyring_iam.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_private_bindings_passes(self, make_catalog):
        cat = make_catalog(**{
            "kms:key_rings": [
                {"name": "kr3", "iam_policy": [
                    {"role": "roles/cloudkms.cryptoKeyDecrypter",
                     "members": ["serviceAccount:sa@proj.iam.gserviceaccount.com"]},
                ]},
            ],
        })
        findings = gckms004_keyring_iam.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_key_rings_returns_empty(self, make_catalog):
        cat = make_catalog(**{"kms:key_rings": []})
        assert gckms004_keyring_iam.check(cat) == []


# -----------------------------------------------------------------------
# GCKMS-005: KMS key primary version scheduled for destruction
# -----------------------------------------------------------------------

from pipeline_check.core.checks.gcp.rules import gckms005_destroy_scheduled


class TestGCKMS005:
    def test_destroy_scheduled_fails(self, make_catalog):
        cat = make_catalog(**{
            "kms:keys": [_key(primary_state="DESTROY_SCHEDULED")],
        })
        findings = gckms005_destroy_scheduled.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCKMS-005"

    def test_enabled_state_passes(self, make_catalog):
        cat = make_catalog(**{
            "kms:keys": [_key(primary_state="ENABLED")],
        })
        findings = gckms005_destroy_scheduled.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_primary_state_skipped(self, make_catalog):
        k = _key()
        k["primary_state"] = None
        cat = make_catalog(**{"kms:keys": [k]})
        findings = gckms005_destroy_scheduled.check(cat)
        assert findings == []

    def test_no_keys_returns_empty(self, make_catalog):
        cat = make_catalog(**{"kms:keys": []})
        assert gckms005_destroy_scheduled.check(cat) == []


# -----------------------------------------------------------------------
# GCKMS-006: KMS key uses imported (external) key material
# -----------------------------------------------------------------------

from pipeline_check.core.checks.gcp.rules import gckms006_imported_key_material


class TestGCKMS006:
    def test_external_protection_fails(self, make_catalog):
        cat = make_catalog(**{
            "kms:keys": [_key(protection="EXTERNAL")],
        })
        findings = gckms006_imported_key_material.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCKMS-006"

    def test_external_vpc_fails(self, make_catalog):
        cat = make_catalog(**{
            "kms:keys": [_key(protection="EXTERNAL_VPC")],
        })
        findings = gckms006_imported_key_material.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_software_protection_passes(self, make_catalog):
        cat = make_catalog(**{
            "kms:keys": [_key(protection="SOFTWARE")],
        })
        findings = gckms006_imported_key_material.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_hsm_protection_passes(self, make_catalog):
        cat = make_catalog(**{
            "kms:keys": [_key(protection="HSM")],
        })
        findings = gckms006_imported_key_material.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_keys_returns_empty(self, make_catalog):
        cat = make_catalog(**{"kms:keys": []})
        assert gckms006_imported_key_material.check(cat) == []
