"""GCCE-001..005 -- Compute Engine instance checks."""
from __future__ import annotations

from pipeline_check.core.checks.gcp.rules import (
    gcce001_shielded_vm,
    gcce002_os_login,
    gcce003_serial_port,
    gcce004_public_ip,
    gcce005_project_ssh_keys,
)


def _instance(
    name: str = "inst-1",
    *,
    vtpm: bool = False,
    integrity: bool = False,
    os_login: str = "",
    serial_port: str = "",
    block_project_keys: str = "",
    access_configs: list | None = None,
) -> dict:
    config = None
    if vtpm or integrity:
        config = {
            "enable_vtpm": vtpm,
            "enable_integrity_monitoring": integrity,
        }
    return {
        "name": name,
        "zone": "us-central1-a",
        "status": "RUNNING",
        "service_accounts": [],
        "shielded_instance_config": config,
        "metadata": {
            "enable-oslogin": os_login,
            "serial-port-enable": serial_port,
            "block-project-ssh-keys": block_project_keys,
        },
        "network_interfaces": [
            {
                "name": "nic0",
                "network": "default",
                "access_configs": access_configs or [],
            },
        ],
    }


# -----------------------------------------------------------------------
# GCCE-001: Shielded VM
# -----------------------------------------------------------------------

class TestGCCE001:
    def test_both_enabled_passes(self, make_catalog):
        cat = make_catalog(**{
            "compute:instances": [_instance(vtpm=True, integrity=True)],
        })
        findings = gcce001_shielded_vm.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "GCCE-001"

    def test_missing_vtpm_fails(self, make_catalog):
        cat = make_catalog(**{
            "compute:instances": [_instance(vtpm=False, integrity=True)],
        })
        findings = gcce001_shielded_vm.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_config_fails(self, make_catalog):
        cat = make_catalog(**{
            "compute:instances": [_instance()],
        })
        findings = gcce001_shielded_vm.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_instances_returns_empty(self, make_catalog):
        cat = make_catalog(**{"compute:instances": []})
        assert gcce001_shielded_vm.check(cat) == []


# -----------------------------------------------------------------------
# GCCE-002: OS Login
# -----------------------------------------------------------------------

class TestGCCE002:
    def test_oslogin_true_passes(self, make_catalog):
        cat = make_catalog(**{
            "compute:instances": [_instance(os_login="TRUE")],
        })
        findings = gcce002_os_login.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "GCCE-002"

    def test_oslogin_empty_fails(self, make_catalog):
        cat = make_catalog(**{
            "compute:instances": [_instance(os_login="")],
        })
        findings = gcce002_os_login.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_oslogin_false_fails(self, make_catalog):
        cat = make_catalog(**{
            "compute:instances": [_instance(os_login="false")],
        })
        findings = gcce002_os_login.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_instances_returns_empty(self, make_catalog):
        cat = make_catalog(**{"compute:instances": []})
        assert gcce002_os_login.check(cat) == []


# -----------------------------------------------------------------------
# GCCE-003: Serial port access
# -----------------------------------------------------------------------

class TestGCCE003:
    def test_serial_port_true_fails(self, make_catalog):
        cat = make_catalog(**{
            "compute:instances": [_instance(serial_port="true")],
        })
        findings = gcce003_serial_port.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCCE-003"

    def test_serial_port_empty_passes(self, make_catalog):
        cat = make_catalog(**{
            "compute:instances": [_instance(serial_port="")],
        })
        findings = gcce003_serial_port.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_serial_port_false_passes(self, make_catalog):
        cat = make_catalog(**{
            "compute:instances": [_instance(serial_port="false")],
        })
        findings = gcce003_serial_port.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_instances_returns_empty(self, make_catalog):
        cat = make_catalog(**{"compute:instances": []})
        assert gcce003_serial_port.check(cat) == []


# -----------------------------------------------------------------------
# GCCE-004: External IP
# -----------------------------------------------------------------------

class TestGCCE004:
    def test_external_ip_fails(self, make_catalog):
        cat = make_catalog(**{
            "compute:instances": [
                _instance(access_configs=[{"nat_ip": "35.1.2.3", "type": "ONE_TO_ONE_NAT"}]),
            ],
        })
        findings = gcce004_public_ip.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCCE-004"

    def test_no_external_ip_passes(self, make_catalog):
        cat = make_catalog(**{
            "compute:instances": [_instance(access_configs=[])],
        })
        findings = gcce004_public_ip.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_ephemeral_ip_fails(self, make_catalog):
        cat = make_catalog(**{
            "compute:instances": [
                _instance(access_configs=[{"nat_ip": None, "type": "ONE_TO_ONE_NAT"}]),
            ],
        })
        findings = gcce004_public_ip.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_instances_returns_empty(self, make_catalog):
        cat = make_catalog(**{"compute:instances": []})
        assert gcce004_public_ip.check(cat) == []


# -----------------------------------------------------------------------
# GCCE-005: Block project-wide SSH keys
# -----------------------------------------------------------------------

class TestGCCE005:
    def test_blocked_passes(self, make_catalog):
        cat = make_catalog(**{
            "compute:instances": [_instance(block_project_keys="TRUE")],
        })
        findings = gcce005_project_ssh_keys.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "GCCE-005"

    def test_not_blocked_fails(self, make_catalog):
        cat = make_catalog(**{
            "compute:instances": [_instance(block_project_keys="")],
        })
        findings = gcce005_project_ssh_keys.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_false_value_fails(self, make_catalog):
        cat = make_catalog(**{
            "compute:instances": [_instance(block_project_keys="FALSE")],
        })
        findings = gcce005_project_ssh_keys.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_instances_returns_empty(self, make_catalog):
        cat = make_catalog(**{"compute:instances": []})
        assert gcce005_project_ssh_keys.check(cat) == []


class TestAudit202607GCCE002:
    """GCCE-002 now accepts alternate truthy enable-oslogin spellings."""

    def test_numeric_one_is_enabled(self, make_catalog):
        cat = make_catalog(**{"compute:instances": [
            {"name": "i", "metadata": {"enable-oslogin": "1"}}]})
        f = gcce002_os_login.check(cat)
        assert f and f[0].passed is True

    def test_false_still_flagged(self, make_catalog):
        cat = make_catalog(**{"compute:instances": [
            {"name": "i", "metadata": {"enable-oslogin": "false"}}]})
        f = gcce002_os_login.check(cat)
        assert f and f[0].passed is False
