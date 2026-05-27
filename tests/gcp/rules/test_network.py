"""GCNET-001..005 -- VPC/Network security checks."""
from __future__ import annotations

from pipeline_check.core.checks.gcp.rules import (
    gcnet001_default_network,
    gcnet002_deny_all_ingress,
    gcnet003_open_ssh_rdp,
    gcnet004_private_google_access,
    gcnet005_cloud_nat,
)

# -----------------------------------------------------------------------
# GCNET-001: Default VPC network exists
# -----------------------------------------------------------------------

class TestGCNET001:
    def test_default_network_exists_fails(self, make_catalog):
        cat = make_catalog(**{
            "network:networks": [
                {"name": "default", "auto_create_subnetworks": True},
            ],
        })
        findings = gcnet001_default_network.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCNET-001"

    def test_no_default_network_passes(self, make_catalog):
        cat = make_catalog(**{
            "network:networks": [
                {"name": "custom-vpc", "auto_create_subnetworks": False},
            ],
        })
        findings = gcnet001_default_network.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_empty_networks_passes(self, make_catalog):
        cat = make_catalog(**{"network:networks": []})
        findings = gcnet001_default_network.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True


# -----------------------------------------------------------------------
# GCNET-002: No default-deny ingress firewall rule
# -----------------------------------------------------------------------

class TestGCNET002:
    def test_deny_all_present_passes(self, make_catalog):
        cat = make_catalog(**{
            "network:firewalls": [
                {"name": "deny-all-ingress", "disabled": False,
                 "direction": "INGRESS",
                 "source_ranges": ["0.0.0.0/0"],
                 "allowed": [],
                 "log_config": {"enable": False}},
            ],
        })
        findings = gcnet002_deny_all_ingress.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "GCNET-002"

    def test_no_deny_all_fails(self, make_catalog):
        cat = make_catalog(**{
            "network:firewalls": [
                {"name": "allow-http", "disabled": False,
                 "direction": "INGRESS",
                 "source_ranges": ["0.0.0.0/0"],
                 "allowed": [{"protocol": "tcp", "ports": ["80"]}],
                 "log_config": {"enable": False}},
            ],
        })
        findings = gcnet002_deny_all_ingress.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_disabled_rule_not_counted(self, make_catalog):
        cat = make_catalog(**{
            "network:firewalls": [
                {"name": "deny-disabled", "disabled": True,
                 "direction": "INGRESS",
                 "source_ranges": ["0.0.0.0/0"],
                 "allowed": [],
                 "log_config": {"enable": False}},
            ],
        })
        findings = gcnet002_deny_all_ingress.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_firewalls_fails(self, make_catalog):
        cat = make_catalog(**{"network:firewalls": []})
        findings = gcnet002_deny_all_ingress.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False


# -----------------------------------------------------------------------
# GCNET-003: Firewall allows SSH or RDP from the internet
# -----------------------------------------------------------------------

class TestGCNET003:
    def test_ssh_from_internet_fails(self, make_catalog):
        cat = make_catalog(**{
            "network:firewalls": [
                {"name": "allow-ssh", "disabled": False,
                 "direction": "INGRESS",
                 "source_ranges": ["0.0.0.0/0"],
                 "allowed": [{"protocol": "tcp", "ports": ["22"]}],
                 "log_config": {"enable": False}},
            ],
        })
        findings = gcnet003_open_ssh_rdp.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCNET-003"

    def test_rdp_from_internet_fails(self, make_catalog):
        cat = make_catalog(**{
            "network:firewalls": [
                {"name": "allow-rdp", "disabled": False,
                 "direction": "INGRESS",
                 "source_ranges": ["0.0.0.0/0"],
                 "allowed": [{"protocol": "tcp", "ports": ["3389"]}],
                 "log_config": {"enable": False}},
            ],
        })
        findings = gcnet003_open_ssh_rdp.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_http_from_internet_passes(self, make_catalog):
        cat = make_catalog(**{
            "network:firewalls": [
                {"name": "allow-http", "disabled": False,
                 "direction": "INGRESS",
                 "source_ranges": ["0.0.0.0/0"],
                 "allowed": [{"protocol": "tcp", "ports": ["80"]}],
                 "log_config": {"enable": False}},
            ],
        })
        findings = gcnet003_open_ssh_rdp.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_ssh_from_internal_not_flagged(self, make_catalog):
        """SSH from internal ranges does not match 0.0.0.0/0."""
        cat = make_catalog(**{
            "network:firewalls": [
                {"name": "allow-internal-ssh", "disabled": False,
                 "direction": "INGRESS",
                 "source_ranges": ["10.0.0.0/8"],
                 "allowed": [{"protocol": "tcp", "ports": ["22"]}],
                 "log_config": {"enable": False}},
            ],
        })
        findings = gcnet003_open_ssh_rdp.check(cat)
        assert findings == []

    def test_empty_firewalls(self, make_catalog):
        cat = make_catalog(**{"network:firewalls": []})
        assert gcnet003_open_ssh_rdp.check(cat) == []


# -----------------------------------------------------------------------
# GCNET-004: Subnet does not have Private Google Access
# -----------------------------------------------------------------------

class TestGCNET004:
    def test_private_access_enabled_passes(self, make_catalog):
        cat = make_catalog(**{
            "network:subnetworks": [
                {"name": "sub-1", "region": "us-central1",
                 "private_ip_google_access": True,
                 "log_config": {"enable": False}},
            ],
        })
        findings = gcnet004_private_google_access.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "GCNET-004"

    def test_private_access_disabled_fails(self, make_catalog):
        cat = make_catalog(**{
            "network:subnetworks": [
                {"name": "sub-2", "region": "us-east1",
                 "private_ip_google_access": False,
                 "log_config": {"enable": False}},
            ],
        })
        findings = gcnet004_private_google_access.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_subnets_returns_empty(self, make_catalog):
        cat = make_catalog(**{"network:subnetworks": []})
        assert gcnet004_private_google_access.check(cat) == []


# -----------------------------------------------------------------------
# GCNET-005: No Cloud NAT gateway configured
# -----------------------------------------------------------------------

class TestGCNET005:
    def test_router_with_nat_passes(self, make_catalog):
        cat = make_catalog(**{
            "network:routers": [
                {"name": "router-1", "region": "us-central1",
                 "nats": [{"name": "nat-1"}]},
            ],
        })
        findings = gcnet005_cloud_nat.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "GCNET-005"

    def test_router_without_nat_fails(self, make_catalog):
        cat = make_catalog(**{
            "network:routers": [
                {"name": "router-2", "region": "us-east1", "nats": []},
            ],
        })
        findings = gcnet005_cloud_nat.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_routers_fails(self, make_catalog):
        cat = make_catalog(**{"network:routers": []})
        findings = gcnet005_cloud_nat.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
