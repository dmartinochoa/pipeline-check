"""Tests for AZNW-001..005 network rules."""
from __future__ import annotations

from unittest.mock import MagicMock

from pipeline_check.core.checks.azure_cloud.rules import (
    aznw001_ssh_rdp_internet as aznw001,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    aznw002_flow_logs as aznw002,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    aznw003_waf_app_gateway as aznw003,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    aznw004_deny_all_inbound as aznw004,
)
from pipeline_check.core.checks.azure_cloud.rules import (
    aznw005_public_ip_vm as aznw005,
)

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _nsg_rule(
    direction: str = "Inbound",
    access: str = "Allow",
    source_address_prefix: str = "*",
    source_address_prefixes: list[str] | None = None,
    destination_port_range: str = "22",
    destination_port_ranges: list[str] | None = None,
) -> MagicMock:
    rule = MagicMock()
    rule.direction = direction
    rule.access = access
    rule.source_address_prefix = source_address_prefix
    rule.source_address_prefixes = source_address_prefixes or []
    rule.destination_port_range = destination_port_range
    rule.destination_port_ranges = destination_port_ranges or []
    return rule


def _nsg(name: str = "nsg1", rules: list | None = None,
         nsg_id: str = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1"):
    obj = MagicMock()
    obj.name = name
    obj.security_rules = rules or []
    obj.id = nsg_id
    return obj


# -----------------------------------------------------------------------
# AZNW-001  NSG allows inbound SSH or RDP from the internet
# -----------------------------------------------------------------------

class TestAznw001:
    def test_ssh_from_internet_fails(self, make_catalog):
        rule = _nsg_rule(destination_port_range="22")
        nsg = _nsg(rules=[rule])
        catalog = make_catalog(**{"network:nsgs": [nsg]})
        findings = aznw001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZNW-001"

    def test_rdp_from_internet_fails(self, make_catalog):
        rule = _nsg_rule(destination_port_range="3389")
        nsg = _nsg(rules=[rule])
        catalog = make_catalog(**{"network:nsgs": [nsg]})
        findings = aznw001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_wildcard_port_from_internet_fails(self, make_catalog):
        rule = _nsg_rule(destination_port_range="*")
        nsg = _nsg(rules=[rule])
        catalog = make_catalog(**{"network:nsgs": [nsg]})
        findings = aznw001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_ssh_from_internal_passes(self, make_catalog):
        rule = _nsg_rule(source_address_prefix="10.0.0.0/8", destination_port_range="22")
        nsg = _nsg(rules=[rule])
        catalog = make_catalog(**{"network:nsgs": [nsg]})
        findings = aznw001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_deny_rule_ignored(self, make_catalog):
        rule = _nsg_rule(access="Deny", destination_port_range="22")
        nsg = _nsg(rules=[rule])
        catalog = make_catalog(**{"network:nsgs": [nsg]})
        findings = aznw001.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_empty_nsgs(self, make_catalog):
        catalog = make_catalog(**{"network:nsgs": []})
        findings = aznw001.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZNW-002  NSG does not have flow logging enabled
# -----------------------------------------------------------------------

class TestAznw002:
    def test_nsg_with_flow_log_passes(self, make_catalog):
        nsg_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1"
        nsg = _nsg(nsg_id=nsg_id)
        fl = MagicMock()
        fl.target_resource_id = nsg_id
        catalog = make_catalog(**{
            "network:nsgs": [nsg],
            "network:flow_logs": [fl],
        })
        findings = aznw002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "AZNW-002"

    def test_nsg_without_flow_log_fails(self, make_catalog):
        nsg = _nsg()
        catalog = make_catalog(**{
            "network:nsgs": [nsg],
            "network:flow_logs": [],
        })
        findings = aznw002.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_nsgs(self, make_catalog):
        catalog = make_catalog(**{
            "network:nsgs": [],
            "network:flow_logs": [],
        })
        findings = aznw002.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZNW-003  Application Gateway does not have WAF enabled
# -----------------------------------------------------------------------

def _app_gateway(name: str = "gw1", tier: str = "Standard_v2",
                 waf_config: object | None = None,
                 firewall_policy: object | None = None) -> MagicMock:
    gw = MagicMock()
    gw.name = name
    gw.sku.tier = tier
    gw.web_application_firewall_configuration = waf_config
    gw.firewall_policy = firewall_policy
    return gw


class TestAznw003:
    def test_waf_tier_passes(self, make_catalog):
        gw = _app_gateway(tier="WAF_v2")
        catalog = make_catalog(**{"network:app_gateways": [gw]})
        findings = aznw003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "AZNW-003"

    def test_standard_tier_no_waf_fails(self, make_catalog):
        gw = _app_gateway(tier="Standard_v2", waf_config=None, firewall_policy=None)
        catalog = make_catalog(**{"network:app_gateways": [gw]})
        findings = aznw003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_firewall_policy_present_passes(self, make_catalog):
        gw = _app_gateway(tier="Standard_v2", firewall_policy=MagicMock())
        catalog = make_catalog(**{"network:app_gateways": [gw]})
        findings = aznw003.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_empty_gateways(self, make_catalog):
        catalog = make_catalog(**{"network:app_gateways": []})
        findings = aznw003.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZNW-004  NSG has no explicit deny-all inbound rule
# -----------------------------------------------------------------------

class TestAznw004:
    def test_has_deny_all_passes(self, make_catalog):
        rule = _nsg_rule(
            direction="Inbound", access="Deny",
            source_address_prefix="*", destination_port_range="*",
        )
        nsg = _nsg(rules=[rule])
        catalog = make_catalog(**{"network:nsgs": [nsg]})
        findings = aznw004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert findings[0].check_id == "AZNW-004"

    def test_no_deny_all_fails(self, make_catalog):
        nsg = _nsg(rules=[])
        catalog = make_catalog(**{"network:nsgs": [nsg]})
        findings = aznw004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_deny_specific_port_not_sufficient(self, make_catalog):
        rule = _nsg_rule(
            direction="Inbound", access="Deny",
            source_address_prefix="*", destination_port_range="80",
        )
        nsg = _nsg(rules=[rule])
        catalog = make_catalog(**{"network:nsgs": [nsg]})
        findings = aznw004.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_empty_nsgs(self, make_catalog):
        catalog = make_catalog(**{"network:nsgs": []})
        findings = aznw004.check(catalog)
        assert findings == []


# -----------------------------------------------------------------------
# AZNW-005  Public IP address associated with a VM NIC
# -----------------------------------------------------------------------

class TestAznw005:
    def test_public_ip_on_vm_nic_fails(self, make_catalog):
        pip = MagicMock()
        pip.name = "pip-1"
        pip.ip_configuration.id = (
            "/subscriptions/sub/resourceGroups/rg/providers/"
            "Microsoft.Network/networkInterfaces/nic1/ipConfigurations/ipconfig1"
        )
        catalog = make_catalog(**{"network:public_ips": [pip]})
        findings = aznw005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "AZNW-005"

    def test_public_ip_on_lb_passes(self, make_catalog):
        pip = MagicMock()
        pip.name = "pip-lb"
        pip.ip_configuration.id = (
            "/subscriptions/sub/resourceGroups/rg/providers/"
            "Microsoft.Network/loadBalancers/lb1/frontendIPConfigurations/fe1"
        )
        catalog = make_catalog(**{"network:public_ips": [pip]})
        findings = aznw005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_public_ips_passes(self, make_catalog):
        catalog = make_catalog(**{"network:public_ips": []})
        findings = aznw005.check(catalog)
        assert len(findings) == 1
        assert findings[0].passed is True
