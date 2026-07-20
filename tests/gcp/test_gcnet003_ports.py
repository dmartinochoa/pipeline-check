"""Unit tests for GCNET-003's port-danger helper.

Regression for the B4 false negative where an ``allowed`` entry with
``IPProtocol: tcp`` and no ``ports`` list (which means *every* TCP port,
including 22 and 3389) was treated as safe, and the rule emitted an
actively-wrong "not on SSH or RDP ports" pass.
"""
from __future__ import annotations

from pipeline_check.core.checks.gcp.rules.gcnet003_open_ssh_rdp import (
    _allows_dangerous_port,
)


def test_tcp_without_ports_is_all_ports():
    assert _allows_dangerous_port([{"protocol": "tcp"}]) == ["22", "3389"]


def test_all_protocol_without_ports_is_all_ports():
    assert _allows_dangerous_port([{"protocol": "all"}]) == ["22", "3389"]


def test_tcp_with_explicit_safe_ports_is_clean():
    assert _allows_dangerous_port(
        [{"protocol": "tcp", "ports": ["443", "8080"]}]
    ) == []


def test_tcp_with_ssh_port_flags_it():
    assert _allows_dangerous_port(
        [{"protocol": "tcp", "ports": ["22"]}]
    ) == ["22"]


def test_udp_without_ports_is_ignored():
    # SSH / RDP are TCP; a udp-only rule doesn't expose them.
    assert _allows_dangerous_port([{"protocol": "udp"}]) == []
