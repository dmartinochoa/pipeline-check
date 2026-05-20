"""Parametrized mechanical contract tests for every XPC-NNN chain.

The five assertions every cross-provider chain must satisfy live here
once; ``tests/_chain_helpers.py:MECHANICAL_CONTRACTS`` declares one
row per chain. Adding a new XPC chain is just a new contract entry —
the mechanical coverage rides along for free.

Per-chain happy-path / reachability / per-finding-shape tests stay
in their respective ``tests/test_chain_xpcNNN.py`` files. Anything
mechanically uniform across chains belongs here instead so the next
chain doesn't carry forward another 100 lines of clone.
"""
from __future__ import annotations

import importlib

import pytest

from pipeline_check.core.chains.engine import evaluate
from pipeline_check.core.checks.base import (
    Confidence,
    Finding,
    Severity,
)

from ._chain_helpers import (
    MECHANICAL_CONTRACTS,
    XpcContract,
    make_failing,
    make_passing,
)

_RULES_PKG = "pipeline_check.core.chains.rules"


def _rule_module(contract: XpcContract):
    return importlib.import_module(f"{_RULES_PKG}.{contract.rule_module_path}")


def _failing_pair(contract: XpcContract) -> list[Finding]:
    """Return a minimal pair of failing findings that satisfy the chain.

    Picks the first member of each ``leg_*_checks`` tuple for chains
    whose legs accept several alternative check-ids; the per-chain
    test module covers the OR-of-N happy paths.
    """
    out = [
        make_failing(contract.leg_a_checks[0], contract.leg_a_resource),
        make_failing(contract.leg_b_checks[0], contract.leg_b_resource),
    ]
    for cid, resource in contract.extra_failing:
        out.append(make_failing(cid, resource))
    return out


@pytest.mark.parametrize("contract", MECHANICAL_CONTRACTS, ids=lambda c: c.chain_id)
def test_silent_when_only_leg_a_fires(contract: XpcContract) -> None:
    r = _rule_module(contract)
    findings = [
        make_failing(contract.leg_a_checks[0], contract.leg_a_resource),
        make_passing(contract.leg_b_checks[0], contract.leg_b_resource),
    ]
    assert r.match(findings) == []


@pytest.mark.parametrize("contract", MECHANICAL_CONTRACTS, ids=lambda c: c.chain_id)
def test_silent_when_only_leg_b_fires(contract: XpcContract) -> None:
    r = _rule_module(contract)
    findings = [
        make_passing(contract.leg_a_checks[0], contract.leg_a_resource),
        make_failing(contract.leg_b_checks[0], contract.leg_b_resource),
    ]
    assert r.match(findings) == []


@pytest.mark.parametrize("contract", MECHANICAL_CONTRACTS, ids=lambda c: c.chain_id)
def test_silent_when_neither_fires(contract: XpcContract) -> None:
    r = _rule_module(contract)
    findings = [
        make_passing(contract.leg_a_checks[0], contract.leg_a_resource),
        make_passing(contract.leg_b_checks[0], contract.leg_b_resource),
    ]
    assert r.match(findings) == []


@pytest.mark.parametrize("contract", MECHANICAL_CONTRACTS, ids=lambda c: c.chain_id)
def test_engine_dispatch_picks_up_chain(contract: XpcContract) -> None:
    chains = evaluate(_failing_pair(contract))
    ids = {c.chain_id for c in chains}
    assert contract.chain_id in ids


@pytest.mark.parametrize("contract", MECHANICAL_CONTRACTS, ids=lambda c: c.chain_id)
def test_confidence_inherits_from_weakest_finding(contract: XpcContract) -> None:
    r = _rule_module(contract)
    findings = [
        make_failing(
            contract.leg_a_checks[0], contract.leg_a_resource,
            confidence=Confidence.HIGH,
        ),
        make_failing(
            contract.leg_b_checks[0], contract.leg_b_resource,
            confidence=Confidence.LOW,
        ),
    ]
    for cid, resource in contract.extra_failing:
        findings.append(make_failing(cid, resource))
    chains = r.match(findings)
    assert chains, f"{contract.chain_id} produced no chain on its happy-path pair"
    # The engine returns one chain in the simple two-leg-one-resource
    # shape these contracts assert; multi-pair behavior is covered by
    # ``test_emits_one_chain_per_pair`` per-file (it varies enough that
    # parametrization would obscure rather than help).
    assert chains[0].confidence is Confidence.LOW
