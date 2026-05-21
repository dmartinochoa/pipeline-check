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


# ── Mechanical-contract coverage floor ─────────────────────────────────


#: XPC chains whose leg shapes preclude a uniform two-leg fixture and
#: are therefore exempt from the mechanical-contract parametrization.
#: Each entry needs a one-line justification so a future contributor
#: knows whether their new chain genuinely belongs here.
_MECHANICAL_CONTRACT_CARVE_OUTS: dict[str, str] = {
    # XPC-009 matches a *prefix* (``INGEST-trivy-CVE-*`` etc.) rather
    # than an exact check_id, so the contract's two-leg fixture can't
    # name a single ingest check_id without baking in one scanner's
    # naming convention. Covered end-to-end by tests/test_chain_xpc009.py
    # (per-prefix happy paths + the engine-dispatch case).
    "XPC-009": "matches INGEST-<tool>-CVE-* prefix, not an exact id",
}


def test_every_registered_xpc_chain_has_a_mechanical_contract() -> None:
    """A new XPC-NNN chain must either appear in
    ``MECHANICAL_CONTRACTS`` (so the five parametrized assertions
    above run against it) or be explicitly listed in
    ``_MECHANICAL_CONTRACT_CARVE_OUTS`` with a one-line reason.

    Catches the silent-skip regression where someone lands a new XPC
    chain rule, adds happy-path tests in its per-chain file, but
    forgets the contract row, the five mechanical guarantees the
    contract enforces (silent-on-one-leg, engine dispatch, weakest-
    confidence inheritance) then go uncovered without anyone noticing.
    """
    from pipeline_check.core import chains as chains_pkg
    registered = {r.id for r in chains_pkg.list_rules() if r.id.startswith("XPC-")}
    covered = {c.chain_id for c in MECHANICAL_CONTRACTS}
    carved_out = set(_MECHANICAL_CONTRACT_CARVE_OUTS)
    uncovered = registered - covered - carved_out
    assert not uncovered, (
        f"XPC chain(s) {sorted(uncovered)} have no MECHANICAL_CONTRACTS "
        f"entry and aren't listed in _MECHANICAL_CONTRACT_CARVE_OUTS. "
        f"Add a contract row to tests/_chain_helpers.py:MECHANICAL_CONTRACTS, "
        f"or document the carve-out reason in the dict above."
    )


def test_carve_outs_only_name_registered_chains() -> None:
    """The carve-out dict shouldn't mention a chain that no longer
    exists, that's stale documentation and would mask a real
    coverage gap for an in-the-wild chain that happens to share the
    same id later."""
    from pipeline_check.core import chains as chains_pkg
    registered = {r.id for r in chains_pkg.list_rules() if r.id.startswith("XPC-")}
    orphans = sorted(set(_MECHANICAL_CONTRACT_CARVE_OUTS) - registered)
    assert not orphans, (
        f"_MECHANICAL_CONTRACT_CARVE_OUTS names {orphans} but those "
        f"chain ids aren't registered. Drop the stale entries or "
        f"restore the rule modules."
    )
