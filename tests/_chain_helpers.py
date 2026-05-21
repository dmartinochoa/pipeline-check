"""Shared factories + the cross-provider chain mechanical contract.

Every ``XPC-NNN`` chain rule shares the same five mechanical
expectations:

  1. Fires when both legs (one finding per ``triggering_check_id``) are
     present and failing.
  2. Silent when only one leg fires.
  3. Silent when neither leg fires.
  4. Emits one chain per cross-product pair when multiple findings of
     each leg type are present.
  5. Chain confidence inherits the minimum of the contributing
     findings' confidences.

The per-chain test modules used to duplicate the same ``_failing`` /
``_passing`` factories plus the four mechanical-test methods (#2-#5
above) verbatim, with only the rule module and the check-id pair
varying. ``tests/test_chain_xpc_mechanical.py`` consumes the
``MECHANICAL_CONTRACTS`` list from this module and runs the
parametrized mechanical assertions; per-chain modules keep only the
``test_fires_on_combined_*`` happy-path cases and any
chain-specific behavior (reachability anchors on XPC-002, the
multi-prefix CVE matcher on XPC-009, etc).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pipeline_check.core.checks.base import (
    Confidence,
    Finding,
    Severity,
)


def make_failing(
    check_id: str,
    resource: str,
    *,
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    **extra: Any,
) -> Finding:
    """A ``passed=False`` synthetic finding for chain-engine tests."""
    return Finding(
        check_id=check_id,
        title="synthetic",
        severity=severity,
        resource=resource,
        description="synthetic test fixture",
        recommendation="",
        passed=False,
        confidence=confidence,
        **extra,
    )


def make_passing(check_id: str, resource: str) -> Finding:
    """A ``passed=True`` synthetic finding for chain-engine tests."""
    return Finding(
        check_id=check_id,
        title="synthetic",
        severity=Severity.HIGH,
        resource=resource,
        description="synthetic test fixture",
        recommendation="",
        passed=True,
        confidence=Confidence.HIGH,
    )


@dataclass(frozen=True)
class XpcContract:
    """One row in the mechanical-contract parametrization.

    Describes a chain rule with exactly two triggering check-ids,
    each with one canonical resource the mechanical tests can use.
    ``leg_a_checks`` and ``leg_b_checks`` are tuples so chains with
    union-of-N legs (``SCM-001 OR SCM-007``) can declare every entry
    that should satisfy the leg.
    """

    rule_module_path: str               # e.g. "xpc001_deploy_without_provenance"
    chain_id: str                       # "XPC-001"
    leg_a_checks: tuple[str, ...]       # ("GHA-006",) or ("SCM-001", "SCM-007")
    leg_a_resource: str                 # ".github/workflows/release.yml"
    leg_b_checks: tuple[str, ...]
    leg_b_resource: str
    #: Extra failing findings that must also be present for the
    #: chain to actually fire. XPC-004 needs both ``SCM-001``/``SCM-007``
    #: AND ``GHA-019`` per chain, for example.
    extra_failing: tuple[tuple[str, str], ...] = field(default_factory=tuple)


# Canonical contracts. New XPC chains add a row here and pick up the
# mechanical test coverage automatically.
MECHANICAL_CONTRACTS: tuple[XpcContract, ...] = (
    XpcContract(
        rule_module_path="xpc001_deploy_without_provenance",
        chain_id="XPC-001",
        leg_a_checks=("GHA-006",),
        leg_a_resource=".github/workflows/release.yml",
        leg_b_checks=("OCI-002",),
        leg_b_resource="image.json",
    ),
    XpcContract(
        rule_module_path="xpc002_floating_tag_continuity",
        chain_id="XPC-002",
        leg_a_checks=("DF-001",),
        leg_a_resource="Dockerfile",
        leg_b_checks=("K8S-001",),
        leg_b_resource="deploy.yaml",
    ),
    XpcContract(
        rule_module_path="xpc003_unverified_helm_release",
        chain_id="XPC-003",
        leg_a_checks=("HELM-002",),
        leg_a_resource="Chart.lock",
        leg_b_checks=("OCI-002",),
        leg_b_resource="img.json",
    ),
    XpcContract(
        rule_module_path="xpc004_token_leak_unprotected_branch",
        chain_id="XPC-004",
        leg_a_checks=("SCM-001", "SCM-007"),  # either satisfies the SCM leg
        leg_a_resource="github:org/repo",
        leg_b_checks=("GHA-019",),
        leg_b_resource=".github/workflows/release.yml",
    ),
    XpcContract(
        rule_module_path="xpc005_unsigned_source_to_unsigned_artifact",
        chain_id="XPC-005",
        leg_a_checks=("SCM-006",),
        leg_a_resource="github/owner/repo",
        leg_b_checks=("GHA-006",),
        leg_b_resource=".github/workflows/release.yml",
    ),
    XpcContract(
        rule_module_path="xpc006_unreviewed_fork_pr_privilege_escalation",
        chain_id="XPC-006",
        leg_a_checks=("SCM-002",),
        leg_a_resource="github/owner/repo",
        leg_b_checks=("GHA-002",),
        leg_b_resource=".github/workflows/ci.yml",
    ),
    XpcContract(
        rule_module_path="xpc007_unpinned_actions_no_remediation",
        chain_id="XPC-007",
        leg_a_checks=("SCM-005",),
        leg_a_resource="github/owner/repo",
        leg_b_checks=("GHA-001",),
        leg_b_resource=".github/workflows/ci.yml",
    ),
    XpcContract(
        rule_module_path="xpc008_unreviewed_source_mutable_runtime",
        chain_id="XPC-008",
        leg_a_checks=("SCM-001", "SCM-007"),  # either satisfies the SCM leg
        leg_a_resource="github:org/repo",
        leg_b_checks=("DF-001",),
        leg_b_resource="Dockerfile",
    ),
    XpcContract(
        rule_module_path="xpc010_npm_cooldown_dockerfile_lifecycle",
        chain_id="XPC-010",
        leg_a_checks=("NPM-008",),
        leg_a_resource="package.json",
        leg_b_checks=("DF-024",),
        leg_b_resource="Dockerfile",
    ),
)
