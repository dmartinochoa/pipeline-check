"""Regression tests from the rule audit (GitHub Actions example fixes).

The 2026-06-01 audit never covered the github pack; a follow-up parse
scan found github ``exploit_example`` snippets that no YAML loader
accepts. The breakages were all the same two shapes:

  * a GitHub ``${{ ... }}`` expression inside a YAML *flow* mapping
    (``with: { ref: ${{ ... }} }``) — the ``${{`` opens a nested flow
    context the parser can't close;
  * a ``run:`` plain scalar carrying a ``: `` (``curl -H
    "Authorization: Bearer ..."``) — the colon-space reads as a
    mapping indicator.

Both fixed by switching the offending line to block style. This module
pins two contracts:

1. **Every** github rule's ``exploit_example`` parses via the
   production loader (``test_every_example_parses``), so a future
   broken snippet trips here rather than silently skipping at scan
   time.
2. For the self-contained single-workflow rules whose fix could have
   changed detection, the Vulnerable half still fires and the Safe
   half still passes (the batch-3 "strong check" shape).

The TAINT rules (TAINT-002/003/009) are taint-engine rules that need a
multi-workflow context to fire, so they are covered by the parse
contract only.
"""
from __future__ import annotations

import warnings

import pytest
import yaml

from pipeline_check.core.checks._yaml_lines import (
    safe_load_all_with_lines,
    safe_load_yaml_lines,
)
from pipeline_check.core.checks.github.rules import gha055_reusable_outputs_secret as gha055
from pipeline_check.core.checks.github.rules import gha072_overprovisioned_secrets as gha072
from pipeline_check.core.checks.github.rules import gha111_ai_iac_apply as gha111
from pipeline_check.core.checks.rule import discover_rules

from .conftest import run_check

_GH_RULES = [
    (rule.id, rule)
    for rule, _check in discover_rules("pipeline_check.core.checks.github.rules")
    if getattr(rule, "exploit_example", None)
]


def _parse_half(half: str) -> None:
    """Parse one example half the way the production loader would.

    A half that carries a ``---`` document separator (an example that
    deliberately shows two workflow files, e.g. GHA-002's split-the-
    workflow fix) is parsed as a multi-document stream; everything else
    is a single document. Duplicate top-level keys only warn, matching
    the real loader.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        if "\n---\n" in half or half.lstrip().startswith("---"):
            list(safe_load_all_with_lines(half))
        else:
            safe_load_yaml_lines(half)


@pytest.mark.parametrize("rule_id,rule", _GH_RULES, ids=[r[0] for r in _GH_RULES])
def test_every_example_parses(rule_id: str, rule) -> None:
    """No github exploit_example may contain unparseable YAML.

    Splits on the first blank line into the Vulnerable / Safe halves
    (the documented convention) and parses each. Catches the
    flow-mapping ``${{ }}`` and ``run:`` colon-space breakages the
    audit found, plus any future regression.
    """
    parts = rule.exploit_example.split("\n\n", 1)
    for half in parts:
        if half.strip():
            _parse_half(half)


class TestGha111AiIacApply:
    def test_exploit_example_strong_check(self) -> None:
        # Vulnerable half previously used ``with: { ref: ${{ ... }} }``
        # (flow mapping) which no YAML loader accepts, so the snippet
        # was silently skipped. Block style fixes it; the agent + IaC
        # apply co-located in one job must still fire.
        vuln, safe = gha111.RULE.exploit_example.split("\n\n", 1)
        assert gha111.check("wf.yml", yaml.safe_load(vuln)).passed is False
        assert gha111.check("wf.yml", yaml.safe_load(safe)).passed is True


class TestGha072OverprovisionedSecrets:
    def test_exploit_example_strong_check(self) -> None:
        # Both halves' ``run: curl -H "Authorization: Bearer ..."``
        # plain scalar carried a colon-space and failed to parse;
        # block scalars fix it. Job-level env still fires, step-level
        # env still passes.
        vuln, safe = gha072.RULE.exploit_example.split("\n\n", 1)
        assert gha072.check("wf.yml", yaml.safe_load(vuln)).passed is False
        assert gha072.check("wf.yml", yaml.safe_load(safe)).passed is True


class TestGha055ReusableOutputsSecret:
    def test_exploit_example_strong_check(self) -> None:
        # Vulnerable half's flow-sequence step
        # (``steps: [{ run: ... ${{ }} ... }]``) failed to parse; block
        # style fixes it. A reusable workflow exposing a secret through
        # ``outputs:`` must still fire; a non-secret output passes.
        vuln, safe = gha055.RULE.exploit_example.split("\n\n", 1)
        assert gha055.check("wf.yml", yaml.safe_load(vuln)).passed is False
        assert gha055.check("wf.yml", yaml.safe_load(safe)).passed is True


class TestGHA022PipUpgradeShortForm:
    """A5: ``pip install -U`` was dead code. ``DEP_UPDATE_RE`` matched a
    case-sensitive ``-U`` but the rules scan a lowercased blob (``-u``), so
    the common short form of ``--upgrade`` was never flagged. Exemptions
    for build/lint tooling must still hold."""

    def test_pip_dash_u_fires(self):
        wf = (
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: pip install -U requests\n"
        )
        assert run_check(wf, "GHA-022").passed is False

    def test_exempt_tooling_upgrade_still_passes(self):
        wf = (
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: pip install -U pip setuptools\n"
        )
        assert run_check(wf, "GHA-022").passed is True
