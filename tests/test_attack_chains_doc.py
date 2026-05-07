"""Lock the auto-generated chain-catalog block in docs/attack_chains.md
against drift from the live registry.

The catalog cards under ``<!-- chain-catalog:start -->`` are produced
by ``scripts/gen_attack_chains_doc.py``. If a new chain lands in
``pipeline_check/core/chains/rules/`` (or an existing one's title /
severity / summary changes) the doc must be regenerated. This test
runs the generator in ``--check`` mode and fails the build if the
on-disk doc is out of sync.

Mirrors ``tests/test_rule_framework.py`` for provider docs.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_chain_catalog_doc_in_sync():
    result = subprocess.run(
        [sys.executable, "scripts/gen_attack_chains_doc.py", "--check"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        "docs/attack_chains.md chain-catalog block is out of sync. "
        "Re-run scripts/gen_attack_chains_doc.py and commit the result.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_every_registered_chain_has_a_card():
    """Spot-check: each AC-id from the registry shows up as an
    anchored H3 inside the catalog block. Catches a regression
    where the generator emits the table but skips some rules."""
    from pipeline_check.core.chains import engine

    doc = (REPO / "docs/attack_chains.md").read_text(encoding="utf-8")
    for rule in engine.list_rules():
        anchor_token = f"{{ #{rule.id.lower()} }}"
        assert anchor_token in doc, (
            f"chain {rule.id} missing from chain-catalog. Re-run "
            f"scripts/gen_attack_chains_doc.py."
        )
