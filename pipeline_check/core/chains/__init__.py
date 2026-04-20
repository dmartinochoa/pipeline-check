"""Attack-chain detection — correlate findings into multi-step attack narratives.

A single finding rarely captures the full risk: a `pull_request_target`
trigger is bad, AWS long-lived credentials are bad, an unprotected deploy
environment is bad — but the *combination* is exactly how the PyTorch
supply-chain compromise worked. This subpackage detects those
combinations and emits a higher-order :class:`Chain` finding mapped to
MITRE ATT&CK techniques.

Public surface:

    from pipeline_check.core.chains import evaluate, list_rules
    chains = evaluate(findings)        # list[Chain]
    rules  = list_rules()              # list[ChainRule]

Adding a new chain: drop a module under ``rules/`` exporting ``RULE``
(a :class:`ChainRule`) and ``match(findings) -> list[Chain]``. The
engine auto-discovers it.
"""
from __future__ import annotations

from .base import Chain, ChainRule
from .engine import evaluate, list_rules

__all__ = ["Chain", "ChainRule", "evaluate", "list_rules"]
