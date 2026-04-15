"""Compliance standards — data-driven mappings between checks and controls.

Each Standard declares its controls and a check_id → control_id mapping.
The Scanner enriches every Finding with the ControlRefs that match it,
so a single check can contribute to multiple standards simultaneously
(e.g. S3-002 covers both OWASP CICD-SEC-9 and CIS AWS 2.1.1).

To add a new standard, create a module under
``pipeline_check/core/standards/data/`` that defines a module-level
``STANDARD`` object and import-registers it in
``pipeline_check/core/standards/__init__.py`` below.
"""
from __future__ import annotations

from .base import ControlRef, Standard
from .registry import available, get, register, resolve, resolve_for_check

# ── Register built-in standards ─────────────────────────────────────────────
from .data.owasp_cicd_top_10 import STANDARD as _OWASP
from .data.cis_aws_foundations import STANDARD as _CIS

register(_OWASP)
register(_CIS)

__all__ = [
    "ControlRef",
    "Standard",
    "available",
    "get",
    "register",
    "resolve",
    "resolve_for_check",
]
