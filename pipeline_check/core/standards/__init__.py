"""Compliance standards, data-driven mappings between checks and controls.

Each Standard declares its controls and a check_id → control_id mapping.
The Scanner enriches every Finding with the ControlRefs that match it,
so a single check can contribute to multiple standards simultaneously
(e.g. S3-002 covers both OWASP CICD-SEC-9 and CIS AWS 2.1.1).

To add a new standard, drop a module under
``pipeline_check/core/standards/data/`` that defines a module-level
``STANDARD`` object. The package auto-discovers and registers every
non-underscore-prefixed module on import — no edit to this file is
required.
"""
from __future__ import annotations

import importlib
import pkgutil

from .base import ControlRef, Standard
from .registry import available, get, register, resolve, resolve_for_check


def _autoregister_data_modules() -> None:
    """Import every module under ``data/`` and register its ``STANDARD``.

    Mirrors ``chains/engine.py:_discover()`` and ``rule.py:discover_rules``:
    a sibling ``data`` package is walked via ``pkgutil.iter_modules``,
    each non-underscore module is imported, and its module-level
    ``STANDARD`` (if any) is registered. Hand-maintained
    ``register(_STD)`` calls were prone to silent drift the moment a
    new data module landed without a matching edit here.
    """
    from . import data as _data
    for info in sorted(
        pkgutil.iter_modules(_data.__path__),
        key=lambda m: m.name,
    ):
        if info.name.startswith("_"):
            continue
        mod = importlib.import_module(f"{_data.__name__}.{info.name}")
        standard = getattr(mod, "STANDARD", None)
        if isinstance(standard, Standard):
            register(standard)


_autoregister_data_modules()


__all__ = [
    "ControlRef",
    "Standard",
    "available",
    "get",
    "register",
    "resolve",
    "resolve_for_check",
]
