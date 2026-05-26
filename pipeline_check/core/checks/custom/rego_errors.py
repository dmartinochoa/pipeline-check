"""Error types for the OPA/Rego custom-rule subsystem."""
from __future__ import annotations

import shutil


class RegoRuleError(ValueError):
    """Raised when a Rego rule file fails validation or evaluation."""


class OpaNotFoundError(RegoRuleError):
    """Raised when the ``opa`` binary is not on ``PATH``."""

    def __init__(self) -> None:
        super().__init__(
            "opa binary not found on PATH. Rego rules require OPA "
            "(https://www.openpolicyagent.org/docs/latest/#running-opa). "
            "Install it and ensure 'opa version' succeeds before using "
            "--rego-rules."
        )


def find_opa_binary() -> str:
    """Return the path to the ``opa`` binary, or raise."""
    opa = shutil.which("opa")
    if opa is None:
        raise OpaNotFoundError()
    return opa


__all__ = ["OpaNotFoundError", "RegoRuleError", "find_opa_binary"]
