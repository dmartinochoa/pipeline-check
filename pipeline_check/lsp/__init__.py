"""LSP server for the pipeline-check VS Code extension.

Runs as ``python -m pipeline_check.lsp``. The TypeScript extension in
``greylag-ci/pipeline-check-vscode`` spawns this process and exchanges
Language Server Protocol messages over stdin / stdout. The server reads
the same rule registry the CLI does, so editor diagnostics match
``pipeline_check --output json`` byte-for-byte modulo position
translation.

This module ships under an optional install extra::

    pip install pipeline-check[lsp]

The base install does not pull in ``pygls``. ``main`` is exposed lazily
through ``__getattr__`` so the pure-Python helpers in this package
(``detection.detect_provider``) stay importable without the extra.
"""
from __future__ import annotations

from typing import Any

__all__ = ["main"]


def __getattr__(name: str) -> Any:
    if name == "main":
        from .server import main

        return main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
