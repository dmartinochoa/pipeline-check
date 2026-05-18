"""LSP server for the pipeline-check VS Code extension.

Runs as ``python -m pipeline_check.lsp``. The TypeScript extension in
``greylag-ci/pipeline-check-vscode`` spawns this process and exchanges
Language Server Protocol messages over stdin / stdout. The server reads
the same rule registry the CLI does, so editor diagnostics match
``pipeline_check --output json`` byte-for-byte modulo position
translation.

This module ships under an optional install extra::

    pip install pipeline-check[lsp]

The base install does not pull in ``pygls`` so the AWS-Lambda /
minimal-install footprints stay unchanged.
"""
from __future__ import annotations

from .server import main

__all__ = ["main"]
