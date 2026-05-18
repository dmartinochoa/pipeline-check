"""Smoke tests for the LSP server module.

The full stdio round-trip is exercised end-to-end in the editor; here
we just confirm the server instantiates with handlers registered and
that the supported-providers table matches the detection table.
"""
from __future__ import annotations

import pytest

pytest.importorskip(
    "pygls",
    reason="LSP server is an optional install: `pip install pipeline-check[lsp]`",
)

from pipeline_check.lsp.scan import supported_providers  # noqa: E402
from pipeline_check.lsp.server import (  # noqa: E402
    PipelineCheckLanguageServer,
    create_server,
)


def test_server_instantiates() -> None:
    server = PipelineCheckLanguageServer()
    assert server.name == "pipeline-check"
    assert server.version == "0.1.0"


def test_create_server_returns_configured_instance() -> None:
    server = create_server()
    assert isinstance(server, PipelineCheckLanguageServer)


def test_supported_providers_covers_pilot_set() -> None:
    # The starter commit pilots single-file workflow providers plus
    # Dockerfile. Multi-file providers (k8s, helm, terraform, aws,
    # cloudformation, scm) are intentionally absent until a follow-up.
    expected = frozenset({
        "github", "gitlab", "azure", "bitbucket", "circleci",
        "cloudbuild", "buildkite", "drone", "jenkins", "dockerfile",
    })
    assert supported_providers() == expected
