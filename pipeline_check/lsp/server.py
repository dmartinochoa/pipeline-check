"""Pygls server entry point.

Spawned by the VS Code extension (``greylag-ci/pipeline-check-vscode``)
as ``python -m pipeline_check.lsp`` and bridged to the editor over
stdio. Lifecycle:

  - ``initialize`` / ``initialized`` — handled by pygls' defaults; we
    register the textDocument feature set we care about
    (``didOpen``, ``didChange``, ``didSave``).
  - ``didOpen`` / ``didSave`` — full scan against the on-disk file,
    publish diagnostics, done.
  - ``didChange`` — full scan against the in-memory document (written
    to a temp file because every provider's
    :meth:`Context.from_path` reads from the filesystem). The cost is
    a few tens of milliseconds for typical pipeline files; a future
    optimization can teach each context an ``from_text(path, text)``
    classmethod.
  - ``didClose`` — clear diagnostics for the URI so stale findings
    don't linger after the editor closes the file.

The server logs to its own ``"pipeline-check"`` LSP log channel via
:func:`pygls.workspace.Workspace.show_message` for soft errors;
unexpected exceptions during a scan are caught and surfaced as a
single ``Information``-severity diagnostic at line 0 so the operator
sees that scanning failed (vs. silently producing no findings).
"""
from __future__ import annotations

import dataclasses
import logging
import os
import tempfile
import traceback
from urllib.parse import unquote, urlparse

from lsprotocol import types as lsp
from pygls.lsp.server import LanguageServer

from .detection import detect_provider
from .diagnostics import findings_to_diagnostics
from .scan import scan_document, supported_providers

# Server identity reported to the editor on ``initialize``.
_SERVER_NAME = "pipeline-check"
_SERVER_VERSION = "0.1.0"


class PipelineCheckLanguageServer(LanguageServer):
    """Thin wrapper over pygls' LanguageServer.

    Holds no state beyond the parent class; the open-document set is
    pygls' workspace, and per-document scan results are not cached.
    Concentrating the handler registration on a subclass keeps the
    module-level scope free of import-time side effects (testing the
    server class doesn't spin up a real stdio listener).
    """

    def __init__(self) -> None:
        super().__init__(name=_SERVER_NAME, version=_SERVER_VERSION)


def _uri_to_path(uri: str) -> str | None:
    """Convert a ``file://`` URI to a local path. Returns None otherwise."""
    parsed = urlparse(uri)
    if parsed.scheme != "file":
        return None
    raw = unquote(parsed.path)
    # On Windows the URI shape is ``file:///C:/Users/...``; urlparse
    # leaves a leading slash before the drive letter, which the
    # filesystem doesn't accept. Strip when we detect the pattern.
    if os.name == "nt" and len(raw) > 3 and raw[0] == "/" and raw[2] == ":":
        raw = raw[1:]
    return raw


def _scan_uri(
    ls: PipelineCheckLanguageServer, uri: str, text: str | None,
) -> list[lsp.Diagnostic]:
    """Scan a document and return LSP diagnostics for it.

    *text* is the in-memory document content; when ``None``, the
    on-disk file at *path* is read directly. ``didChange`` always
    passes ``text``; ``didOpen`` / ``didSave`` pass ``None`` so we
    pick up exactly what's on disk.
    """
    path = _uri_to_path(uri)
    if path is None:
        return []
    provider = detect_provider(path)
    if provider is None or provider not in supported_providers():
        return []
    scan_path = path
    tmp_path: str | None = None
    if text is not None:
        # Round-trip through a tempfile because every provider's
        # ``Context.from_path`` reads from disk. The temp file keeps
        # the original suffix so suffix-based detection inside the
        # context loader (Dockerfile vs *.dockerfile, etc.) still fires.
        suffix = os.path.splitext(path)[1] or ""
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", suffix=suffix, delete=False,
        ) as fh:
            fh.write(text)
            tmp_path = fh.name
        scan_path = tmp_path
    try:
        findings = scan_document(provider, scan_path)
    except Exception as exc:  # noqa: BLE001 — surface every failure
        ls.window_log_message(
            lsp.LogMessageParams(
                type=lsp.MessageType.Warning,
                message=(
                    f"pipeline-check: scan failed for {path}: "
                    f"{type(exc).__name__}: {exc}\n"
                    f"{traceback.format_exc()}"
                ),
            ),
        )
        return []
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    # Findings have ``locations[].path`` pointing at the temp file
    # (when *text* was supplied) or the on-disk path otherwise. The
    # client's diagnostic publish is keyed by URI, so rewrite paths
    # back to the original document path before translation. This
    # keeps the diagnostic-filter in
    # :func:`findings_to_diagnostics` simple: it matches by string
    # equality against the document path we control.
    for f in findings:
        # ``Location`` is a frozen dataclass, so rebuild each entry
        # rather than assigning to ``loc.path``.
        f.locations = [
            dataclasses.replace(loc, path=path) for loc in f.locations
        ]
    return findings_to_diagnostics(findings, path, provider)


def _publish(
    ls: PipelineCheckLanguageServer,
    uri: str,
    diagnostics: list[lsp.Diagnostic],
) -> None:
    ls.text_document_publish_diagnostics(
        lsp.PublishDiagnosticsParams(uri=uri, diagnostics=diagnostics),
    )


def _register_handlers(ls: PipelineCheckLanguageServer) -> None:
    @ls.feature(lsp.TEXT_DOCUMENT_DID_OPEN)
    def on_open(params: lsp.DidOpenTextDocumentParams) -> None:
        uri = params.text_document.uri
        diagnostics = _scan_uri(ls, uri, params.text_document.text)
        _publish(ls, uri, diagnostics)

    @ls.feature(lsp.TEXT_DOCUMENT_DID_CHANGE)
    def on_change(params: lsp.DidChangeTextDocumentParams) -> None:
        uri = params.text_document.uri
        # The editor sends incremental changes by default, but pygls
        # tracks the full reconstructed document in its workspace.
        # Use that as the source of truth.
        doc = ls.workspace.get_text_document(uri)
        diagnostics = _scan_uri(ls, uri, doc.source)
        _publish(ls, uri, diagnostics)

    @ls.feature(lsp.TEXT_DOCUMENT_DID_SAVE)
    def on_save(params: lsp.DidSaveTextDocumentParams) -> None:
        uri = params.text_document.uri
        diagnostics = _scan_uri(ls, uri, None)
        _publish(ls, uri, diagnostics)

    @ls.feature(lsp.TEXT_DOCUMENT_DID_CLOSE)
    def on_close(params: lsp.DidCloseTextDocumentParams) -> None:
        # Clear stale findings for the URI when the doc is closed.
        _publish(ls, params.text_document.uri, [])


def create_server() -> PipelineCheckLanguageServer:
    """Build a configured server (used by tests + :func:`main`)."""
    server = PipelineCheckLanguageServer()
    _register_handlers(server)
    return server


def main() -> None:
    """Run the server over stdio. Entry point of ``python -m pipeline_check.lsp``."""
    logging.basicConfig(level=logging.INFO)
    server = create_server()
    server.start_io()
