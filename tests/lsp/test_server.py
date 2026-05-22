"""Tests for the LSP server module.

The full stdio round-trip is exercised end-to-end in the editor; here
we cover the pure-Python helpers (URI translation, scan dispatch,
handler registration, error paths) without spinning up a real stdio
listener.
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip(
    "pygls",
    reason="LSP server is an optional install: `pip install pipeline-check[lsp]`",
)

from lsprotocol import types as lsp

from pipeline_check.core.checks.base import (
    Finding,
    Location,
    Severity,
)
from pipeline_check.lsp import server as server_mod
from pipeline_check.lsp.scan import supported_providers
from pipeline_check.lsp.server import (
    PipelineCheckLanguageServer,
    _publish,
    _register_handlers,
    _scan_uri,
    _uri_to_path,
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


# ── _uri_to_path ───────────────────────────────────────────────────


class TestUriToPath:
    def test_plain_file_uri_round_trips(self) -> None:
        # On POSIX the URI ``file:///etc/hosts`` should return ``/etc/hosts``;
        # on Windows the same path shape isn't valid but the function
        # still handles the leading slash correctly. We only assert the
        # path part for POSIX shapes here.
        path = _uri_to_path("file:///tmp/foo.yml")
        assert path is not None
        assert path.endswith("/tmp/foo.yml") or path.endswith("\\tmp\\foo.yml") or path == "/tmp/foo.yml"

    def test_non_file_scheme_returns_none(self) -> None:
        assert _uri_to_path("http://example.com/foo.yml") is None
        assert _uri_to_path("untitled:Untitled-1") is None
        assert _uri_to_path("vscode-remote://wsl%2Bubuntu/etc/hosts") is None

    def test_url_encoded_spaces_decoded(self) -> None:
        # The editor URI-encodes spaces; the file system needs them
        # raw, so unquote must run.
        path = _uri_to_path("file:///tmp/my%20file.yml")
        assert path is not None
        assert "my file.yml" in path

    @patch.object(server_mod, "os")
    def test_windows_drive_letter_leading_slash_stripped(self, mock_os) -> None:
        # On Windows, ``urlparse("file:///C:/Users/x.yml").path`` is
        # ``"/C:/Users/x.yml"``; the leading slash before the drive
        # letter has to be stripped. We patch os.name so the branch
        # runs deterministically on any host.
        mock_os.name = "nt"
        # ``sep`` is read by other helpers but not by _uri_to_path itself.
        # ``unquote`` is imported up-top so the patch on os only affects
        # the os.name branch.
        result = _uri_to_path("file:///C:/Users/me/foo.yml")
        assert result == "C:/Users/me/foo.yml"

    def test_empty_uri_returns_none(self) -> None:
        # ``urlparse("")`` yields scheme="" → not "file" → None.
        assert _uri_to_path("") is None


# ── _scan_uri ──────────────────────────────────────────────────────


class TestScanUri:
    def test_non_file_uri_returns_empty(self) -> None:
        ls = MagicMock(spec=PipelineCheckLanguageServer)
        result = _scan_uri(ls, "untitled:Untitled-1", "yaml content")
        assert result == []

    def test_unsupported_provider_returns_empty(self, tmp_path) -> None:
        # README.md is not a recognized provider file, so the detector
        # returns None and the scan short-circuits.
        ls = MagicMock(spec=PipelineCheckLanguageServer)
        path = tmp_path / "README.md"
        path.write_text("hello")
        uri = path.as_uri()
        assert _scan_uri(ls, uri, None) == []

    def test_supported_provider_runs_scan_on_disk(self, tmp_path) -> None:
        # A simple GitHub workflow with a known violation (no permissions
        # block, action pinned to a floating tag) should produce
        # diagnostics when scanned on disk.
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        wf = wf_dir / "ci.yml"
        wf.write_text(
            "name: CI\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: echo hi\n"
        )
        ls = MagicMock(spec=PipelineCheckLanguageServer)
        diagnostics = _scan_uri(ls, wf.as_uri(), None)
        # At least one diagnostic for the unpinned action / missing permissions.
        assert isinstance(diagnostics, list)
        assert all(isinstance(d, lsp.Diagnostic) for d in diagnostics)
        assert len(diagnostics) >= 1

    def test_in_memory_text_round_trips_via_tempfile(self, tmp_path) -> None:
        # When text is supplied, the function writes a temp file and
        # scans that. The resulting diagnostics' findings should have
        # paths rewritten back to the original document path before
        # translation.
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        wf = wf_dir / "ci.yml"
        # File is empty on disk; "live" text supplies the body so we
        # confirm the in-memory branch ran (the empty-file branch
        # would produce zero findings).
        wf.write_text("")
        text = (
            "name: CI\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
        )
        ls = MagicMock(spec=PipelineCheckLanguageServer)
        diagnostics = _scan_uri(ls, wf.as_uri(), text)
        assert isinstance(diagnostics, list)
        # The in-memory path ran, otherwise this would be 0.
        assert len(diagnostics) >= 1

    def test_scan_failure_logs_and_returns_empty(self, tmp_path, monkeypatch) -> None:
        # When the dispatched scan raises, the helper should swallow,
        # log to the server, and return an empty list rather than
        # propagating to the editor.
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        wf = wf_dir / "ci.yml"
        wf.write_text("name: CI\n")

        def _explode(*_a, **_kw):
            raise RuntimeError("synthetic blow-up")

        monkeypatch.setattr(server_mod, "scan_document", _explode)

        ls = MagicMock(spec=PipelineCheckLanguageServer)
        result = _scan_uri(ls, wf.as_uri(), None)
        assert result == []
        # The server should have been told about the failure once.
        assert ls.window_log_message.call_count == 1

    def test_tempfile_cleaned_up_even_on_scan_failure(
        self, tmp_path, monkeypatch,
    ) -> None:
        # The finally branch must unlink the tempfile when text is
        # supplied. Track the tempfile path and confirm it's gone
        # after the call, regardless of scan outcome.
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        wf = wf_dir / "ci.yml"
        wf.write_text("")

        seen_paths: list[str] = []

        def _capture(provider: str, path: str):
            seen_paths.append(path)
            raise RuntimeError("synthetic")

        monkeypatch.setattr(server_mod, "scan_document", _capture)
        ls = MagicMock(spec=PipelineCheckLanguageServer)
        _scan_uri(ls, wf.as_uri(), "name: CI\n")
        assert seen_paths, "scan_document should have been called"
        # The tempfile should no longer exist after the helper returned.
        assert not os.path.exists(seen_paths[0])


# ── _register_handlers + _publish ──────────────────────────────────


class TestHandlers:
    def test_register_handlers_attaches_four_features(self) -> None:
        # The four handlers cover didOpen / didChange / didSave / didClose.
        # We capture the feature registrations via a MagicMock spec'd
        # against the server class.
        ls = MagicMock(spec=PipelineCheckLanguageServer)
        # `feature` returns a decorator; MagicMock auto-handles that
        # for us as `feature.return_value(fn) -> MagicMock()`.
        _register_handlers(ls)
        registered_features = [c.args[0] for c in ls.feature.call_args_list]
        assert lsp.TEXT_DOCUMENT_DID_OPEN in registered_features
        assert lsp.TEXT_DOCUMENT_DID_CHANGE in registered_features
        assert lsp.TEXT_DOCUMENT_DID_SAVE in registered_features
        assert lsp.TEXT_DOCUMENT_DID_CLOSE in registered_features

    def test_create_server_registers_all_four(self) -> None:
        # End-to-end: create_server should produce an instance whose
        # protocol-level feature manager knows about the four LSP
        # text-document features we wire up.
        server = create_server()
        registered = set(server.protocol.fm.features.keys())
        for feature in (
            lsp.TEXT_DOCUMENT_DID_OPEN,
            lsp.TEXT_DOCUMENT_DID_CHANGE,
            lsp.TEXT_DOCUMENT_DID_SAVE,
            lsp.TEXT_DOCUMENT_DID_CLOSE,
        ):
            assert feature in registered

    def test_publish_calls_text_document_publish(self) -> None:
        ls = MagicMock(spec=PipelineCheckLanguageServer)
        diag = lsp.Diagnostic(
            range=lsp.Range(
                start=lsp.Position(line=0, character=0),
                end=lsp.Position(line=0, character=0),
            ),
            message="x",
        )
        _publish(ls, "file:///tmp/foo.yml", [diag])
        ls.text_document_publish_diagnostics.assert_called_once()
        kwargs = ls.text_document_publish_diagnostics.call_args
        # The PublishDiagnosticsParams object carries the URI and
        # diagnostic list together.
        params = kwargs.args[0]
        assert params.uri == "file:///tmp/foo.yml"
        assert params.diagnostics == [diag]


# ── lsp.__init__.__getattr__ ───────────────────────────────────────


class TestLspPackageGetattr:
    def test_main_attribute_lazy_loads(self) -> None:
        import pipeline_check.lsp as pkg
        main = pkg.main
        # Should resolve through __getattr__ to server.main.
        from pipeline_check.lsp.server import main as actual
        assert main is actual

    def test_unknown_attribute_raises(self) -> None:
        import pipeline_check.lsp as pkg
        with pytest.raises(AttributeError):
            pkg.does_not_exist  # noqa: B018


# ── findings path-rewrite contract ─────────────────────────────────


class TestScanUriRewritesFindingPaths:
    def test_in_memory_findings_get_original_path_back(
        self, tmp_path, monkeypatch,
    ) -> None:
        # When text is supplied, scan_document runs against a tempfile
        # and the findings carry the tempfile path on their Location.
        # ``_scan_uri`` must rewrite each Location.path back to the
        # *original* document path so the diagnostic-filter (matching
        # by path equality) still works after publish.
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        wf = wf_dir / "ci.yml"
        wf.write_text("")

        scanned_path_holder: dict[str, str] = {}

        def _fake_scan(provider: str, path: str) -> list[Finding]:
            scanned_path_holder["path"] = path
            return [Finding(
                check_id="GHA-001",
                title="t", severity=Severity.HIGH,
                resource=path, description="d",
                recommendation="r", passed=False,
                locations=[Location(path=path, start_line=1)],
            )]

        monkeypatch.setattr(server_mod, "scan_document", _fake_scan)
        ls = MagicMock(spec=PipelineCheckLanguageServer)
        diagnostics = _scan_uri(ls, wf.as_uri(), "name: CI\n")
        # If the rewrite happened, findings_to_diagnostics passed the
        # path filter (Finding.locations[0].path == document path), so
        # the diagnostic survived.
        assert len(diagnostics) == 1
        # The scan was run against a *different* path (the tempfile),
        # which proves the rewrite is what made the filter pass.
        assert scanned_path_holder["path"] != str(wf)
