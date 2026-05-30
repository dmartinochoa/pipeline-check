"""Per-rule unit tests for GOMOD-011..012 (Go modules supply-chain pack)."""
from __future__ import annotations

import pathlib

from pipeline_check.core.checks.gomod.base import GoModContext
from pipeline_check.core.checks.gomod.pipelines import GoModChecks


def _scan(tmp_path: pathlib.Path, go_mod: str, has_sum: bool = True):
    (tmp_path / "go.mod").write_text(go_mod, encoding="utf-8")
    if has_sum:
        (tmp_path / "go.sum").write_text("", encoding="utf-8")
    ctx = GoModContext.from_path(str(tmp_path / "go.mod"))
    return {f.check_id: f for f in GoModChecks(ctx).run()}


# ── GOMOD-011 (tool directive) ──────────────────────────────────


class TestGoMod011ToolDirective:
    def test_passes_with_no_tool_directive(self, tmp_path):
        go_mod = (
            "module example.com/x\ngo 1.24\n"
            "require github.com/foo/bar v1.0.0\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert findings["GOMOD-011"].passed

    def test_fires_on_single_line_tool(self, tmp_path):
        go_mod = (
            "module example.com/x\ngo 1.24\n"
            "tool example.com/x/gen\n"
            "require example.com/x/gen v1.2.0\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert not findings["GOMOD-011"].passed
        # The require-pinned version is surfaced in the description.
        assert "v1.2.0" in findings["GOMOD-011"].description

    def test_fires_on_tool_block(self, tmp_path):
        go_mod = (
            "module example.com/x\ngo 1.24\n"
            "tool (\n"
            "    example.com/x/gen\n"
            "    example.com/y/mock\n"
            ")\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert not findings["GOMOD-011"].passed
        assert "example.com/x/gen" in findings["GOMOD-011"].description
        assert "example.com/y/mock" in findings["GOMOD-011"].description

    def test_toolchain_directive_is_not_a_tool(self, tmp_path):
        """``toolchain go1.24`` must not be mistaken for a ``tool``."""
        go_mod = (
            "module example.com/x\ngo 1.24\n"
            "toolchain go1.24.2\n"
            "require github.com/foo/bar v1.0.0\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert findings["GOMOD-011"].passed


# ── GOMOD-012 (insecure / non-canonical host) ───────────────────


class TestGoMod012InsecureHost:
    def test_passes_on_canonical_hosts(self, tmp_path):
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require github.com/foo/bar v1.0.0\n"
            "require git.internal.example.com/team/util v1.2.0\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert findings["GOMOD-012"].passed

    def test_fires_on_bare_ip_host(self, tmp_path):
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require 10.0.0.42/team/util v1.0.0\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert not findings["GOMOD-012"].passed
        assert "bare IP" in findings["GOMOD-012"].description

    def test_fires_on_explicit_port_in_replace_target(self, tmp_path):
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require example.com/x v1.0.0\n"
            "replace example.com/x => git.internal:8443/mirror/x v1.0.0\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert not findings["GOMOD-012"].passed
        assert ":port" in findings["GOMOD-012"].description

    def test_skips_local_path_replace(self, tmp_path):
        """Local-path replaces are GOMOD-002's surface, not a host."""
        go_mod = (
            "module example.com/x\ngo 1.22\n"
            "require example.com/x v1.0.0\n"
            "replace example.com/x => ../local-fork\n"
        )
        findings = _scan(tmp_path, go_mod)
        assert findings["GOMOD-012"].passed
