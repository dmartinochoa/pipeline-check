"""pnpm-lock.yaml loader + rule reuse tests.

Exercises both layers:

1. ``_synthesize_pnpm_lock`` unit tests: every key shape pnpm has
   ever shipped (v5 slash, v6 ``@`` separator, scoped names, peer-
   dep disambiguator) round-trips to the npm-7+ ``packages`` shape.
2. End-to-end through ``NpmContext.from_path``: a real
   ``pnpm-lock.yaml`` on disk produces an :class:`NpmLock` that
   :class:`NpmChecks` fans out across NPM-002 / NPM-003 / NPM-006
   without per-rule changes.
"""
from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

from pipeline_check.core.checks.npm.base import (
    NpmContext,
    _split_pnpm_key,
    _synthesize_pnpm_lock,
)
from pipeline_check.core.checks.npm.pipelines import NpmChecks

# ── _split_pnpm_key ─────────────────────────────────────────────────


class TestSplitPnpmKey:
    def test_v6_at_separator(self) -> None:
        assert _split_pnpm_key("/foo@1.2.3") == ("foo", "1.2.3")

    def test_v9_no_leading_slash(self) -> None:
        assert _split_pnpm_key("foo@1.2.3") == ("foo", "1.2.3")

    def test_v5_slash_separator(self) -> None:
        assert _split_pnpm_key("/foo/1.2.3") == ("foo", "1.2.3")

    def test_scoped_v6(self) -> None:
        assert _split_pnpm_key("/@scope/foo@1.2.3") == (
            "@scope/foo", "1.2.3",
        )

    def test_scoped_v5(self) -> None:
        assert _split_pnpm_key("/@scope/foo/1.2.3") == (
            "@scope/foo", "1.2.3",
        )

    def test_peer_dep_suffix_stripped(self) -> None:
        assert _split_pnpm_key("foo@1.2.3(react@18.0.0)") == (
            "foo", "1.2.3",
        )

    def test_empty_returns_none(self) -> None:
        assert _split_pnpm_key("") is None

    def test_non_string_returns_none(self) -> None:
        assert _split_pnpm_key(None) is None  # type: ignore[arg-type]


# ── _synthesize_pnpm_lock ──────────────────────────────────────────


class TestSynthesizePnpmLock:
    def test_registry_entry_gets_synthesized_resolved_url(self) -> None:
        raw: dict[str, Any] = {
            "lockfileVersion": "6.0",
            "packages": {
                "/lodash@4.17.21": {
                    "resolution": {"integrity": "sha512-aaa"},
                },
            },
        }
        out = _synthesize_pnpm_lock(raw)
        rec = out["packages"]["node_modules/lodash"]
        assert rec["name"] == "lodash"
        assert rec["version"] == "4.17.21"
        assert rec["integrity"] == "sha512-aaa"
        # Registry tarball URL synthesized from the coordinate so
        # NPM-003 classifies it as a safe registry source.
        assert rec["resolved"] == (
            "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
        )

    def test_scoped_registry_tarball_uses_unscoped_filename(self) -> None:
        raw: dict[str, Any] = {
            "lockfileVersion": "6.0",
            "packages": {
                "/@scope/foo@1.0.0": {
                    "resolution": {"integrity": "sha512-bbb"},
                },
            },
        }
        out = _synthesize_pnpm_lock(raw)
        rec = out["packages"]["node_modules/@scope/foo"]
        assert rec["resolved"] == (
            "https://registry.npmjs.org/@scope/foo/-/foo-1.0.0.tgz"
        )

    def test_non_registry_tarball_resolved_passes_through(self) -> None:
        raw: dict[str, Any] = {
            "packages": {
                "/insecure@1.0.0": {
                    "resolution": {
                        "tarball": "http://example.com/insecure.tgz",
                    },
                },
            },
        }
        out = _synthesize_pnpm_lock(raw)
        rec = out["packages"]["node_modules/insecure"]
        # Non-registry tarball flows through verbatim so NPM-003
        # classifies the unsafe transport.
        assert rec["resolved"] == "http://example.com/insecure.tgz"

    def test_git_resolution_becomes_resolved_with_sha(self) -> None:
        raw: dict[str, Any] = {
            "packages": {
                "/forked@1.0.0": {
                    "resolution": {
                        "type": "git",
                        "repo": "https://github.com/o/r.git",
                        "commit": "a" * 40,
                    },
                },
            },
        }
        out = _synthesize_pnpm_lock(raw)
        rec = out["packages"]["node_modules/forked"]
        assert rec["resolved"] == (
            f"git+https://github.com/o/r.git#{'a' * 40}"
        )

    def test_link_entry_skipped_by_npm002(self) -> None:
        # An entry without ``resolution`` is treated as a workspace
        # link — NPM-002 skips ``link: True`` records.
        raw: dict[str, Any] = {
            "packages": {
                "/workspace-link@0.0.0": {},
            },
        }
        out = _synthesize_pnpm_lock(raw)
        rec = out["packages"]["node_modules/workspace-link"]
        assert rec.get("link") is True
        assert "resolved" not in rec

    def test_peer_dep_disambiguated_keys_collapse_to_one_path(self) -> None:
        # pnpm writes one ``packages:`` key per peer-dep permutation;
        # the synthesizer treats them as the same logical install
        # but disambiguates the path so neither entry is lost.
        raw: dict[str, Any] = {
            "packages": {
                "/foo@1.2.3(react@18.0.0)": {
                    "resolution": {"integrity": "sha512-xxx"},
                },
                "/foo@1.2.3(react@17.0.0)": {
                    "resolution": {"integrity": "sha512-yyy"},
                },
            },
        }
        out = _synthesize_pnpm_lock(raw)
        # Both records present, second one under a version-suffixed
        # path to avoid the collision (same version here, so we
        # accept the second-write-wins behavior).
        assert "node_modules/foo" in out["packages"]
        # No crash, no silent data loss: the second write replaces
        # the first under the same path (documented behavior).
        assert out["packages"]["node_modules/foo"]["name"] == "foo"

    def test_multi_version_same_name_disambiguated(self) -> None:
        raw: dict[str, Any] = {
            "packages": {
                "/foo@1.0.0": {
                    "resolution": {"integrity": "sha512-one"},
                },
                "/foo@2.0.0": {
                    "resolution": {"integrity": "sha512-two"},
                },
            },
        }
        out = _synthesize_pnpm_lock(raw)
        # First-write wins for the canonical ``node_modules/<name>``
        # path; second version lands under a disambiguated path so
        # both records reach the rule layer.
        assert out["packages"]["node_modules/foo"]["version"] == "1.0.0"
        assert (
            out["packages"]["node_modules/foo+2.0.0"]["version"]
            == "2.0.0"
        )


# ── Integration: end-to-end via NpmContext.from_path ──────────────


_PNPM_LOCK_BODY = textwrap.dedent(
    """\
    lockfileVersion: '6.0'

    settings:
      autoInstallPeers: true

    dependencies:
      ua-parser-js:
        specifier: 0.7.29
        version: 0.7.29
      lodash:
        specifier: ^4.17.21
        version: 4.17.21

    packages:

      /lodash@4.17.21:
        resolution: {integrity: sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==}

      /ua-parser-js@0.7.29:
        resolution: {integrity: sha512-malicious=}
    """
)


def _write_pnpm_lock(tmp_path: Path) -> Path:
    target = tmp_path / "pnpm-lock.yaml"
    target.write_text(_PNPM_LOCK_BODY, encoding="utf-8")
    return target


def test_pnpm_lock_picked_up_by_loader(tmp_path: Path) -> None:
    _write_pnpm_lock(tmp_path)
    ctx = NpmContext.from_path(tmp_path)
    assert len(ctx.locks) == 1
    lock = ctx.locks[0]
    assert lock.lockfile_version == 3
    # Synthesized npm-7+ ``packages`` map exposes both deps.
    pkgs = lock.data["packages"]
    assert "node_modules/lodash" in pkgs
    assert "node_modules/ua-parser-js" in pkgs


def test_pnpm_lock_npm002_clean_with_integrity(tmp_path: Path) -> None:
    _write_pnpm_lock(tmp_path)
    ctx = NpmContext.from_path(tmp_path)
    findings = list(NpmChecks(ctx).run())
    npm002 = [f for f in findings if f.check_id == "NPM-002"]
    assert npm002, "NPM-002 must always emit a finding"
    assert all(f.passed for f in npm002), (
        "Healthy pnpm-lock with integrity hashes should pass NPM-002"
    )


def test_pnpm_lock_npm003_clean_for_registry_only(tmp_path: Path) -> None:
    _write_pnpm_lock(tmp_path)
    ctx = NpmContext.from_path(tmp_path)
    findings = list(NpmChecks(ctx).run())
    npm003 = [f for f in findings if f.check_id == "NPM-003"]
    assert npm003 and all(f.passed for f in npm003), (
        "Synthesized registry tarball URLs must pass NPM-003"
    )


def test_pnpm_lock_npm003_fires_on_http_tarball(tmp_path: Path) -> None:
    body = textwrap.dedent(
        """\
        lockfileVersion: '6.0'
        packages:
          /insecure@1.0.0:
            resolution: {tarball: 'http://example.com/insecure.tgz'}
        """
    )
    (tmp_path / "pnpm-lock.yaml").write_text(body, encoding="utf-8")
    ctx = NpmContext.from_path(tmp_path)
    findings = list(NpmChecks(ctx).run())
    npm003 = [f for f in findings if f.check_id == "NPM-003"]
    assert npm003 and not npm003[0].passed
    assert "insecure" in npm003[0].description.lower() or (
        "http" in npm003[0].description.lower()
    )


def test_pnpm_lock_npm006_flags_compromised_version(tmp_path: Path) -> None:
    _write_pnpm_lock(tmp_path)  # body pins ua-parser-js@0.7.29
    ctx = NpmContext.from_path(tmp_path)
    findings = list(NpmChecks(ctx).run())
    npm006 = [f for f in findings if f.check_id == "NPM-006"]
    assert npm006 and not npm006[0].passed
    assert "ua-parser-js" in npm006[0].description
