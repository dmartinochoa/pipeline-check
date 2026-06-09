"""Tests for the policy-as-code overlay (``pipeline_check/core/policies.py``)."""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_check.core.policies import (
    BUILTIN_PACKS,
    POLICY_DIRS,
    Policy,
    PolicyError,
    builtin_policies,
    discover_policies,
    load_policy,
    policy_to_config_map,
)
from pipeline_check.core.standards import available as _standards_available

# ────────────────────────────────────────────────────────────────────────────
# load_policy: resolution + parsing
# ────────────────────────────────────────────────────────────────────────────


class TestLoadPolicyResolution:
    def test_loads_by_short_name_from_policies_dir(self, tmp_path: Path) -> None:
        (tmp_path / "policies").mkdir()
        (tmp_path / "policies" / "pre-merge.yml").write_text(
            "description: PR gate\n"
            "gate:\n"
            "  fail_on: HIGH\n",
            encoding="utf-8",
        )
        pol = load_policy("pre-merge", cwd=tmp_path)
        assert pol.name == "pre-merge"
        assert pol.description == "PR gate"
        assert pol.fail_on == "HIGH"

    def test_loads_by_short_name_from_dot_dir(self, tmp_path: Path) -> None:
        (tmp_path / ".pipeline-check" / "policies").mkdir(parents=True)
        (tmp_path / ".pipeline-check" / "policies" / "release.yaml").write_text(
            "gate:\n  fail_on: MEDIUM\n", encoding="utf-8",
        )
        pol = load_policy("release", cwd=tmp_path)
        assert pol.fail_on == "MEDIUM"

    def test_top_dir_wins_over_dot_dir(self, tmp_path: Path) -> None:
        (tmp_path / "policies").mkdir()
        (tmp_path / "policies" / "p.yml").write_text(
            "gate:\n  fail_on: LOW\n", encoding="utf-8",
        )
        (tmp_path / ".pipeline-check" / "policies").mkdir(parents=True)
        (tmp_path / ".pipeline-check" / "policies" / "p.yml").write_text(
            "gate:\n  fail_on: CRITICAL\n", encoding="utf-8",
        )
        pol = load_policy("p", cwd=tmp_path)
        assert pol.fail_on == "LOW"

    def test_explicit_path_loads_directly(self, tmp_path: Path) -> None:
        somewhere = tmp_path / "elsewhere"
        somewhere.mkdir()
        f = somewhere / "thing.yml"
        f.write_text("name: thing\ngate:\n  fail_on: HIGH\n", encoding="utf-8")
        pol = load_policy(str(f), cwd=tmp_path)
        assert pol.name == "thing"
        assert pol.fail_on == "HIGH"

    def test_unknown_name_raises(self, tmp_path: Path) -> None:
        with pytest.raises(PolicyError) as exc:
            load_policy("nope", cwd=tmp_path)
        assert "not found" in str(exc.value)

    def test_traversal_in_name_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(PolicyError):
            load_policy("../etc/passwd", cwd=tmp_path)
        with pytest.raises(PolicyError):
            load_policy("sub/policy", cwd=tmp_path)

    def test_empty_name_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(PolicyError):
            load_policy("   ", cwd=tmp_path)

    def test_yml_preferred_over_yaml(self, tmp_path: Path) -> None:
        (tmp_path / "policies").mkdir()
        (tmp_path / "policies" / "p.yml").write_text(
            "gate:\n  fail_on: HIGH\n", encoding="utf-8",
        )
        (tmp_path / "policies" / "p.yaml").write_text(
            "gate:\n  fail_on: CRITICAL\n", encoding="utf-8",
        )
        pol = load_policy("p", cwd=tmp_path)
        assert pol.fail_on == "HIGH"


# ────────────────────────────────────────────────────────────────────────────
# Schema: every field round-trips
# ────────────────────────────────────────────────────────────────────────────


class TestSchema:
    def test_full_round_trip(self, tmp_path: Path) -> None:
        (tmp_path / "policies").mkdir()
        (tmp_path / "policies" / "release-gate.yml").write_text(
            "name: release-gate\n"
            "description: release-only profile\n"
            "checks: [GHA-001, GHA-016, ATTEST-*]\n"
            "standards: [owasp_cicd_top_10, slsa]\n"
            "gate:\n"
            "  fail_on: MEDIUM\n"
            "  min_grade: B\n"
            "  max_failures: 10\n"
            "  fail_on_checks: [GHA-019]\n"
            "overrides:\n"
            "  GHA-016:\n"
            "    severity: LOW\n"
            "  ATTEST-001:\n"
            "    severity: CRITICAL\n",
            encoding="utf-8",
        )
        pol = load_policy("release-gate", cwd=tmp_path)
        assert pol.name == "release-gate"
        assert pol.description == "release-only profile"
        assert pol.checks == ("GHA-001", "GHA-016", "ATTEST-*")
        assert pol.standards == ("owasp_cicd_top_10", "slsa")
        assert pol.fail_on == "MEDIUM"
        assert pol.min_grade == "B"
        assert pol.max_failures == 10
        assert pol.fail_on_checks == ("GHA-019",)
        assert pol.overrides == {
            "GHA-016": {"severity": "LOW"},
            "ATTEST-001": {"severity": "CRITICAL"},
        }

    def test_name_defaults_to_stem(self, tmp_path: Path) -> None:
        (tmp_path / "policies").mkdir()
        (tmp_path / "policies" / "pre-commit.yml").write_text(
            "gate:\n  fail_on: HIGH\n", encoding="utf-8",
        )
        pol = load_policy("pre-commit", cwd=tmp_path)
        assert pol.name == "pre-commit"

    def test_empty_policy_is_valid(self, tmp_path: Path) -> None:
        """A file that just names itself is a no-op policy."""
        (tmp_path / "policies").mkdir()
        (tmp_path / "policies" / "noop.yml").write_text(
            "description: deliberately empty\n", encoding="utf-8",
        )
        pol = load_policy("noop", cwd=tmp_path)
        assert pol.name == "noop"
        assert pol.checks == ()
        assert pol.fail_on is None
        assert pol.overrides == {}

    def test_severity_normalized_to_upper(self, tmp_path: Path) -> None:
        (tmp_path / "policies").mkdir()
        (tmp_path / "policies" / "p.yml").write_text(
            "gate:\n  fail_on: high\n"
            "overrides:\n"
            "  gha-016:\n"
            "    severity: low\n",
            encoding="utf-8",
        )
        pol = load_policy("p", cwd=tmp_path)
        assert pol.fail_on == "HIGH"
        assert pol.overrides == {"GHA-016": {"severity": "LOW"}}

    def test_check_ids_normalized_to_upper(self, tmp_path: Path) -> None:
        (tmp_path / "policies").mkdir()
        (tmp_path / "policies" / "p.yml").write_text(
            "checks: [gha-001, GHA-002]\n", encoding="utf-8",
        )
        pol = load_policy("p", cwd=tmp_path)
        assert pol.checks == ("GHA-001", "GHA-002")


# ────────────────────────────────────────────────────────────────────────────
# Schema: rejection paths
# ────────────────────────────────────────────────────────────────────────────


class TestSchemaErrors:
    def _make(self, tmp_path: Path, body: str) -> Path:
        (tmp_path / "policies").mkdir()
        f = tmp_path / "policies" / "p.yml"
        f.write_text(body, encoding="utf-8")
        return f

    def test_empty_file_rejected(self, tmp_path: Path) -> None:
        self._make(tmp_path, "")
        with pytest.raises(PolicyError, match="empty"):
            load_policy("p", cwd=tmp_path)

    def test_top_level_list_rejected(self, tmp_path: Path) -> None:
        self._make(tmp_path, "- name: thing\n")
        with pytest.raises(PolicyError, match="must be a mapping"):
            load_policy("p", cwd=tmp_path)

    def test_invalid_severity_rejected(self, tmp_path: Path) -> None:
        self._make(tmp_path, "gate:\n  fail_on: SUPER\n")
        with pytest.raises(PolicyError, match="fail_on"):
            load_policy("p", cwd=tmp_path)

    def test_invalid_grade_rejected(self, tmp_path: Path) -> None:
        self._make(tmp_path, "gate:\n  min_grade: F\n")
        with pytest.raises(PolicyError, match="min_grade"):
            load_policy("p", cwd=tmp_path)

    def test_non_int_max_failures_rejected(self, tmp_path: Path) -> None:
        self._make(tmp_path, "gate:\n  max_failures: many\n")
        with pytest.raises(PolicyError, match="max_failures"):
            load_policy("p", cwd=tmp_path)

    def test_bool_max_failures_rejected(self, tmp_path: Path) -> None:
        self._make(tmp_path, "gate:\n  max_failures: true\n")
        with pytest.raises(PolicyError, match="max_failures"):
            load_policy("p", cwd=tmp_path)

    def test_negative_max_failures_rejected(self, tmp_path: Path) -> None:
        self._make(tmp_path, "gate:\n  max_failures: -3\n")
        with pytest.raises(PolicyError, match="non-negative"):
            load_policy("p", cwd=tmp_path)

    def test_checks_not_a_list_rejected(self, tmp_path: Path) -> None:
        self._make(tmp_path, "checks: GHA-001\n")
        with pytest.raises(PolicyError, match="must be a list"):
            load_policy("p", cwd=tmp_path)

    def test_overrides_not_a_mapping_rejected(self, tmp_path: Path) -> None:
        self._make(tmp_path, "overrides: GHA-001\n")
        with pytest.raises(PolicyError, match="overrides"):
            load_policy("p", cwd=tmp_path)

    def test_unknown_top_level_key_warns_not_raises(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str],
    ) -> None:
        self._make(
            tmp_path,
            "name: p\ngate:\n  fail_on: HIGH\nunknown_field: oops\n",
        )
        pol = load_policy("p", cwd=tmp_path)
        assert pol.fail_on == "HIGH"
        captured = capsys.readouterr()
        assert "ignoring unknown key 'unknown_field'" in captured.err

    def test_bad_override_severity_warns_not_raises(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str],
    ) -> None:
        self._make(
            tmp_path,
            "overrides:\n  GHA-016:\n    severity: SUPER\n",
        )
        pol = load_policy("p", cwd=tmp_path)
        assert pol.overrides == {}
        captured = capsys.readouterr()
        assert "ignoring overrides" in captured.err

    def test_malformed_yaml_raises(self, tmp_path: Path) -> None:
        self._make(tmp_path, "name: p\n  bad: indent\n: [\n")
        with pytest.raises(PolicyError, match="could not parse"):
            load_policy("p", cwd=tmp_path)


# ────────────────────────────────────────────────────────────────────────────
# discover_policies
# ────────────────────────────────────────────────────────────────────────────


class TestDiscoverPolicies:
    def test_no_dir_returns_empty(self, tmp_path: Path) -> None:
        assert discover_policies(cwd=tmp_path) == []

    def test_lists_all_files_in_first_dir(self, tmp_path: Path) -> None:
        (tmp_path / "policies").mkdir()
        for name in ("a.yml", "b.yml", "c.yaml"):
            (tmp_path / "policies" / name).write_text(
                "gate:\n  fail_on: HIGH\n", encoding="utf-8",
            )
        out = discover_policies(cwd=tmp_path)
        names = sorted(p.name for p in out)
        assert names == ["a", "b", "c"]

    def test_ignores_non_yaml_files(self, tmp_path: Path) -> None:
        (tmp_path / "policies").mkdir()
        (tmp_path / "policies" / "README.md").write_text("hi", encoding="utf-8")
        (tmp_path / "policies" / "real.yml").write_text(
            "gate:\n  fail_on: HIGH\n", encoding="utf-8",
        )
        out = discover_policies(cwd=tmp_path)
        assert [p.name for p in out] == ["real"]

    def test_top_dir_blocks_dot_dir(self, tmp_path: Path) -> None:
        (tmp_path / "policies").mkdir()
        (tmp_path / "policies" / "a.yml").write_text(
            "gate:\n  fail_on: HIGH\n", encoding="utf-8",
        )
        (tmp_path / ".pipeline-check" / "policies").mkdir(parents=True)
        (tmp_path / ".pipeline-check" / "policies" / "b.yml").write_text(
            "gate:\n  fail_on: HIGH\n", encoding="utf-8",
        )
        out = discover_policies(cwd=tmp_path)
        assert [p.name for p in out] == ["a"]

    def test_dot_dir_used_when_top_dir_absent(self, tmp_path: Path) -> None:
        (tmp_path / ".pipeline-check" / "policies").mkdir(parents=True)
        (tmp_path / ".pipeline-check" / "policies" / "b.yml").write_text(
            "gate:\n  fail_on: HIGH\n", encoding="utf-8",
        )
        out = discover_policies(cwd=tmp_path)
        assert [p.name for p in out] == ["b"]

    def test_broken_file_is_skipped_with_warning(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str],
    ) -> None:
        (tmp_path / "policies").mkdir()
        (tmp_path / "policies" / "good.yml").write_text(
            "gate:\n  fail_on: HIGH\n", encoding="utf-8",
        )
        (tmp_path / "policies" / "broken.yml").write_text(
            "gate:\n  fail_on: NOTREAL\n", encoding="utf-8",
        )
        out = discover_policies(cwd=tmp_path)
        assert [p.name for p in out] == ["good"]
        captured = capsys.readouterr()
        assert "skipping" in captured.err


# ────────────────────────────────────────────────────────────────────────────
# policy_to_config_map
# ────────────────────────────────────────────────────────────────────────────


class TestPolicyToConfigMap:
    def test_empty_policy_emits_empty_map(self) -> None:
        pol = Policy(name="p", source="dummy")
        assert policy_to_config_map(pol) == {}

    def test_each_field_maps_to_click_option(self) -> None:
        pol = Policy(
            name="p",
            source="dummy",
            checks=("GHA-001",),
            standards=("owasp_cicd_top_10",),
            fail_on="HIGH",
            min_grade="B",
            max_failures=5,
            fail_on_checks=("GHA-002",),
            overrides={"GHA-016": {"severity": "LOW"}},
        )
        m = policy_to_config_map(pol)
        assert m == {
            "checks": ("GHA-001",),
            "standards": ("owasp_cicd_top_10",),
            "fail_on": "HIGH",
            "min_grade": "B",
            "max_failures": 5,
            "fail_on_checks": ("GHA-002",),
        }
        # overrides intentionally NOT in the map; the CLI handles them
        # off the Policy object directly.
        assert "overrides" not in m


# ────────────────────────────────────────────────────────────────────────────
# Sanity: POLICY_DIRS is the expected search path
# ────────────────────────────────────────────────────────────────────────────


def test_policy_dirs_contains_documented_paths() -> None:
    """``--list-policies`` help text claims these paths; lock them."""
    assert "policies" in POLICY_DIRS
    assert ".pipeline-check/policies" in POLICY_DIRS


# ────────────────────────────────────────────────────────────────────────────
# Built-in packs
# ────────────────────────────────────────────────────────────────────────────


class TestBuiltinPacks:
    def test_builtin_policies_all_parse_and_validate(self) -> None:
        """Every shipped pack round-trips through the same loader as a file."""
        pols = builtin_policies()
        assert {p.name for p in pols} == set(BUILTIN_PACKS)
        for p in pols:
            assert p.name, p
            assert p.description, f"{p.name}: built-in packs must self-describe"
            assert p.source.startswith("<built-in:")

    def test_builtin_standards_filters_are_registered(self) -> None:
        """A pack's ``standards`` focus must name real registered standards."""
        registered = set(_standards_available())
        for p in builtin_policies():
            for std in p.standards:
                assert std in registered, f"{p.name}: unknown standard {std!r}"

    def test_load_builtin_by_name_from_empty_cwd(self, tmp_path: Path) -> None:
        """A built-in pack resolves by name when no local policy dir exists."""
        pol = load_policy("slsa-l3", cwd=tmp_path)
        assert pol.name == "slsa-l3"
        assert pol.fail_on == "HIGH"
        assert "slsa" in pol.standards

    def test_supply_chain_strict_override_normalized(self) -> None:
        pol = load_policy("supply-chain-strict", cwd=Path("/nonexistent"))
        assert pol.overrides == {"GHA-001": {"severity": "CRITICAL"}}
        assert pol.min_grade == "B"

    def test_local_file_shadows_builtin(self, tmp_path: Path) -> None:
        """A local ``policies/<name>.yml`` wins over a same-named built-in."""
        (tmp_path / "policies").mkdir()
        (tmp_path / "policies" / "slsa-l3.yml").write_text(
            "gate:\n  fail_on: LOW\n", encoding="utf-8",
        )
        pol = load_policy("slsa-l3", cwd=tmp_path)
        assert pol.fail_on == "LOW"
        assert not pol.source.startswith("<built-in:")

    def test_unknown_name_error_lists_builtins(self, tmp_path: Path) -> None:
        with pytest.raises(PolicyError) as exc:
            load_policy("ghost", cwd=tmp_path)
        # The error should point the user at the built-in packs.
        assert "slsa-l3" in str(exc.value)

    def test_discover_policies_stays_local_only(self, tmp_path: Path) -> None:
        """Built-ins are surfaced by ``--list-policies`` (CLI), not by the
        local-discovery helper, which keeps its on-disk-only contract."""
        assert discover_policies(cwd=tmp_path) == []


# ────────────────────────────────────────────────────────────────────────────
# load_policy: remote (https URL) shareable packs
# ────────────────────────────────────────────────────────────────────────────


class _FakeResp:
    """Minimal context-manager response with ``.read(n)``."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self, n: int = -1) -> bytes:
        return self._body


_REMOTE_YAML = (
    b"name: fintech-strict\n"
    b"description: shared gate\n"
    b"gate:\n"
    b"  fail_on: HIGH\n"
    b"  min_grade: B\n"
)

_SAFE_HTTP = "pipeline_check.core.checks._primitives.safe_http.urlopen_https_only"


class TestLoadPolicyURL:
    def test_https_url_fetches_and_validates(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setattr(
            "pipeline_check.core.policies._policy_cache_dir",
            lambda: tmp_path / "cache",
        )
        monkeypatch.setattr(_SAFE_HTTP, lambda req, timeout: _FakeResp(_REMOTE_YAML))
        url = "https://example.com/policies/fintech-strict.yml"
        pol = load_policy(url)
        assert pol.name == "fintech-strict"
        assert pol.fail_on == "HIGH"
        assert pol.min_grade == "B"
        # The source is the verbatim URL (not the //-collapsed Path form).
        assert pol.source == url

    def test_http_url_rejected(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setattr(
            "pipeline_check.core.policies._policy_cache_dir",
            lambda: tmp_path / "cache",
        )
        with pytest.raises(PolicyError) as exc:
            load_policy("http://example.com/p.yml")
        assert "https" in str(exc.value)

    def test_oversized_remote_policy_rejected(self, monkeypatch, tmp_path) -> None:
        from pipeline_check.core.policies import _MAX_POLICY_BYTES

        monkeypatch.setattr(
            "pipeline_check.core.policies._policy_cache_dir",
            lambda: tmp_path / "cache",
        )
        big = b"name: x\n" + b"#" * (_MAX_POLICY_BYTES + 10)
        monkeypatch.setattr(_SAFE_HTTP, lambda req, timeout: _FakeResp(big))
        with pytest.raises(PolicyError) as exc:
            load_policy("https://example.com/big.yml")
        assert "too large" in str(exc.value)

    def test_fetch_failure_falls_back_to_cache(self, monkeypatch, tmp_path) -> None:
        import urllib.error

        cache = tmp_path / "cache"
        monkeypatch.setattr(
            "pipeline_check.core.policies._policy_cache_dir", lambda: cache
        )
        url = "https://example.com/p.yml"
        # First call succeeds and populates the cache.
        monkeypatch.setattr(_SAFE_HTTP, lambda req, timeout: _FakeResp(_REMOTE_YAML))
        assert load_policy(url).name == "fintech-strict"
        # Second call: the network is down; the cached copy still resolves.
        def _boom(req, timeout):
            raise urllib.error.URLError("offline")

        monkeypatch.setattr(_SAFE_HTTP, _boom)
        assert load_policy(url).name == "fintech-strict"

    def test_fetch_failure_without_cache_raises(self, monkeypatch, tmp_path) -> None:
        import urllib.error

        monkeypatch.setattr(
            "pipeline_check.core.policies._policy_cache_dir",
            lambda: tmp_path / "cache",
        )

        def _boom(req, timeout):
            raise urllib.error.URLError("offline")

        monkeypatch.setattr(_SAFE_HTTP, _boom)
        with pytest.raises(PolicyError) as exc:
            load_policy("https://example.com/p.yml")
        assert "could not fetch" in str(exc.value)

    def test_non_utf8_body_raises_and_does_not_fall_back_to_cache(
        self, monkeypatch, tmp_path
    ) -> None:
        # A successful (200) fetch that isn't valid UTF-8 is a bad response,
        # not a network failure: it must surface, never silently serve the
        # stale cached copy (which could mask a changed / hijacked endpoint).
        cache = tmp_path / "cache"
        monkeypatch.setattr(
            "pipeline_check.core.policies._policy_cache_dir", lambda: cache
        )
        url = "https://example.com/p.yml"
        # Prime the cache with a good fetch.
        monkeypatch.setattr(_SAFE_HTTP, lambda req, timeout: _FakeResp(_REMOTE_YAML))
        assert load_policy(url).name == "fintech-strict"
        # Now the endpoint returns a non-UTF-8 body: must raise, not fall back.
        monkeypatch.setattr(
            _SAFE_HTTP, lambda req, timeout: _FakeResp(b"\xff\xfe\x00\x80bad")
        )
        with pytest.raises(PolicyError) as exc:
            load_policy(url)
        assert "UTF-8" in str(exc.value)
