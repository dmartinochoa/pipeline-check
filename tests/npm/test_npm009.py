"""Per-rule tests for NPM-009 (new-transitive-dep diff gate).

Three layers exercised:

1. ``_name_from_install_path`` unit tests — name extraction across
   npm 7+, scoped, nested, pnpm / yarn-1 disambig, and npm 6 legacy
   shapes.
2. ``check`` behavior — silent-pass paths, new-transitive fire,
   direct-dep subtraction, version-bump-skip, mixed shapes.
3. ``load_base_locks_via_git`` — happy path (mocked subprocess),
   missing ref (warning, no raise), parse error (warning).

No git invocations: the loader's subprocess is monkeypatched out
via the ``git_show`` indirection so the tests stay hermetic.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pipeline_check.core.checks.base import Confidence, Severity
from pipeline_check.core.checks.npm import base as npm_base
from pipeline_check.core.checks.npm.base import (
    NpmContext,
    NpmLock,
    NpmManifest,
    load_base_locks_via_git,
)
from pipeline_check.core.checks.npm.pipelines import NpmChecks
from pipeline_check.core.checks.npm.rules.npm009_new_transitive_dep import (
    _lock_package_names,
    _name_from_install_path,
)

# ── _name_from_install_path ─────────────────────────────────────────


class TestNameFromInstallPath:
    def test_bare_top_level(self) -> None:
        assert _name_from_install_path("node_modules/lodash") == "lodash"

    def test_scoped_top_level(self) -> None:
        assert _name_from_install_path(
            "node_modules/@babel/core",
        ) == "@babel/core"

    def test_nested_transitive_strips_outer(self) -> None:
        # npm 7+ nested install: ``foo`` pulls ``bar`` in its own
        # ``node_modules``. The extractor returns ``bar``.
        assert _name_from_install_path(
            "node_modules/foo/node_modules/bar",
        ) == "bar"

    def test_nested_scoped_transitive(self) -> None:
        assert _name_from_install_path(
            "node_modules/foo/node_modules/@scope/bar",
        ) == "@scope/bar"

    def test_pnpm_disambig_suffix_stripped(self) -> None:
        assert _name_from_install_path(
            "node_modules/foo+1.2.3",
        ) == "foo"

    def test_pnpm_scoped_disambig_suffix_stripped(self) -> None:
        assert _name_from_install_path(
            "node_modules/@scope/foo+1.2.3",
        ) == "@scope/foo"

    def test_legacy_v1_bare_top_level(self) -> None:
        # npm 6 (lockfileVersion: 1) walks the ``dependencies``
        # tree and emits install paths without ``node_modules/``.
        assert _name_from_install_path("lodash") == "lodash"

    def test_legacy_v1_nested(self) -> None:
        # ``foo/bar`` means ``bar`` nested under ``foo``; the
        # installed package is ``bar``.
        assert _name_from_install_path("foo/bar") == "bar"

    def test_legacy_v1_nested_scoped(self) -> None:
        assert _name_from_install_path(
            "foo/@scope/bar",
        ) == "@scope/bar"

    def test_empty_returns_none(self) -> None:
        assert _name_from_install_path("") is None

    def test_disambig_without_name_returns_none(self) -> None:
        # Pathological: ``node_modules/+1.2.3`` has no name body.
        assert _name_from_install_path("node_modules/+1.2.3") is None


# ── _lock_package_names ─────────────────────────────────────────────


def _lock_with_packages(names: list[str], path: str = "package-lock.json") -> NpmLock:
    """Synthesize a minimal npm 7+ lock carrying ``names`` as packages."""
    packages = {
        f"node_modules/{name}": {"version": "1.0.0"} for name in names
    }
    packages[""] = {"name": "root"}  # root manifest entry, skipped
    return NpmLock(
        path=path,
        text=json.dumps({"packages": packages}, indent=2),
        data={"packages": packages},
        lockfile_version=3,
    )


class TestLockPackageNames:
    def test_collects_all_names(self) -> None:
        lock = _lock_with_packages(["lodash", "axios", "react"])
        assert _lock_package_names(lock) == {"lodash", "axios", "react"}

    def test_skips_root_entry(self) -> None:
        lock = _lock_with_packages(["lodash"])
        # The ``""`` root entry is skipped by iter_lock_packages.
        names = _lock_package_names(lock)
        assert "" not in names
        assert names == {"lodash"}

    def test_dedupes_multi_install_with_disambig(self) -> None:
        # pnpm / yarn-1 can install two versions of the same package
        # under ``foo`` and ``foo+2.0.0``. The extractor strips the
        # disambig, so both collapse to one name.
        packages = {
            "node_modules/foo": {"version": "1.0.0"},
            "node_modules/foo+2.0.0": {"version": "2.0.0"},
        }
        lock = NpmLock(
            path="package-lock.json",
            text=json.dumps({"packages": packages}),
            data={"packages": packages},
            lockfile_version=3,
        )
        assert _lock_package_names(lock) == {"foo"}


# ── NPM-009 rule via NpmChecks dispatch ─────────────────────────────


def _manifest(deps: dict[str, str] | None = None) -> NpmManifest:
    data: dict[str, Any] = {"name": "test", "version": "0.0.0"}
    if deps:
        data["dependencies"] = deps
    return NpmManifest(
        path="package.json", text=json.dumps(data, indent=2), data=data,
    )


def _run_npm009(ctx: NpmContext):
    findings = [f for f in NpmChecks(ctx).run() if f.check_id == "NPM-009"]
    assert findings, "expected at least one NPM-009 finding"
    return findings


class TestNpm009Rule:
    def test_silent_pass_when_no_base_locks(self) -> None:
        # Default path: --npm-base-ref was not passed, so the
        # provider's post_filter didn't populate base_locks.
        ctx = NpmContext(
            manifests=[_manifest({"lodash": "^4.0.0"})],
            locks=[_lock_with_packages(["lodash"])],
        )
        f = _run_npm009(ctx)[0]
        assert f.passed is True
        assert "npm-base-ref" in f.description

    def test_silent_pass_when_no_matching_base(self) -> None:
        # base_locks has a lock for a *different* path — there's no
        # counterpart to diff against, so the rule passes silently
        # rather than treating every current name as "new".
        ctx = NpmContext(
            manifests=[_manifest({"lodash": "^4.0.0"})],
            locks=[_lock_with_packages(["lodash"], path="a/package-lock.json")],
        )
        ctx.base_locks = [
            _lock_with_packages(["lodash"], path="b/package-lock.json"),
        ]
        f = _run_npm009(ctx)[0]
        assert f.passed is True
        assert "no base-ref counterpart" in f.description.lower()

    def test_fires_on_new_transitive(self) -> None:
        # Base lockfile carries only ``lodash``. Current adds
        # ``stealthy-transitive``, which is NOT in any manifest.
        ctx = NpmContext(
            manifests=[_manifest({"lodash": "^4.0.0"})],
            locks=[_lock_with_packages(["lodash", "stealthy-transitive"])],
        )
        ctx.base_locks = [_lock_with_packages(["lodash"])]
        f = _run_npm009(ctx)[0]
        assert f.passed is False
        assert "stealthy-transitive" in f.description
        assert f.severity is Severity.HIGH

    def test_does_not_fire_on_new_direct(self) -> None:
        # ``axios`` is new in the lockfile but also declared in
        # the manifest's ``dependencies`` — that's an intentional
        # add by the developer (NPM-008's territory if it's also
        # freshly published), not a stealthy transitive.
        ctx = NpmContext(
            manifests=[_manifest({"lodash": "^4.0.0", "axios": "^1.7.5"})],
            locks=[_lock_with_packages(["lodash", "axios"])],
        )
        ctx.base_locks = [_lock_with_packages(["lodash"])]
        f = _run_npm009(ctx)[0]
        assert f.passed is True

    def test_does_not_fire_on_version_bump(self) -> None:
        # Same package name, different version. NPM-009 diffs by
        # name only — NPM-006 / NPM-008 cover version-bump shapes.
        base_packages = {
            "node_modules/lodash": {"version": "4.17.20"},
        }
        current_packages = {
            "node_modules/lodash": {"version": "4.17.21"},
        }
        ctx = NpmContext(
            manifests=[_manifest({"lodash": "4.17.21"})],
            locks=[NpmLock(
                path="package-lock.json",
                text=json.dumps({"packages": current_packages}),
                data={"packages": current_packages},
                lockfile_version=3,
            )],
        )
        ctx.base_locks = [NpmLock(
            path="package-lock.json",
            text=json.dumps({"packages": base_packages}),
            data={"packages": base_packages},
            lockfile_version=3,
        )]
        f = _run_npm009(ctx)[0]
        assert f.passed is True

    def test_truncates_description_at_five(self) -> None:
        # Six new transitives in current; description summarizes
        # the first five and appends an ellipsis.
        new = [f"evil-{i}" for i in range(6)]
        ctx = NpmContext(
            manifests=[_manifest({"lodash": "^4.0.0"})],
            locks=[_lock_with_packages(["lodash", *new])],
        )
        ctx.base_locks = [_lock_with_packages(["lodash"])]
        f = _run_npm009(ctx)[0]
        assert f.passed is False
        assert "6 new transitive" in f.description
        assert f.description.count("evil-") == 5
        assert "…" in f.description

    def test_locations_capped_at_five(self) -> None:
        new = [f"evil-{i}" for i in range(7)]
        ctx = NpmContext(
            manifests=[_manifest({"lodash": "^4.0.0"})],
            locks=[_lock_with_packages(["lodash", *new])],
        )
        ctx.base_locks = [_lock_with_packages(["lodash"])]
        f = _run_npm009(ctx)[0]
        assert f.passed is False
        assert len(f.locations) == 5

    def test_passes_when_current_subset_of_base(self) -> None:
        # Dropping a transitive (current ⊂ base) is the dual of a
        # new-transitive — not in scope. The rule passes silently.
        ctx = NpmContext(
            manifests=[_manifest({"lodash": "^4.0.0"})],
            locks=[_lock_with_packages(["lodash"])],
        )
        ctx.base_locks = [_lock_with_packages(["lodash", "old-helper"])]
        f = _run_npm009(ctx)[0]
        assert f.passed is True

    def test_pnpm_disambig_collapses_in_diff(self) -> None:
        # Base has foo@1.0.0; current upgrades to foo@2.0.0 which
        # pnpm/yarn-1 install under ``node_modules/foo+2.0.0``.
        # After name extraction both lockfiles carry ``foo`` only,
        # so the diff is empty.
        base_packages = {
            "node_modules/foo": {"version": "1.0.0"},
        }
        current_packages = {
            "node_modules/foo": {"version": "1.0.0"},
            "node_modules/foo+2.0.0": {"version": "2.0.0"},
        }
        ctx = NpmContext(
            manifests=[_manifest({"foo": "^1.0.0"})],
            locks=[NpmLock(
                path="package-lock.json",
                text=json.dumps({"packages": current_packages}),
                data={"packages": current_packages},
                lockfile_version=3,
            )],
        )
        ctx.base_locks = [NpmLock(
            path="package-lock.json",
            text=json.dumps({"packages": base_packages}),
            data={"packages": base_packages},
            lockfile_version=3,
        )]
        f = _run_npm009(ctx)[0]
        assert f.passed is True

    def test_confidence_default_high(self) -> None:
        ctx = NpmContext(
            manifests=[_manifest({"lodash": "^4.0.0"})],
            locks=[_lock_with_packages(["lodash", "evil"])],
        )
        ctx.base_locks = [_lock_with_packages(["lodash"])]
        f = _run_npm009(ctx)[0]
        assert f.confidence is Confidence.HIGH
        assert f.severity is Severity.HIGH


# ── load_base_locks_via_git (subprocess-mocked) ─────────────────────


class TestLoadBaseLocksViaGit:
    def _ctx_with_one_lock(self, tmp_path: Path) -> NpmContext:
        lock_path = tmp_path / "package-lock.json"
        body = json.dumps({"packages": {"node_modules/lodash": {}}})
        lock_path.write_text(body, encoding="utf-8")
        return NpmContext.from_path(tmp_path)

    def test_happy_path_appends_base_lock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ctx = self._ctx_with_one_lock(tmp_path)
        # Base ref carries lodash + axios.
        base_body = json.dumps({"packages": {
            "node_modules/lodash": {},
            "node_modules/axios": {},
        }})
        monkeypatch.setattr(
            npm_base, "git_show",
            lambda ref, path, cwd: base_body,
        )
        load_base_locks_via_git(ctx, "main", tmp_path)
        assert len(ctx.base_locks) == 1
        base = ctx.base_locks[0]
        assert "node_modules/axios" in base.data["packages"]

    def test_missing_ref_warns_no_raise(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ctx = self._ctx_with_one_lock(tmp_path)
        monkeypatch.setattr(
            npm_base, "git_show",
            lambda ref, path, cwd: None,
        )
        load_base_locks_via_git(ctx, "nope-not-a-ref", tmp_path)
        assert ctx.base_locks == []
        assert any(
            "base ref" in w and "could not be resolved" in w
            for w in ctx.warnings
        )

    def test_parse_error_warns_no_raise(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ctx = self._ctx_with_one_lock(tmp_path)
        monkeypatch.setattr(
            npm_base, "git_show",
            lambda ref, path, cwd: "{not json",
        )
        load_base_locks_via_git(ctx, "main", tmp_path)
        assert ctx.base_locks == []
        assert any(
            "base-ref parse failed" in w for w in ctx.warnings
        )

    def test_scan_root_can_be_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # ``--npm-path foo/package-lock.json`` points at a file, not
        # a directory. The loader uses the file's parent as the
        # git working directory.
        ctx = self._ctx_with_one_lock(tmp_path)
        base_body = json.dumps({"packages": {"node_modules/lodash": {}}})
        cwd_seen: list[str] = []
        monkeypatch.setattr(
            npm_base, "git_show",
            lambda ref, path, cwd: (
                cwd_seen.append(str(cwd)) or base_body
            ),
        )
        lock_file = tmp_path / "package-lock.json"
        load_base_locks_via_git(ctx, "main", lock_file)
        assert len(ctx.base_locks) == 1
        # cwd argument resolves to the file's parent (the tmp_path).
        assert any(str(tmp_path) in c for c in cwd_seen)

    def test_yarn_lock_round_trips_through_loader(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Loader dispatches by filename, so a yarn.lock body comes
        # back synthesized to the npm 7+ shape — proving NPM-009
        # works on yarn-1 projects too.
        (tmp_path / "yarn.lock").write_text(
            "# yarn lockfile v1\n\n"
            'lodash@^4.0.0:\n'
            '  version "4.17.21"\n'
            '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"\n'
            '  integrity sha512-aaa==\n',
            encoding="utf-8",
        )
        ctx = NpmContext.from_path(tmp_path)
        base_body = (
            "# yarn lockfile v1\n\n"
            'lodash@^4.0.0:\n'
            '  version "4.17.20"\n'
            '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"\n'
            '  integrity sha512-bbb==\n'
        )
        monkeypatch.setattr(
            npm_base, "git_show",
            lambda ref, path, cwd: base_body,
        )
        load_base_locks_via_git(ctx, "main", tmp_path)
        assert len(ctx.base_locks) == 1
        # Synthesizer projects yarn-1 onto npm-7+ packages map.
        assert "node_modules/lodash" in ctx.base_locks[0].data["packages"]
