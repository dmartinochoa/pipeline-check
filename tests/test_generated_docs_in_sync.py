"""Strong drift guard: every generated doc on disk must equal a
fresh render from the live registries.

The doc set under ``docs/providers/`` and ``docs/standards/`` is
produced by four scripts:

  - ``scripts/gen_provider_docs.py``        (provider reference pages)
  - ``scripts/gen_standards_docs.py``       (per-standard reference pages)
  - ``scripts/gen_attack_chains_doc.py``    (chain catalog in attack_chains.md)
  - ``scripts/link_standards_check_ids.py`` (mapping-table cell linking)

Drift sources the existing tests don't fully cover:

  - ``tests/test_doc_claims.py`` locks numerical claims (provider count,
    rule-range high IDs, comparison-matrix per-cell counts).
  - ``tests/test_rule_framework.py`` locks that every rule's id + title
    appears in the corresponding provider doc.

Neither catches changes to a rule's ``recommendation`` / ``docs_note``,
or to a standard's prose, or to formatting. This test does, by running
each generator in ``--check`` mode and asserting exit 0. A failure
maps 1:1 to "re-run the named generator and commit the result".

The four ``--check`` invocations are uniform: same script per
generator, same expected exit. Subprocess (over importing main())
keeps the test cheap-to-add and matches the precedent set by
``tests/test_attack_chains_doc.py``.

Additional structural guards:

  - mkdocs nav ↔ files on disk (orphan nav entries, unreachable pages)
  - provider-doc generator coverage (SUPPORTED_PROVIDERS completeness)
  - design-tokens CSS mirror drift (committed copy vs canonical source)
  - provider-stats hook coverage (every provider with rules has an entry)
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent


# (script_path, fix_command_hint) — the hint is shown verbatim in the
# failure message so the contributor doesn't have to crack the test
# open to learn what to re-run.
_GENERATORS: list[tuple[str, str]] = [
    ("scripts/gen_provider_docs.py",
     "python scripts/gen_provider_docs.py"),
    ("scripts/gen_standards_docs.py",
     "python scripts/gen_standards_docs.py"),
    ("scripts/gen_attack_chains_doc.py",
     "python scripts/gen_attack_chains_doc.py"),
    ("scripts/link_standards_check_ids.py",
     "python scripts/link_standards_check_ids.py"),
]


@pytest.mark.parametrize(
    "script,fix_hint",
    _GENERATORS,
    ids=[Path(s).stem for s, _ in _GENERATORS],
)
def test_generated_doc_in_sync(script: str, fix_hint: str) -> None:
    """Run the generator with ``--check`` and require exit 0.

    Each generator's ``--check`` mode renders its targets in memory
    and compares against the on-disk file, exiting 1 (with a helpful
    line on stderr) when any byte differs. A failure here means a
    rule's prose, a standard's mapping, or a chain's metadata moved
    in source code without the matching doc being regenerated.
    """
    result = subprocess.run(
        [sys.executable, script, "--check"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"{script}: generated docs out of sync. "
        f"Re-run `{fix_hint}` and commit the result.\n"
        f"--- stdout ---\n{result.stdout}"
        f"--- stderr ---\n{result.stderr}"
    )


# ──────────────────────────────────────────────────────────────────────
# Non-circular guard for the standards docs
# ──────────────────────────────────────────────────────────────────────
#
# ``test_generated_doc_in_sync`` above re-runs the generator and diffs
# its output against the on-disk doc, so a bug inside the generator
# matches both sides and the drift test stays green. The provider-doc
# side has ``test_rule_framework.py::test_generated_doc_references_every_rule``
# as a non-circular guard (it asserts each rule's id + title appears
# in the rendered output independently of the generator). This block
# is the equivalent guard for the standards docs.


def _registered_standards():
    """Return every Standard registered in the live package."""
    from pipeline_check.core.standards import resolve
    return resolve()


@pytest.mark.parametrize(
    "standard",
    _registered_standards(),
    ids=lambda s: s.name,
)
def test_standards_doc_references_every_control(standard) -> None:
    """Every control id (and title) in the live registry must appear
    verbatim in the rendered ``docs/standards/<name>.md``.

    Bypasses the generator entirely: reads the doc straight off disk
    and ``in``-checks each ``control_id`` + ``control_title``. If the
    standards registry grows a control, this test reds without
    re-running the generator, breaking the circularity that
    ``test_generated_doc_in_sync`` carries on its own.
    """
    doc_path = REPO / "docs" / "standards" / f"{standard.name}.md"
    assert doc_path.exists(), (
        f"{doc_path.relative_to(REPO)} missing — re-run "
        f"`python scripts/gen_standards_docs.py {standard.name}` "
        f"to generate it."
    )
    doc = doc_path.read_text(encoding="utf-8")
    for ctrl_id, ctrl_title in standard.controls.items():
        assert ctrl_id in doc, (
            f"control {ctrl_id} missing from "
            f"{doc_path.relative_to(REPO)} — did you regenerate the "
            f"standards docs after editing the registry?"
        )
        if ctrl_title:
            assert ctrl_title in doc, (
                f"control {ctrl_id}'s title is out of sync with the "
                f"generated doc. Regenerate with "
                f"gen_standards_docs.py."
            )


# ──────────────────────────────────────────────────────────────────────
# _PROVIDER_PACKAGES coverage guard
# ──────────────────────────────────────────────────────────────────────
#
# ``gen_standards_docs.py`` carries a hand-curated ``_PROVIDER_PACKAGES``
# tuple that enumerates which provider rule packages feed the standards-
# doc rendering. A provider that adds a ``rules/`` package on disk but
# isn't appended here silently disappears from the standards docs:
# nothing crashes, the script still renders, the existing drift guards
# still pass, but the new provider's per-rule prose just doesn't appear.
# That's exactly the bug 8766da7 fixed (cloudformation / terraform /
# npm / pypi were missing).
#
# This guard walks ``pipeline_check/core/checks/<provider>/rules/`` and
# asserts each one has a matching entry in ``_PROVIDER_PACKAGES``. The
# import side-loads the script module without executing main(), so the
# tuple is read directly.


def _provider_packages_from_script() -> set[str]:
    """Return the set of package FQNs registered in ``_PROVIDER_PACKAGES``.

    Extracts via regex rather than importing the module, since
    ``gen_standards_docs.py`` defines a ``@dataclass`` at import time
    and loading it under a synthetic module name via
    ``importlib.util.spec_from_file_location`` confuses
    ``dataclasses.dataclass`` (it looks up the class's module in
    ``sys.modules`` and doesn't find it). The regex is anchored on
    the unique ``pipeline_check.core.checks.<X>.rules`` shape so it
    can't pick up unrelated strings.
    """
    import re

    text = (REPO / "scripts" / "gen_standards_docs.py").read_text(
        encoding="utf-8",
    )
    pattern = re.compile(
        r'"(pipeline_check\.core\.checks\.[A-Za-z_]+\.rules)"',
    )
    return set(pattern.findall(text))


def _provider_packages_on_disk() -> set[str]:
    """Return every package FQN that ships a ``rules/`` subdirectory."""
    checks_root = REPO / "pipeline_check" / "core" / "checks"
    found: set[str] = set()
    for rules_dir in checks_root.glob("*/rules"):
        if not rules_dir.is_dir():
            continue
        # Skip if the directory contains no rule modules (only ``__init__``
        # plus underscore-prefixed helpers).
        rule_files = [
            p for p in rules_dir.glob("*.py")
            if p.stem != "__init__" and not p.stem.startswith("_")
        ]
        if not rule_files:
            continue
        provider = rules_dir.parent.name
        found.add(f"pipeline_check.core.checks.{provider}.rules")
    return found


def test_gen_standards_docs_covers_every_provider_with_rules() -> None:
    """Every provider that ships a ``rules/`` package must appear in
    ``gen_standards_docs.py:_PROVIDER_PACKAGES``.

    Otherwise the provider's rule-based check modules silently drop
    out of the standards-doc rendering — the script still renders
    cleanly, the drift guard above still passes, but the per-rule
    prose simply doesn't appear. 8766da7 fixed exactly this gap for
    cloudformation / terraform / npm / pypi.
    """
    registered = _provider_packages_from_script()
    on_disk = _provider_packages_on_disk()
    missing = sorted(on_disk - registered)
    assert not missing, (
        "Provider(s) ship a rules/ package but aren't in "
        "scripts/gen_standards_docs.py:_PROVIDER_PACKAGES, so their "
        "rule-based check modules won't surface in the standards "
        f"docs: {missing}. Append the (slug, pkg_fqn, title) tuple "
        "for each missing provider."
    )


# ──────────────────────────────────────────────────────────────────────
# Provider-doc generator coverage guard
# ──────────────────────────────────────────────────────────────────────
#
# Parallel to the standards-side ``_PROVIDER_PACKAGES`` guard above.
# ``gen_provider_docs.py`` has a hand-curated ``SUPPORTED_PROVIDERS``
# dict. A provider that ships a ``rules/`` directory but isn't listed
# there silently gets no provider reference page. No crash, no diff,
# no test failure — the page just doesn't exist and the docs site has
# a dead link (or no link at all).


def _supported_provider_slugs_from_script() -> set[str]:
    """Return the set of provider slugs registered in
    ``gen_provider_docs.py::SUPPORTED_PROVIDERS``."""
    text = (REPO / "scripts" / "gen_provider_docs.py").read_text(
        encoding="utf-8",
    )
    pattern = re.compile(
        r'"(pipeline_check\.core\.checks\.([A-Za-z_]+)\.rules)"',
    )
    return {m.group(2) for m in pattern.finditer(text)}


def test_gen_provider_docs_covers_every_provider_with_rules() -> None:
    """Every provider that ships a ``rules/`` package must appear in
    ``gen_provider_docs.py:SUPPORTED_PROVIDERS``.

    Otherwise no provider reference page is generated and the docs
    site either has a dead nav link or silently omits the provider.
    """
    on_disk = {
        pkg.split(".")[-2]
        for pkg in _provider_packages_on_disk()
    }
    registered = _supported_provider_slugs_from_script()
    missing = sorted(on_disk - registered)
    assert not missing, (
        "Provider(s) ship a rules/ package but aren't in "
        "scripts/gen_provider_docs.py:SUPPORTED_PROVIDERS, so no "
        f"provider reference page is generated: {missing}. Add the "
        "provider entry to SUPPORTED_PROVIDERS."
    )


# ──────────────────────────────────────────────────────────────────────
# mkdocs.yml nav ↔ files on disk
# ──────────────────────────────────────────────────────────────────────
#
# A nav entry that references a nonexistent file causes a build
# warning (Material theme) or a broken link. A doc file that exists
# but isn't in the nav is unreachable from the site chrome. Both are
# drift classes worth catching in CI.


def _extract_nav_paths(nav: list | dict | str, acc: list[str] | None = None) -> list[str]:
    """Recursively extract every ``.md`` path from the mkdocs nav tree."""
    if acc is None:
        acc = []
    if isinstance(nav, str):
        if nav.endswith(".md"):
            acc.append(nav)
    elif isinstance(nav, dict):
        for v in nav.values():
            _extract_nav_paths(v, acc)
    elif isinstance(nav, list):
        for item in nav:
            _extract_nav_paths(item, acc)
    return acc


class _PermissiveLoader(yaml.SafeLoader):
    """SafeLoader that treats ``!!python/name:`` and other unknown tags
    as plain strings instead of raising ConstructorError. mkdocs.yml
    uses ``!!python/name:`` for emoji / superfences extensions; we
    only need the ``nav:`` key, not the Python object references."""


_PermissiveLoader.add_multi_constructor(
    "tag:yaml.org,2002:python/",
    lambda loader, suffix, node: loader.construct_scalar(node),
)


def _load_nav() -> list[str]:
    """Parse mkdocs.yml and return every .md path from the nav tree."""
    mkdocs_path = REPO / "mkdocs.yml"
    config = yaml.load(
        mkdocs_path.read_text(encoding="utf-8"),
        Loader=_PermissiveLoader,
    )
    return _extract_nav_paths(config.get("nav", []))


def test_mkdocs_nav_references_existing_files() -> None:
    """Every .md path in the mkdocs.yml nav must exist under docs/.

    An orphan nav entry produces a broken link on the live site (or a
    build warning that scrolls past unnoticed in CI output).
    """
    nav_paths = _load_nav()
    assert nav_paths, "mkdocs.yml nav is empty or unparseable"
    missing = [
        p for p in nav_paths
        if not (REPO / "docs" / p).is_file()
    ]
    assert not missing, (
        "mkdocs.yml nav references files that don't exist under "
        f"docs/: {missing}"
    )


def test_every_provider_doc_in_mkdocs_nav() -> None:
    """Every ``docs/providers/<name>.md`` must appear in the mkdocs nav.

    A generated provider doc that isn't wired into the nav is
    unreachable from the site chrome — it exists on disk but readers
    can't navigate to it.
    """
    nav_paths = set(_load_nav())
    provider_docs = {
        f"providers/{p.name}"
        for p in (REPO / "docs" / "providers").iterdir()
        if p.suffix == ".md"
    }
    missing = sorted(provider_docs - nav_paths)
    assert not missing, (
        "Provider docs exist on disk but aren't in mkdocs.yml nav: "
        f"{missing}. Add them to the Coverage > Providers section."
    )


def test_every_standards_doc_in_mkdocs_nav() -> None:
    """Every ``docs/standards/<name>.md`` must appear in the mkdocs nav.

    Same guard as provider docs: a generated standards page that
    exists on disk but isn't in the nav is invisible to readers.
    """
    nav_paths = set(_load_nav())
    standards_docs = {
        f"standards/{p.name}"
        for p in (REPO / "docs" / "standards").iterdir()
        if p.suffix == ".md"
    }
    missing = sorted(standards_docs - nav_paths)
    assert not missing, (
        "Standards docs exist on disk but aren't in mkdocs.yml nav: "
        f"{missing}. Add them to the Coverage > Standards section."
    )


# ──────────────────────────────────────────────────────────────────────
# Design-tokens CSS mirror drift
# ──────────────────────────────────────────────────────────────────────
#
# ``hooks/mkdocs_design_tokens.py`` copies
# ``pipeline_check/core/_design_tokens.css`` into
# ``docs/stylesheets/_design_tokens.css`` at build time. The committed
# mirror must match the source so CI catches edits that skip the
# build step.

_DESIGN_TOKEN_HEADER = (
    "/* DO NOT EDIT. Mirrored from pipeline_check/core/_design_tokens.css\n"
    "   by hooks/mkdocs_design_tokens.py. Edit the package file and\n"
    "   re-run ``mkdocs build`` (or rely on the docs CI to refresh). */\n"
)


def test_design_tokens_css_mirror_in_sync() -> None:
    """The committed ``docs/stylesheets/_design_tokens.css`` must be
    the canonical ``pipeline_check/core/_design_tokens.css`` prefixed
    with the DO-NOT-EDIT header.

    Catches the case where someone edits the package source but
    doesn't run ``mkdocs build`` to refresh the mirror.
    """
    src = REPO / "pipeline_check" / "core" / "_design_tokens.css"
    dst = REPO / "docs" / "stylesheets" / "_design_tokens.css"
    if not src.is_file():
        pytest.skip("_design_tokens.css not present")
    if not dst.is_file():
        pytest.fail(
            "docs/stylesheets/_design_tokens.css missing — run "
            "`mkdocs build` or `python -c "
            '"import hooks.mkdocs_design_tokens"` to create it.'
        )
    want = _DESIGN_TOKEN_HEADER + src.read_text(encoding="utf-8")
    have = dst.read_text(encoding="utf-8")
    assert want == have, (
        "docs/stylesheets/_design_tokens.css is out of sync with "
        "pipeline_check/core/_design_tokens.css. Run `mkdocs build` "
        "to refresh the mirror."
    )


# ──────────────────────────────────────────────────────────────────────
# Provider-stats hook coverage
# ──────────────────────────────────────────────────────────────────────
#
# ``hooks/mkdocs_provider_stats.py`` builds an ``_INDEX`` at import
# time. Every provider directory that ships rule files must have an
# entry so the home-page tile tokens resolve to a label. Without an
# entry the token passes through unrendered and the live page shows
# ``{{ providers.<slug>.checks }}`` verbatim.


def test_provider_stats_hook_covers_every_provider_with_rules() -> None:
    """The hook's ``_INDEX`` must have an entry for every provider
    that has rule files on disk."""
    sys.path.insert(0, str(REPO / "hooks"))
    try:
        from mkdocs_provider_stats import _INDEX
    finally:
        sys.path.pop(0)

    checks_root = REPO / "pipeline_check" / "core" / "checks"
    on_disk: set[str] = set()
    for prov_dir in checks_root.iterdir():
        if not prov_dir.is_dir() or prov_dir.name.startswith("_"):
            continue
        rules_dir = prov_dir / "rules"
        if not rules_dir.is_dir():
            continue
        rule_files = [
            p for p in rules_dir.glob("*.py")
            if p.stem != "__init__" and not p.stem.startswith("_")
        ]
        if rule_files:
            on_disk.add(prov_dir.name)

    missing = sorted(on_disk - set(_INDEX.keys()))
    assert not missing, (
        "Provider(s) ship rule files but have no entry in "
        "hooks/mkdocs_provider_stats.py _INDEX (via _build_index or "
        f"_CLASS_BASED_LABELS): {missing}. The home-page tile token "
        "will render as literal {{ providers.<slug>.checks }}."
    )


# ──────────────────────────────────────────────────────────────────────
# Version consistency
# ──────────────────────────────────────────────────────────────────────
#
# The package version is declared in two places:
#   - ``pyproject.toml``  (``[project] version``)
#   - ``pipeline_check/__init__.py``  (``__version__``)
#
# The release script bumps both, but a manual edit to one file without
# the other produces a mismatch: PyPI sees one version, ``--version``
# prints another, and the docs site (which reads from pyproject.toml
# via the mkdocs hook) shows a third.


def test_version_in_pyproject_matches_init() -> None:
    """``pyproject.toml [project] version`` must equal
    ``pipeline_check.__version__``.
    """
    import tomllib
    with (REPO / "pyproject.toml").open("rb") as fh:
        pyproject_version = tomllib.load(fh)["project"]["version"]

    from pipeline_check import __version__

    assert pyproject_version == __version__, (
        f"Version mismatch: pyproject.toml says {pyproject_version!r}, "
        f"pipeline_check.__version__ says {__version__!r}. Bump both "
        "in the same commit."
    )


def test_mkdocs_version_hook_reads_version() -> None:
    """``hooks/mkdocs_version.py`` must read a non-fallback version
    from ``pyproject.toml``.

    The hook's fallback is ``"0.0.0"``, which silently activates when
    ``pyproject.toml`` is malformed. If readers see "0.0.0" on the
    docs site, the hook is broken.
    """
    sys.path.insert(0, str(REPO / "hooks"))
    try:
        from mkdocs_version import _VERSION
    finally:
        sys.path.pop(0)

    assert _VERSION != "0.0.0", (
        "mkdocs_version.py fell back to '0.0.0' — check that "
        "pyproject.toml has a [project] version = '...' entry."
    )
    from pipeline_check import __version__
    assert _VERSION == __version__, (
        f"mkdocs_version.py reads {_VERSION!r} from pyproject.toml "
        f"but pipeline_check.__version__ is {__version__!r}."
    )


# ──────────────────────────────────────────────────────────────────────
# docs/config.md key coverage
# ──────────────────────────────────────────────────────────────────────
#
# ``docs/config.md`` documents the config-file schema with TOML and
# YAML examples. The accepted keys are defined by ``_TOPLEVEL_KEYS``
# and ``_GATE_KEYS`` in ``pipeline_check/core/config.py``. Adding a
# key to the code without mentioning it in the doc means users can't
# discover the key from the docs page.


def test_config_md_mentions_every_gate_key() -> None:
    """Every key in ``_GATE_KEYS`` must appear verbatim in
    ``docs/config.md``.

    Gate keys are the most user-facing config keys (fail_on, min_grade,
    baseline, etc.) — if the docs don't show them, users won't know
    they exist.
    """
    from pipeline_check.core.config import _GATE_KEYS

    text = (REPO / "docs" / "config.md").read_text(encoding="utf-8")
    missing = sorted(k for k in _GATE_KEYS if k not in text)
    assert not missing, (
        "Gate key(s) accepted by the config parser but not mentioned "
        f"in docs/config.md: {missing}. Add them to the TOML/YAML "
        "examples or the prose."
    )
