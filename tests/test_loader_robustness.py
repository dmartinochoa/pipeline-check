"""Standing robustness gate for the file loaders.

Two complementary harnesses:

1. **Fuzz / pathological-input** — a malformed or pathological *scanned
   input* (a repo/PR file the scanner parses at context-build time) must
   degrade to a skip-with-warning, never abort the whole scan with an
   unhandled exception. Context construction runs *before* the per-check
   guard, so a `RecursionError` / `MemoryError` that slips past a
   loader's `except yaml.YAMLError` / `except json.JSONDecodeError` /
   `except tomllib.TOMLDecodeError` would crash everything. This battery
   would fail the moment a loader reintroduces the narrow-except gap.

2. **Differential** — the same logical pipeline expressed in different
   valid syntaxes must yield the same finding, so a parser-shape quirk
   can't silently drop a rule.

The curated inputs are a deterministic battery of the shapes that
actually break loaders (deep nesting, alias bombs, non-UTF-8 bytes,
truncation, wrong top-level type, empty), backed by a Hypothesis
property-based pass that fuzzes the shared YAML loader with a wide,
shrinking sample (structured documents + arbitrary byte / text blobs) to
catch a crash class no one thought to curate. The generative pass runs
``derandomize=True`` so it stays reproducible and CI-stable while still
shrinking any failure to a minimal reproducer.
"""
from __future__ import annotations

import json

import hypothesis.strategies as st
import pytest
import yaml
from click.testing import CliRunner
from hypothesis import HealthCheck, given, settings

from pipeline_check.cli import scan
from pipeline_check.core.checks._yaml_files import load_yaml_files

# ── Pathological payloads ────────────────────────────────────────────────
# Deep enough to blow the recursion limit in any pure-Python parser (the
# default limit is 1000; every parser burns several frames per level).

_DEEP_YAML = "a:\n" + "".join("  " * i + "k:\n" for i in range(1, 600))
_DEEP_JSON = '{"a":' * 3000 + "1" + "}" * 3000
_DEEP_TOML = "x = " + "{ y = " * 1500 + "1" + " }" * 1500
_DEEP_XML = "<a>" * 6000 + "x" + "</a>" * 6000

# Non-UTF-8 bytes: every loader reads with ``encoding="utf-8"``; a loader
# that doesn't catch ``UnicodeDecodeError`` crashes the whole scan.
_NON_UTF8 = b"\xff\xfe\x00 not valid utf-8 \x80\x81"

# YAML alias bomb (the "billion laughs" shape): exponential expansion on
# parse. The loader must refuse it without exhausting memory.
_ALIAS_BOMB = (
    "a: &a [x, x, x, x, x, x, x, x, x]\n"
    "b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\n"
    "c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]\n"
    "d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]\n"
    "e: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d]\n"
)
_TRUNCATED_YAML = "a: [unterminated\n"
_WRONG_TYPE_YAML = "- just\n- a\n- sequence\n"
_EMPTY = ""


# ── 1a. Shared YAML loader battery (covers the 11 YAML providers) ────────

@pytest.mark.parametrize(
    "content",
    [_DEEP_YAML, _ALIAS_BOMB, _TRUNCATED_YAML, _WRONG_TYPE_YAML, _EMPTY],
    ids=["deep-nested", "alias-bomb", "truncated", "wrong-type", "empty"],
)
def test_load_yaml_files_degrades_on_pathological_text(tmp_path, content):
    p = tmp_path / "f.yml"
    p.write_text(content, encoding="utf-8")
    # Must return the (loaded, warnings, skipped) triple, never raise.
    loaded, warnings, skipped = load_yaml_files([p])
    assert isinstance(loaded, list)


def test_load_yaml_files_degrades_on_non_utf8_bytes(tmp_path):
    p = tmp_path / "f.yml"
    p.write_bytes(b"\xff\xfe\x00 not valid utf-8 \x80\x81")
    loaded, warnings, skipped = load_yaml_files([p])  # must not raise
    assert skipped == 1 and warnings


# ── 1b. Per-provider deep-nest, driven through the CLI ───────────────────
# A deeply-nested file in each format reaches the corresponding context
# loader (YAML via load_yaml_files, JSON via json.loads, TOML via
# tomllib). Pre-hardening, each raised RecursionError out of build_context
# and crashed the scan with a raw traceback. Now each must degrade: the
# scan completes with a clean exit code and no traceback.
#
# Each case: (provider, path_flag, relative_file, pass_dir, payload).
# pass_dir=True  → the flag points at the temp dir (provider searches it);
# pass_dir=False → the flag points directly at the file.
_CASES = [
    ("github", "--gha-path", "wf/w.yml", True, _DEEP_YAML),
    ("kubernetes", "--k8s-path", "m.yaml", False, _DEEP_YAML),
    ("gitlab", "--gitlab-path", ".gitlab-ci.yml", False, _DEEP_YAML),
    ("cloudformation", "--cfn-template", "t.json", False, _DEEP_JSON),
    ("terraform", "--tf-plan", "plan.json", False, _DEEP_JSON),
    ("oci", "--oci-manifest", "index.json", False, _DEEP_JSON),
    ("npm", "--npm-path", "package.json", True, _DEEP_JSON),
    ("composer", "--composer-path", "composer.json", True, _DEEP_JSON),
    ("cargo", "--cargo-path", "Cargo.toml", True, _DEEP_TOML),
    ("devenv", "--devenv-path", ".vscode/settings.json", True, _DEEP_JSON),
    # XML providers — a distinct parser (ElementTree) the YAML/JSON
    # battery doesn't exercise.
    ("maven", "--maven-path", "pom.xml", False, _DEEP_XML),
    ("nuget", "--nuget-path", "app.csproj", False, _DEEP_XML),
]


@pytest.mark.parametrize(
    "provider,flag,relfile,pass_dir,payload",
    _CASES,
    ids=[c[0] for c in _CASES],
)
def test_provider_loader_degrades_on_deeply_nested_input(
    tmp_path, provider, flag, relfile, pass_dir, payload,
):
    target = tmp_path / relfile
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(payload, encoding="utf-8")
    path_arg = str(tmp_path / relfile.split("/")[0]) if pass_dir else str(target)
    # github's --gha-path wants the workflows dir specifically.
    if provider == "github":
        path_arg = str(tmp_path / "wf")
    result = CliRunner().invoke(
        scan, ["--pipeline", provider, flag, path_arg, "--output", "json"],
    )
    # CliRunner captures an uncaught exception into ``result.exception``
    # rather than printing it, so that (not the text) is the crash signal.
    # A clean ``click.Exit`` is a SystemExit and is fine; a RecursionError
    # / MemoryError escaping the loader is not.
    exc = result.exception
    assert exc is None or isinstance(exc, SystemExit), (
        f"{provider} loader crashed on deeply-nested input: {exc!r}"
    )
    # 0 (clean/sub-critical), 1 (gate fail), 2 (scanner error) are all
    # controlled exits; what must not happen is an uncaught crash.
    assert result.exit_code in (0, 1, 2), result.output


# ── 1c. Per-provider non-UTF-8 bytes ─────────────────────────────────────
# The shared YAML loader's UnicodeDecodeError handling is covered above
# (``test_load_yaml_files_degrades_on_non_utf8_bytes``). These providers
# read their own files with a bespoke parser (ElementTree for the XML
# packs, hand-rolled line parsers for the rest), so each needs its own
# ``except UnicodeDecodeError`` — a gap here crashes the whole scan on a
# repo that simply ships a latin-1 manifest.
_NON_UTF8_CASES = [
    ("maven", "--maven-path", "pom.xml"),
    ("nuget", "--nuget-path", "app.csproj"),
    ("gomod", "--gomod-path", "go.mod"),
    ("rubygems", "--rubygems-path", "Gemfile"),
    ("pypi", "--pypi-path", "requirements.txt"),
    ("dockerfile", "--dockerfile-path", "Dockerfile"),
    ("modelfile", "--modelfile-path", "Modelfile"),
]


@pytest.mark.parametrize(
    "provider,flag,relfile",
    _NON_UTF8_CASES,
    ids=[c[0] for c in _NON_UTF8_CASES],
)
def test_provider_loader_degrades_on_non_utf8(
    tmp_path, provider, flag, relfile,
):
    target = tmp_path / relfile
    target.write_bytes(_NON_UTF8)
    result = CliRunner().invoke(
        scan, ["--pipeline", provider, flag, str(target), "--output", "json"],
    )
    exc = result.exception
    assert exc is None or isinstance(exc, SystemExit), (
        f"{provider} loader crashed on non-UTF-8 bytes: {exc!r}"
    )
    assert result.exit_code in (0, 1, 2), result.output


def test_maven_parse_pom_degrades_on_recursion_error(monkeypatch):
    # ``ET.fromstring`` is iterative, so deeply-nested XML doesn't recurse
    # in practice — but the loader must still treat a RecursionError /
    # MemoryError as a parse failure rather than let it escape and crash
    # the scan. Pin that defensively (the ``except`` was narrowed to
    # ``ET.ParseError`` only before this).
    from pipeline_check.core.checks.maven import base as maven_base

    def boom(_text):
        raise RecursionError("simulated deep tree")

    monkeypatch.setattr(maven_base.ET, "fromstring", boom)
    pom = maven_base._parse_pom("pom.xml", "<project/>")
    assert pom.parsed_ok is False


# ── 1d. Generative fuzz — Hypothesis property tests ──────────────────────
# Where the batteries above are hand-curated shapes, these throw a wide,
# shrinking sample at the shared YAML loader to catch a crash class no one
# thought to curate. Hypothesis generates structured documents and
# arbitrary byte / text blobs and shrinks any failure to a minimal
# reproducer. ``derandomize=True`` keeps the run reproducible and
# CI-stable (the same examples every run); ``deadline=None`` because the
# loader's recursion / anchor guards can be slow on a pathological
# generated input and a per-example deadline would flake.

# "Any YAML-dumpable Python object": scalars at the leaves, lists and
# string-keyed dicts as containers.
_yaml_objects = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(),
    lambda children: (
        st.lists(children, max_size=5)
        | st.dictionaries(st.text(max_size=20), children, max_size=5)
    ),
    max_leaves=30,
)

_FUZZ = settings(
    max_examples=200,
    deadline=None,
    derandomize=True,
    suppress_health_check=[HealthCheck.too_slow],
)


@pytest.fixture(scope="module")
def _fuzz_path(tmp_path_factory):
    # Module-scoped (not function-scoped) so it is safe to consume from a
    # ``@given`` test; reused across examples, which run sequentially
    # within one worker so the overwrite-then-read is race-free.
    return tmp_path_factory.mktemp("loader_fuzz") / "f.yml"


@_FUZZ
@given(obj=_yaml_objects)
def test_yaml_loader_never_raises_on_structured(_fuzz_path, obj):
    """Any YAML-dumpable object, serialized then reloaded, must return the
    (loaded, warnings, skipped) triple, never raise."""
    try:
        text = yaml.safe_dump(obj)
    except yaml.YAMLError:
        return  # un-dumpable object — not an input the scanner ever sees
    _fuzz_path.write_text(text, encoding="utf-8")
    loaded, _warnings, _skipped = load_yaml_files([_fuzz_path])
    assert isinstance(loaded, list)


@_FUZZ
@given(blob=st.binary(max_size=512))
def test_yaml_loader_never_raises_on_bytes(_fuzz_path, blob):
    """Arbitrary byte blobs (mostly invalid YAML / bad encoding) must
    degrade to a skip, never raise."""
    _fuzz_path.write_bytes(blob)
    loaded, _warnings, _skipped = load_yaml_files([_fuzz_path])
    assert isinstance(loaded, list)


@_FUZZ
@given(text=st.text())
def test_yaml_loader_never_raises_on_text(_fuzz_path, text):
    """Arbitrary valid-UTF-8 text (arbitrary YAML validity) must not raise
    out of the loader."""
    _fuzz_path.write_text(text, encoding="utf-8")
    loaded, _warnings, _skipped = load_yaml_files([_fuzz_path])
    assert isinstance(loaded, list)


# ── 2. Differential — the same trigger in different YAML shapes ──────────
# GitHub's ``on:`` block has several valid encodings. GHA-002 (pwn-request:
# pull_request_target + PR-head checkout) must fire for every one of them,
# or a parser-shape quirk silently disables the rule.

@pytest.mark.parametrize(
    "on_block",
    [
        "on: pull_request_target\n",
        "on: [pull_request_target]\n",
        "on:\n  pull_request_target:\n",
        "'on':\n  pull_request_target: {}\n",
    ],
    ids=["scalar", "flow-seq", "block-map", "quoted-key"],
)
def test_github_on_shape_variants_all_fire_gha002(tmp_path, on_block):
    wf = tmp_path / "wf"
    wf.mkdir()
    (wf / "w.yml").write_text(
        on_block
        + "jobs:\n"
        "  b:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        '          ref: "${{ github.event.pull_request.head.sha }}"\n'
        "      - run: ./build.sh\n"
    )
    result = CliRunner().invoke(
        scan, ["--pipeline", "github", "--gha-path", str(wf), "--output", "json"],
    )
    out = result.output
    payload = json.loads(out[out.find("{"):])
    ids = {f["check_id"] for f in payload["findings"]}
    assert "GHA-002" in ids, f"GHA-002 missed for shape: {on_block!r}"


# GHA-003 (script injection: an untrusted ``${{ github.event.* }}`` in a
# ``run:`` step) must fire whichever YAML scalar style encodes the same
# command. Literal / folded / inline / quoted all denote the same logical
# shell line, so a whitespace-sensitive matcher must not drop any of them.

_INJ = "echo ${{ github.event.issue.title }}"


@pytest.mark.parametrize(
    "run_block",
    [
        f"      - run: {_INJ}\n",
        f'      - run: "{_INJ}"\n',
        f"      - run: '{_INJ}'\n",
        f"      - run: |\n          {_INJ}\n",
        f"      - run: >\n          {_INJ}\n",
    ],
    ids=["inline", "dquoted", "squoted", "literal", "folded"],
)
def test_github_run_scalar_styles_all_fire_gha003(tmp_path, run_block):
    wf = tmp_path / "wf"
    wf.mkdir()
    (wf / "w.yml").write_text(
        "on: issue_comment\n"
        "jobs:\n"
        "  b:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        + run_block
    )
    result = CliRunner().invoke(
        scan, ["--pipeline", "github", "--gha-path", str(wf), "--output", "json"],
    )
    out = result.output
    payload = json.loads(out[out.find("{"):])
    ids = {f["check_id"] for f in payload["findings"] if not f.get("passed")}
    assert "GHA-003" in ids, f"GHA-003 missed for run style: {run_block!r}"


# GHA-008 (hardcoded credential) must fire whichever scalar style encodes
# the secret value. YAML normalizes the quote style away, but a block
# scalar appends a trailing newline, so the value-shape detector has to
# tolerate surrounding whitespace.

_SECRET = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


@pytest.mark.parametrize(
    "val_block",
    [
        f"  TOK: {_SECRET}\n",
        f'  TOK: "{_SECRET}"\n',
        f"  TOK: '{_SECRET}'\n",
        f"  TOK: |\n    {_SECRET}\n",
    ],
    ids=["plain", "dquoted", "squoted", "literal"],
)
def test_github_secret_scalar_styles_all_fire_gha008(tmp_path, val_block):
    wf = tmp_path / "wf"
    wf.mkdir()
    (wf / "w.yml").write_text(
        "on: push\n"
        "env:\n"
        + val_block
        + "jobs:\n"
        "  b:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    result = CliRunner().invoke(
        scan, ["--pipeline", "github", "--gha-path", str(wf), "--output", "json"],
    )
    out = result.output
    payload = json.loads(out[out.find("{"):])
    ids = {f["check_id"] for f in payload["findings"] if not f.get("passed")}
    assert "GHA-008" in ids, f"GHA-008 missed for value style: {val_block!r}"
