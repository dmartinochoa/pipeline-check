"""Focused tests for the pipeline-poisoning (CICD-SEC-4) check family.

The broader fixture sweep (``test_workflow_fixtures.py``) and the
per-check real-examples sweep (``test_per_check_real_examples.py``)
cover the happy paths. This module exercises edge cases each check
can subtly get wrong — e.g. the ``runs-on`` dict form, the
``release.body`` context the regex was just extended to catch, and
the verification-step recognition list for GHA-009.

Snippet bodies live on disk under
``tests/fixtures/scenarios/github/``. Two extension conventions:

  ``*.yml``           — load and use as-is.
  ``*.template.yml``  — load + ``str.format(**vars)`` interpolation.

The template form lets parametrized tests keep a single base
workflow on disk and inject the varying expression / step body at
test time.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_check.core.checks.github.base import GitHubContext
from pipeline_check.core.checks.github.workflows import WorkflowChecks


SCENARIO_DIR = Path(__file__).parent / "fixtures" / "scenarios" / "github"


def _scenario(name: str, **fmt_vars: str) -> str:
    """Load ``<name>`` from the scenarios directory.

    Pass ``fmt_vars`` for ``*.template.yml`` files. The placeholder
    syntax is ``__NAME__`` (not Python's ``{name}``) so the templates
    can contain literal YAML/GitHub-expression braces — ``permissions:
    { contents: read }`` and ``${{ … }}`` — without escaping.
    """
    path = SCENARIO_DIR / name
    text = path.read_text(encoding="utf-8")
    if name.endswith(".template.yml"):
        for k, v in fmt_vars.items():
            text = text.replace(f"__{k.upper()}__", v)
    return text


def _scan(text: str, tmp_path: Path):
    p = tmp_path / "wf.yml"
    p.write_text(text, encoding="utf-8")
    ctx = GitHubContext.from_path(p)
    return {f.check_id: f.passed for f in WorkflowChecks(ctx).run()}


# ────────────────────────────────────────────────────────────────────────
# GHA-003 — expanded untrusted-context catalogue
# ────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("expr", [
    # Fields newly added in the expansion round.
    "${{ github.event.release.body }}",
    "${{ github.event.release.tag_name }}",
    "${{ github.event.deployment.payload.target_env }}",
    "${{ github.event.workflow_run.head_commit.message }}",
    "${{ github.event.workflow_run.display_title }}",
    # Derived shortcuts — pusher controls these via ref naming.
    "${{ github.head_ref }}",
    "${{ github.ref_name }}",
    # workflow_dispatch / workflow_call inputs — caller-controlled.
    "${{ inputs.target_branch }}",
    # Pre-existing high-signal fields, kept as a regression net.
    "${{ github.event.pull_request.title }}",
    "${{ github.event.head_commit.message }}",
])
def test_gha003_flags_expanded_untrusted_contexts(expr, tmp_path):
    text = _scenario("gha003-untrusted-context.template.yml", EXPR=expr)
    results = _scan(text, tmp_path)
    assert results["GHA-003"] is False, (
        f"GHA-003 did not catch interpolation of {expr!r}"
    )


def test_gha003_does_not_flag_safe_contexts(tmp_path):
    """Sanity: ``github.repository``, ``github.run_id`` etc. are NOT
    attacker-controllable and must NOT trigger GHA-003."""
    results = _scan(_scenario("gha003-safe-contexts.yml"), tmp_path)
    assert results["GHA-003"] is True


# ────────────────────────────────────────────────────────────────────────
# GHA-009 — workflow_run artifact poisoning
# ────────────────────────────────────────────────────────────────────────


def test_gha009_passes_when_no_workflow_run_trigger(tmp_path):
    text = _scenario("gha009-no-workflow-run-trigger.yml")
    assert _scan(text, tmp_path)["GHA-009"] is True


def test_gha009_passes_when_no_artifact_download(tmp_path):
    """workflow_run trigger present but the workflow doesn't ingest
    an upstream artifact — there's nothing to poison."""
    text = _scenario("gha009-no-artifact-download.yml")
    assert _scan(text, tmp_path)["GHA-009"] is True


@pytest.mark.parametrize("verify_step", [
    "cosign verify-attestation --type slsaprovenance ./build-output",
    "gh attestation verify --owner my-org ./build-output",
    "sha256sum --check checksums.txt",
    "sha256sum -c checksums.txt",
])
def test_gha009_passes_with_a_verification_step(verify_step, tmp_path):
    text = _scenario("gha009-with-verification.template.yml", VERIFY_STEP=verify_step)
    assert _scan(text, tmp_path)["GHA-009"] is True


def test_gha009_recognises_gh_run_download(tmp_path):
    """``gh run download`` is the CLI equivalent of
    actions/download-artifact and must trigger the same check."""
    text = _scenario("gha009-gh-run-download.yml")
    assert _scan(text, tmp_path)["GHA-009"] is False


# ────────────────────────────────────────────────────────────────────────
# GHA-010 — local action on untrusted trigger
# ────────────────────────────────────────────────────────────────────────


def test_gha010_passes_on_pull_request_trigger(tmp_path):
    """``pull_request`` (NOT ``pull_request_target``) runs with a
    read-only token from the fork's perspective — local actions are
    safer there. GHA-010 should NOT flag this case."""
    text = _scenario("gha010-pull-request-trigger.yml")
    assert _scan(text, tmp_path)["GHA-010"] is True


def test_gha010_flags_workflow_run_trigger(tmp_path):
    """workflow_run is the OTHER untrusted trigger — same risk class."""
    text = _scenario("gha010-workflow-run-trigger.yml")
    assert _scan(text, tmp_path)["GHA-010"] is False


def test_gha010_flags_parent_path_traversal(tmp_path):
    """``uses: ../action`` is just as bad — a relative path that
    escapes the workspace can still resolve into a PR-controlled
    location depending on checkout depth."""
    text = _scenario("gha010-parent-path-traversal.yml")
    assert _scan(text, tmp_path)["GHA-010"] is False


# ────────────────────────────────────────────────────────────────────────
# GHA-011 — cache key from attacker input
# ────────────────────────────────────────────────────────────────────────


def test_gha011_passes_with_safe_key_components(tmp_path):
    """``runner.os`` + ``hashFiles(...)`` is the canonical safe
    cache key. Must NOT trigger the check."""
    text = _scenario("gha011-safe-key.yml")
    assert _scan(text, tmp_path)["GHA-011"] is True


def test_gha011_flags_restore_keys_too(tmp_path):
    """``restore-keys`` falls through on cache miss; tainting it is
    just as exploitable as tainting the primary ``key``."""
    text = _scenario("gha011-restore-keys-tainted.yml")
    assert _scan(text, tmp_path)["GHA-011"] is False


def test_gha011_passes_when_no_cache_step(tmp_path):
    text = _scenario("gha011-no-cache-step.yml")
    assert _scan(text, tmp_path)["GHA-011"] is True


# ────────────────────────────────────────────────────────────────────────
# GHA-012 — self-hosted ephemeral marker
# ────────────────────────────────────────────────────────────────────────


def test_gha012_passes_on_github_hosted_runner(tmp_path):
    text = _scenario("gha012-github-hosted.yml")
    assert _scan(text, tmp_path)["GHA-012"] is True


def test_gha012_flags_string_self_hosted_form(tmp_path):
    text = _scenario("gha012-string-self-hosted.yml")
    assert _scan(text, tmp_path)["GHA-012"] is False


def test_gha012_passes_on_list_form_with_ephemeral(tmp_path):
    text = _scenario("gha012-list-with-ephemeral.yml")
    assert _scan(text, tmp_path)["GHA-012"] is True


def test_gha012_handles_runs_on_dict_form(tmp_path):
    """The ``runs-on: { group: foo, labels: [bar, baz] }`` shape — a
    real GitHub feature — must be parsed correctly. Without ephemeral
    it should fail; with it, it should pass."""
    unsafe = _scenario("gha012-dict-form-unsafe.yml")
    safe = _scenario("gha012-dict-form-safe.yml")
    assert _scan(unsafe, tmp_path)["GHA-012"] is False
    assert _scan(safe, tmp_path)["GHA-012"] is True
