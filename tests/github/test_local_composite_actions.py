"""Tests for local composite-action discovery.

The discovery code walks loaded workflows for ``uses: ./path``
references, resolves ``<repo_root>/<path>/action.yml`` on disk,
synthesizes the composite body as a ``__composite__`` job, and
appends it to the context's workflow list. The same GHA rule pack
then runs against the synthesized body. Mirrors the remote-composite
synthesis in :mod:`pipeline_check.core.checks.github.resolver`, but
runs on the disk-only default path (no ``--resolve-remote``).

Closes cicd-goat scenario 18 (composite action ``${{ inputs.* }}``
injection).
"""
from __future__ import annotations

import textwrap
from pathlib import Path

from pipeline_check.core.checks.github.base import GitHubContext
from pipeline_check.core.checks.github.local_actions import (
    _DEFAULT_MAX_DEPTH,
    _HARD_DEPTH_CEILING,
    discover_local_composite_actions,
    infer_repo_root,
)
from pipeline_check.core.checks.github.workflows import WorkflowChecks


def _seed_layout(
    root: Path,
    workflow_body: str,
    actions: dict[str, str] | None = None,
) -> Path:
    """Materialize a ``<root>/.github/workflows/`` layout on disk.

    *actions* maps repo-relative directory paths to ``action.yml``
    bodies. Each entry creates ``<root>/<dir>/action.yml`` with the
    given content.
    """
    workflows_dir = root / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    (workflows_dir / "main.yml").write_text(
        textwrap.dedent(workflow_body), encoding="utf-8",
    )
    if actions:
        for rel, body in actions.items():
            action_dir = root / rel
            action_dir.mkdir(parents=True, exist_ok=True)
            (action_dir / "action.yml").write_text(
                textwrap.dedent(body), encoding="utf-8",
            )
    return workflows_dir


def test_scenario18_composite_input_injection_fires_gha003(tmp_path: Path) -> None:
    """The canonical cicd-goat scenario 18 shape fires GHA-003."""
    _seed_layout(
        tmp_path,
        workflow_body="""
            name: triage
            on:
              issue_comment:
                types: [created]
            jobs:
              triage:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
                  - uses: ./actions/triage-notifier
                    with:
                      message: ${{ github.event.comment.body }}
        """,
        actions={
            "actions/triage-notifier": """
                name: 'Triage notifier (vulnerable composite)'
                description: 'Demonstrates composite-action input injection.'
                inputs:
                  message:
                    description: 'Untrusted message body to log'
                    required: true
                runs:
                  using: 'composite'
                  steps:
                    - name: Log message
                      shell: bash
                      run: |
                        echo "TRIAGE: ${{ inputs.message }}"
            """,
        },
    )
    ctx = GitHubContext.from_path(tmp_path / ".github" / "workflows")
    finding_ids = {
        f.check_id for f in WorkflowChecks(ctx).run()
    }
    assert "GHA-003" in finding_ids, (
        "GHA-003 should fire on the composite step's "
        "${{ inputs.message }} -> run: interpolation"
    )


def test_composite_action_appended_to_ctx_workflows(tmp_path: Path) -> None:
    """The synthesized composite body lands in ctx.workflows."""
    _seed_layout(
        tmp_path,
        workflow_body="""
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: ./actions/setup
        """,
        actions={
            "actions/setup": """
                name: Setup
                runs:
                  using: composite
                  steps:
                    - shell: bash
                      run: echo hi
            """,
        },
    )
    ctx = GitHubContext.from_path(tmp_path / ".github" / "workflows")
    composite_workflows = [
        wf for wf in ctx.workflows if wf.source_ref is not None
    ]
    assert len(composite_workflows) == 1
    composite = composite_workflows[0]
    assert composite.source_ref == "local-composite:actions/setup/action.yml"
    assert "__composite__" in composite.data["jobs"]
    assert any(
        "[gha-local-actions] resolved 1 local composite" in w
        for w in ctx.warnings
    )


def test_non_composite_action_skipped(tmp_path: Path) -> None:
    """``runs.using: node20`` and ``docker`` actions are counted but not scanned."""
    _seed_layout(
        tmp_path,
        workflow_body="""
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: ./actions/js-action
                  - uses: ./actions/docker-action
        """,
        actions={
            "actions/js-action": """
                name: JS Action
                runs:
                  using: node20
                  main: index.js
            """,
            "actions/docker-action": """
                name: Docker Action
                runs:
                  using: docker
                  image: Dockerfile
            """,
        },
    )
    ctx = GitHubContext.from_path(tmp_path / ".github" / "workflows")
    composites = [wf for wf in ctx.workflows if wf.source_ref is not None]
    assert composites == []
    assert any(
        "skipped 2 non-composite local action(s)" in w
        for w in ctx.warnings
    )


def test_missing_action_yml_warns_but_continues(tmp_path: Path) -> None:
    """A ``./missing-action`` reference produces a warning, not a crash."""
    _seed_layout(
        tmp_path,
        workflow_body="""
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: ./missing-action
        """,
    )
    ctx = GitHubContext.from_path(tmp_path / ".github" / "workflows")
    assert any(
        "could not resolve local action ./missing-action" in w
        for w in ctx.warnings
    )
    # Scan still produces the original workflow.
    main_workflows = [
        wf for wf in ctx.workflows if wf.source_ref is None
    ]
    assert len(main_workflows) == 1


def test_path_traversal_rejected(tmp_path: Path) -> None:
    """``./../../etc/passwd``-shaped refs don't escape the repo root."""
    workflows_dir = _seed_layout(
        tmp_path,
        workflow_body="""
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: ./../escaped-action
        """,
    )
    # Create what would be the "escaped" target outside the repo root.
    escaped = tmp_path.parent / "escaped-action"
    escaped.mkdir(exist_ok=True)
    (escaped / "action.yml").write_text(
        "name: x\nruns:\n  using: composite\n  steps: []\n",
        encoding="utf-8",
    )
    try:
        ctx = GitHubContext.from_path(workflows_dir)
        composites = [
            wf for wf in ctx.workflows if wf.source_ref is not None
        ]
        # The traversal must not produce a synthesized composite.
        assert composites == []
    finally:
        (escaped / "action.yml").unlink()
        escaped.rmdir()


def test_composite_of_composite_recurses_bounded(tmp_path: Path) -> None:
    """A composite that calls another composite resolves both."""
    _seed_layout(
        tmp_path,
        workflow_body="""
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: ./actions/outer
        """,
        actions={
            "actions/outer": """
                name: Outer
                runs:
                  using: composite
                  steps:
                    - uses: ./actions/inner
            """,
            "actions/inner": """
                name: Inner
                runs:
                  using: composite
                  steps:
                    - shell: bash
                      run: echo inner
            """,
        },
    )
    ctx = GitHubContext.from_path(tmp_path / ".github" / "workflows")
    refs = {wf.source_ref for wf in ctx.workflows if wf.source_ref is not None}
    assert refs == {
        "local-composite:actions/outer/action.yml",
        "local-composite:actions/inner/action.yml",
    }


def test_dedup_across_multiple_callers(tmp_path: Path) -> None:
    """A composite used by two workflows synthesizes once."""
    root = tmp_path
    workflows_dir = root / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    for name in ("a.yml", "b.yml"):
        (workflows_dir / name).write_text(textwrap.dedent("""
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: ./actions/shared
        """), encoding="utf-8")
    action_dir = root / "actions" / "shared"
    action_dir.mkdir(parents=True)
    (action_dir / "action.yml").write_text(textwrap.dedent("""
        name: Shared
        runs:
          using: composite
          steps:
            - shell: bash
              run: echo shared
    """), encoding="utf-8")

    ctx = GitHubContext.from_path(workflows_dir)
    composites = [wf for wf in ctx.workflows if wf.source_ref is not None]
    assert len(composites) == 1


def test_infer_repo_root_canonical_layout(tmp_path: Path) -> None:
    """``<root>/.github/workflows`` resolves to ``<root>``."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    assert infer_repo_root(workflows) == tmp_path.resolve()


def test_infer_repo_root_single_file(tmp_path: Path) -> None:
    """A single workflow file under the canonical layout resolves correctly."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    wf = workflows / "main.yml"
    wf.write_text("on: push\njobs: {}\n", encoding="utf-8")
    assert infer_repo_root(wf) == tmp_path.resolve()


def test_infer_repo_root_ad_hoc_layout(tmp_path: Path) -> None:
    """Non-canonical layouts fall back to the parent directory."""
    flat = tmp_path / "my-workflows"
    flat.mkdir()
    assert infer_repo_root(flat) == tmp_path.resolve()


def test_action_yaml_extension_supported(tmp_path: Path) -> None:
    """Both ``action.yml`` and ``action.yaml`` are recognized."""
    workflows_dir = _seed_layout(
        tmp_path,
        workflow_body="""
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: ./actions/yaml-extension
        """,
    )
    # Build action.yaml (not .yml) by hand.
    action_dir = tmp_path / "actions" / "yaml-extension"
    action_dir.mkdir(parents=True)
    (action_dir / "action.yaml").write_text(textwrap.dedent("""
        name: Yaml-Extension
        runs:
          using: composite
          steps:
            - shell: bash
              run: echo hi
    """), encoding="utf-8")
    ctx = GitHubContext.from_path(workflows_dir)
    composites = [wf for wf in ctx.workflows if wf.source_ref is not None]
    assert len(composites) == 1
    assert composites[0].source_ref == "local-composite:actions/yaml-extension/action.yaml"


def test_depth_cap_hard_ceiling() -> None:
    """The hard ceiling clamps absurdly large *max_depth* values."""
    out, warnings = discover_local_composite_actions(
        workflows=[], repo_root=Path("."), max_depth=10_000,
    )
    assert out == []
    assert warnings == []
    # Just verifies the call doesn't raise; the hard ceiling is internal.
    assert _HARD_DEPTH_CEILING >= _DEFAULT_MAX_DEPTH
