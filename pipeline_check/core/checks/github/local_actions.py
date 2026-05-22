"""Local composite-action discovery for the GitHub Actions provider.

Workflows reference local composite actions via ``uses: ./path/to/action``.
Each such reference resolves to ``<repo_root>/<path>/action.yml`` (or
``action.yaml``) on disk. When that action's ``runs.using`` is
``composite``, its inner ``runs.steps`` execute inside the calling
job's context, with the same secrets and ``GITHUB_TOKEN`` permissions.

This module discovers those composite action bodies during context
load and synthesizes them as ``__composite__`` jobs so the same GHA
rule pack runs against them. Mirrors what :mod:`resolver` already does
for *remote* composite actions, but operates entirely on disk and is
on by default. No ``--resolve-remote`` opt-in is needed because no
network call happens.

Scope: composite ``runs.using == "composite"`` only. JavaScript
(``node20`` / ``node16``) and Docker actions ship as opaque bytecode
or OCI images that the workflow rule pack can't statically scan, so
they are counted and skipped exactly like the remote path does.
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

from .._yaml_lines import safe_load_yaml_lines
from .base import Workflow
from .uses_parser import parse_uses

#: Recursion cap for composite-of-composite chains. Mirrors the
#: resolver's defaults so a deeply nested local action chain has the
#: same bound as a deeply nested remote one.
_DEFAULT_MAX_DEPTH = 3
_HARD_DEPTH_CEILING = 10


def infer_repo_root(gha_path: Path) -> Path | None:
    """Infer the repo root that anchors ``uses: ./path`` references.

    Recognized shapes, in order of confidence:

      * ``<root>/.github/workflows``, the canonical layout. Returns
        ``<root>``.
      * Any directory passed directly (ad-hoc test layouts, custom
        workflow dirs). Returns the parent of *gha_path* so a sibling
        ``actions/`` directory next to the workflow dir resolves.
      * A single workflow file. Returns the file's grandparent under
        the same canonical-layout assumption.

    Returns ``None`` only when the path doesn't exist on disk.
    """
    try:
        p = gha_path.resolve()
    except OSError:
        return None
    if not p.exists():
        return None
    if p.is_file():
        # ``<root>/.github/workflows/foo.yml`` -> ``<root>``
        parts = p.parts
        if (
            len(parts) >= 3
            and parts[-3].lower() == ".github"
            and parts[-2].lower() == "workflows"
        ):
            return p.parent.parent.parent
        return p.parent.parent
    parts = p.parts
    if (
        len(parts) >= 2
        and parts[-2].lower() == ".github"
        and parts[-1].lower() == "workflows"
    ):
        return p.parent.parent
    return p.parent


def discover_local_composite_actions(
    workflows: list[Workflow],
    repo_root: Path,
    max_depth: int = _DEFAULT_MAX_DEPTH,
) -> tuple[list[Workflow], list[str]]:
    """Walk *workflows* for local-action refs and synthesize composites.

    Returns ``(new_workflows, warnings)``. The caller extends
    ``ctx.workflows`` with *new_workflows* and ``ctx.warnings`` with
    *warnings*.

    Each discovered ``uses: ./path`` whose ``action.yml`` declares
    ``runs.using: composite`` produces one synthesized
    :class:`Workflow` with a single ``__composite__`` job carrying
    the action's ``runs.steps``. Path-traversal attempts that escape
    *repo_root* are rejected. Composite-of-composite chains are
    bounded by *max_depth* (capped at ``_HARD_DEPTH_CEILING``).
    """
    max_depth = min(max(1, max_depth), _HARD_DEPTH_CEILING)
    try:
        root_resolved = repo_root.resolve()
    except OSError:
        return [], []
    if not root_resolved.is_dir():
        return [], []

    out: list[Workflow] = []
    warnings: list[str] = []
    # Dedup composite synthesis: a project that uses ``./actions/build``
    # from five workflows synthesizes one body. Findings still attribute
    # via the synthesized workflow's path; multi-caller attribution
    # routes through the existing rule-level resource handle.
    visited: set[Path] = set()
    # Per-action missing-file warning: dedup so a typo'd ./missing-action
    # referenced from N workflows reports once.
    missing_reported: set[str] = set()

    queue: list[tuple[Workflow, str, int]] = []
    for wf in workflows:
        if wf.source_ref is not None:
            continue  # already a resolved callee
        for local_path in _iter_local_action_paths(wf):
            queue.append((wf, local_path, 1))

    composite_count = 0
    skipped_non_composite = 0

    while queue:
        current, queue = queue, []
        for caller, local_path, depth in current:
            action_file = _resolve_action_file(root_resolved, local_path)
            if action_file is None:
                if local_path not in missing_reported:
                    missing_reported.add(local_path)
                    warnings.append(
                        f"[gha-local-actions] could not resolve "
                        f"local action {local_path} "
                        f"(referenced from {caller.path}); expected "
                        f"action.yml / action.yaml under "
                        f"{local_path.lstrip('./').lstrip('/')}/."
                    )
                continue
            if action_file in visited:
                continue
            visited.add(action_file)

            doc = _parse_action_yaml(action_file, warnings)
            if doc is None:
                continue

            synthesized = _build_composite_workflow(
                action_file=action_file,
                action_doc=doc,
                repo_root=root_resolved,
                caller_path=caller.path,
            )
            if synthesized is None:
                # Non-composite (node20 / docker) action, or malformed.
                if _is_non_composite(doc):
                    skipped_non_composite += 1
                continue

            out.append(synthesized)
            composite_count += 1

            if depth >= max_depth:
                continue
            for nested_path in _iter_local_action_paths(synthesized):
                queue.append((synthesized, nested_path, depth + 1))

    if composite_count:
        warnings.append(
            f"[gha-local-actions] resolved {composite_count} local "
            f"composite action(s); rule pack ran against their bodies."
        )
    if skipped_non_composite:
        warnings.append(
            f"[gha-local-actions] skipped {skipped_non_composite} non-"
            f"composite local action(s) (JavaScript / Docker); their "
            f"executable surface is outside the workflow YAML rule pack."
        )
    return out, warnings


def _iter_local_action_paths(wf: Workflow) -> Iterator[str]:
    """Yield each ``uses: ./path`` (local-action kind) in *wf*."""
    jobs = wf.data.get("jobs")
    if not isinstance(jobs, dict):
        return
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            ref = parse_uses(step.get("uses"))
            if ref is None or ref.kind != "local-action":
                continue
            yield ref.path


def _resolve_action_file(
    root_resolved: Path, local_path: str,
) -> Path | None:
    """Map ``./path`` to an on-disk ``action.yml`` / ``action.yaml``.

    Rejects path-traversal attempts that escape *root_resolved* (i.e.,
    a ``./../../etc/passwd`` ref). Returns ``None`` if no
    ``action.yml`` / ``action.yaml`` exists under the resolved path.
    """
    cleaned = local_path.lstrip("/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    if not cleaned or ".." in Path(cleaned).parts:
        return None
    for candidate_name in ("action.yml", "action.yaml"):
        candidate = root_resolved / cleaned / candidate_name
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if (
            resolved != root_resolved
            and root_resolved not in resolved.parents
        ):
            # Symlink (or component combination) escaped the root.
            continue
        if resolved.is_file():
            return resolved
    return None


def _parse_action_yaml(
    action_file: Path, warnings: list[str],
) -> dict[str, Any] | None:
    """Read + parse *action_file*. Warnings appended; ``None`` on error."""
    try:
        text = action_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        warnings.append(
            f"[gha-local-actions] read error on {action_file}: {exc}"
        )
        return None
    try:
        doc = safe_load_yaml_lines(text)
    except yaml.YAMLError as exc:
        first_line = str(exc).split("\n", 1)[0]
        warnings.append(
            f"[gha-local-actions] YAML parse error in "
            f"{action_file}: {first_line}"
        )
        return None
    if not isinstance(doc, dict):
        return None
    return doc


def _is_non_composite(action_doc: dict[str, Any]) -> bool:
    """Distinguish ``using: node20`` / ``docker`` from malformed bodies."""
    runs = action_doc.get("runs")
    if not isinstance(runs, dict):
        return False
    using = runs.get("using")
    if not isinstance(using, str):
        return False
    return using.lower() != "composite"


def _build_composite_workflow(
    action_file: Path,
    action_doc: dict[str, Any],
    repo_root: Path,
    caller_path: str,
) -> Workflow | None:
    """Synthesize a Workflow from a composite action's body.

    Mirrors :meth:`Resolver._build_composite_workflow`. Returns
    ``None`` for non-composite actions (counted by the caller) or
    bodies missing a ``runs.steps`` list.
    """
    runs = action_doc.get("runs")
    if not isinstance(runs, dict):
        return None
    using = runs.get("using")
    if not isinstance(using, str) or using.lower() != "composite":
        return None
    steps = runs.get("steps")
    if not isinstance(steps, list):
        return None

    try:
        relative = action_file.relative_to(repo_root)
        attribution_path = relative.as_posix()
    except ValueError:
        attribution_path = action_file.as_posix()

    attribution = f"local-composite:{attribution_path}"
    synthetic_path = f"{caller_path} -> {attribution}"
    synthetic_doc: dict[str, Any] = {
        "name": str(action_doc.get("name") or attribution),
        "jobs": {
            "__composite__": {
                "runs-on": "ubuntu-latest",
                "steps": steps,
            },
        },
    }
    return Workflow(
        path=synthetic_path,
        data=synthetic_doc,
        source_ref=attribution,
        caller_path=caller_path,
        inherited_permissions=None,
        inherited_secret_names=frozenset(),
        inherits_secrets=True,
    )
