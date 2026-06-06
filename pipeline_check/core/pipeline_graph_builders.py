"""Dispatch a provider context to its step-level pipeline-graph builder.

Each pipeline-shaped provider ships a ``checks/<provider>/_graph.py`` that
defines ``build_graphs(context) -> list[PipelineGraph]`` and registers it here
via :func:`register_builder` at import. The builder modules are imported lazily
(only when a scan of that provider asks for graphs) so a GitHub scan never
imports the Azure builder, keeping startup cost off the hot path. IaC / SCA /
cloud providers have no entry and yield ``[]``.
"""
from __future__ import annotations

import importlib
from collections.abc import Callable
from typing import Any

from .pipeline_graph import PipelineGraph

#: provider name -> builder. Populated as ``_graph`` modules import.
_BUILDERS: dict[str, Callable[[Any], list[PipelineGraph]]] = {}

#: provider name -> the module that registers its builder. Imported on first
#: use. Append one line here per provider increment.
_BUILDER_MODULES: dict[str, str] = {
    "github": "pipeline_check.core.checks.github._graph",
    "gitlab": "pipeline_check.core.checks.gitlab._graph",
    "circleci": "pipeline_check.core.checks.circleci._graph",
    "cloudbuild": "pipeline_check.core.checks.cloudbuild._graph",
    "drone": "pipeline_check.core.checks.drone._graph",
}


def register_builder(
    provider: str, fn: Callable[[Any], list[PipelineGraph]],
) -> None:
    """Register *fn* as the graph builder for *provider* (called at import)."""
    _BUILDERS[provider.lower()] = fn


def build_graphs_for(provider: str, context: Any) -> list[PipelineGraph]:
    """Return one :class:`PipelineGraph` per pipeline file, or ``[]``.

    Never raises: a builder that fails (an unexpected context shape, a
    malformed pipeline) yields ``[]`` so graph-building stays an additive
    visual signal that can't abort a scan.
    """
    name = provider.lower()
    if name not in _BUILDERS and name in _BUILDER_MODULES:
        try:
            importlib.import_module(_BUILDER_MODULES[name])
        except Exception:
            return []
    fn = _BUILDERS.get(name)
    if fn is None:
        return []
    try:
        return fn(context)
    except Exception:
        return []
