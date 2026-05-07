"""Shared helpers for Argo Workflows per-rule tests."""
from __future__ import annotations

import textwrap

import yaml

from pipeline_check.core.checks.argo.base import ArgoContext, ArgoDoc
from pipeline_check.core.checks.argo.pipelines import ArgoChecks


def argo_ctx(yaml_text: str, path: str = "argo.yaml") -> ArgoContext:
    """Parse a multi-doc YAML snippet into an ArgoContext."""
    text = textwrap.dedent(yaml_text)
    parsed = list(yaml.safe_load_all(text))
    docs: list[ArgoDoc] = []
    for idx, raw in enumerate(parsed):
        if not isinstance(raw, dict):
            continue
        api_version = raw.get("apiVersion")
        kind = raw.get("kind")
        if not isinstance(api_version, str) or not isinstance(kind, str):
            continue
        if not api_version.startswith("argoproj.io/"):
            continue
        meta = raw.get("metadata") or {}
        if not isinstance(meta, dict):
            meta = {}
        docs.append(ArgoDoc(
            path=path,
            doc_index=idx,
            api_version=api_version,
            kind=kind,
            name=meta.get("name", "") if isinstance(meta.get("name"), str) else "",
            namespace=meta.get("namespace", "") if isinstance(meta.get("namespace"), str) else "",
            data=raw,
        ))
    return ArgoContext(docs)


def run_check(yaml_text: str, check_id: str):
    """Run every Argo check; return the Finding with the given id."""
    ctx = argo_ctx(yaml_text)
    for f in ArgoChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not found in Argo orchestrator output"
    )
