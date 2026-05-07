"""Shared helpers for Tekton per-rule tests."""
from __future__ import annotations

import textwrap

import yaml

from pipeline_check.core.checks.tekton.base import (
    TektonContext,
    TektonDoc,
)
from pipeline_check.core.checks.tekton.pipelines import TektonChecks


def tk_ctx(yaml_text: str, path: str = "tekton.yaml") -> TektonContext:
    """Parse a multi-doc YAML snippet into a TektonContext."""
    text = textwrap.dedent(yaml_text)
    parsed = list(yaml.safe_load_all(text))
    docs: list[TektonDoc] = []
    for idx, raw in enumerate(parsed):
        if not isinstance(raw, dict):
            continue
        api_version = raw.get("apiVersion")
        kind = raw.get("kind")
        if not isinstance(api_version, str) or not isinstance(kind, str):
            continue
        group, sep, _version = api_version.partition("/")
        if sep != "/" or group != "tekton.dev":
            continue
        meta = raw.get("metadata") or {}
        if not isinstance(meta, dict):
            meta = {}
        docs.append(TektonDoc(
            path=path,
            doc_index=idx,
            api_version=api_version,
            kind=kind,
            name=meta.get("name", "") if isinstance(meta.get("name"), str) else "",
            namespace=meta.get("namespace", "") if isinstance(meta.get("namespace"), str) else "",
            data=raw,
        ))
    return TektonContext(docs)


def run_check(yaml_text: str, check_id: str):
    """Run every Tekton check; return the Finding with the given id."""
    ctx = tk_ctx(yaml_text)
    for f in TektonChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not found in Tekton orchestrator output"
    )
