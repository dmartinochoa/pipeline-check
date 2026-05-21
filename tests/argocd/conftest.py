"""Shared helpers for Argo CD per-rule tests."""
from __future__ import annotations

import textwrap

import yaml

from pipeline_check.core.checks.argocd.base import (
    ARGOCD_CONFIGMAPS,
    ARGOCD_CRD_KINDS,
    ArgoCDContext,
    ArgoCDDoc,
)
from pipeline_check.core.checks.argocd.pipelines import ArgoCDChecks


def argocd_ctx(yaml_text: str, path: str = "argocd.yaml") -> ArgoCDContext:
    """Parse a multi-doc YAML snippet into an ArgoCDContext."""
    text = textwrap.dedent(yaml_text)
    parsed = list(yaml.safe_load_all(text))
    docs: list[ArgoCDDoc] = []
    for idx, raw in enumerate(parsed):
        if not isinstance(raw, dict):
            continue
        api_version = raw.get("apiVersion")
        kind = raw.get("kind")
        if not isinstance(api_version, str) or not isinstance(kind, str):
            continue
        meta = raw.get("metadata") or {}
        if not isinstance(meta, dict):
            meta = {}
        name = meta.get("name", "") if isinstance(meta.get("name"), str) else ""
        namespace = meta.get("namespace", "") if isinstance(meta.get("namespace"), str) else ""
        group, sep, _v = api_version.partition("/")
        if sep == "/" and group == "argoproj.io":
            if kind not in ARGOCD_CRD_KINDS:
                continue
        elif api_version == "v1" and kind == "ConfigMap":
            if name not in ARGOCD_CONFIGMAPS:
                continue
        else:
            continue
        docs.append(ArgoCDDoc(
            path=path,
            doc_index=idx,
            api_version=api_version,
            kind=kind,
            name=name,
            namespace=namespace,
            data=raw,
        ))
    return ArgoCDContext(docs)


def run_check(yaml_text: str, check_id: str):
    """Run every Argo CD check; return the Finding with the given id."""
    ctx = argocd_ctx(yaml_text)
    for f in ArgoCDChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not found in Argo CD orchestrator output"
    )
