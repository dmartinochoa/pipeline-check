"""Discover ``.rego`` files, extract ``# METADATA`` annotations via
``opa inspect``, validate, and produce :class:`RegoRuleMetadata`
objects that the runner can evaluate.

Policy authors declare rule metadata using OPA's built-in annotation
block::

    # METADATA
    # title: Container image must come from corp registry
    # custom:
    #   id: ACME-001
    #   severity: HIGH
    #   provider: kubernetes
    #   recommendation: Use acme.io/<team>/<image>:<tag>.
    package pipeline_check.kubernetes.acme_001

The loader validates required fields, checks ID collisions against
built-in and YAML custom rules, and groups rules by provider.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..base import Severity
from ..rule import Rule
from .rego_errors import OpaNotFoundError, RegoRuleError, find_opa_binary

_ID_RE = re.compile(r"^[A-Z][A-Z0-9]{1,9}-\d{3}$")

_ALLOWED_SEVERITIES: frozenset[str] = frozenset({
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
})

REGO_ALLOWED_PROVIDERS: frozenset[str] = frozenset({
    "github", "gitlab", "bitbucket", "azure", "circleci", "cloudbuild",
    "kubernetes", "dockerfile", "terraform", "cloudformation", "helm",
    "aws", "npm", "pypi", "maven", "nuget",
    "jenkins", "drone", "buildkite", "tekton", "argo", "argocd",
    "oci", "scm",
})


@dataclass(frozen=True, slots=True)
class RegoRuleMetadata:
    """Validated metadata for a single ``.rego`` policy file."""

    rule: Rule
    provider: str
    package_path: str
    source: str


@dataclass(slots=True)
class LoadedRegoRules:
    """Aggregated Rego load result, grouped by provider."""

    by_provider: dict[str, list[RegoRuleMetadata]] = field(
        default_factory=dict,
    )
    rules: list[Rule] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


def _find_opa() -> str:
    return find_opa_binary()


def find_rego_files(
    paths: list[str] | tuple[str, ...],
) -> list[Path]:
    out: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if not p.exists():
            raise RegoRuleError(
                f"--rego-rules path does not exist: {raw}"
            )
        if p.is_file():
            if p.suffix == ".rego":
                out.append(p)
            else:
                raise RegoRuleError(
                    f"--rego-rules file is not a .rego file: {raw}"
                )
        else:
            files = sorted(f for f in p.rglob("*.rego") if f.is_file())
            if not files:
                raise RegoRuleError(
                    f"--rego-rules path {raw}: no .rego files found"
                )
            out.extend(files)
    return out


def _run_opa_inspect(
    opa: str,
    policy_paths: list[Path],
) -> list[dict[str, Any]]:
    dirs = sorted({str(p.parent) for p in policy_paths})
    annotations: list[dict[str, Any]] = []
    for d in dirs:
        try:
            result = subprocess.run(
                [opa, "inspect", "--annotations", "--format", "json", d],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except FileNotFoundError:
            raise OpaNotFoundError() from None
        if result.returncode != 0:
            raise RegoRuleError(
                f"opa inspect failed for {d}: {result.stderr.strip()}"
            )
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RegoRuleError(
                f"opa inspect returned invalid JSON for {d}: {exc}"
            ) from exc
        file_annotations = data.get("annotations", [])
        if isinstance(file_annotations, list):
            annotations.extend(file_annotations)
    return annotations


def _parse_annotation(
    ann: dict[str, Any],
) -> RegoRuleMetadata | None:
    """Parse one entry from ``opa inspect --annotations`` output.

    The structure from OPA is::

        {
          "annotations": {"title": "...", "scope": "package", "custom": {...}},
          "location": {"file": "...", "row": N, "col": N},
          "path": [{"type": "var", "value": "data"}, {"type": "string", "value": "..."}]
        }
    """
    location = ann.get("location", {})
    source_file = location.get("file", "")

    inner = ann.get("annotations", {})
    if not isinstance(inner, dict):
        return None

    scope = inner.get("scope", "")
    if scope != "package":
        return None

    title = inner.get("title", "")
    description = inner.get("description", "")
    custom = inner.get("custom", {})
    if not isinstance(custom, dict):
        return None

    rule_id = custom.get("id")
    if not rule_id:
        return None

    severity_str = custom.get("severity", "")
    provider = custom.get("provider", "")

    pkg_raw = _extract_package_path(ann.get("path", []))

    return _validate_and_build(
        source=source_file or "<unknown>",
        title=title,
        description=description,
        rule_id=str(rule_id),
        severity_str=str(severity_str).upper(),
        provider=str(provider).lower(),
        package_path=pkg_raw,
        custom=custom,
    )


def _extract_package_path(path_list: Any) -> str:
    if not isinstance(path_list, list):
        return ""
    parts: list[str] = []
    for segment in path_list:
        if isinstance(segment, dict):
            val = segment.get("value", "")
            if val and val != "data":
                parts.append(str(val))
    return ".".join(parts)


def _validate_and_build(
    *,
    source: str,
    title: str,
    description: str,
    rule_id: str,
    severity_str: str,
    provider: str,
    package_path: str,
    custom: dict[str, Any],
) -> RegoRuleMetadata:
    where = f"{source}: rule {rule_id!r}"

    if not title:
        raise RegoRuleError(
            f"{where}: missing required METADATA field 'title'"
        )
    if not _ID_RE.match(rule_id):
        raise RegoRuleError(
            f"{where}: id {rule_id!r} must match {_ID_RE.pattern} "
            f"(e.g. 'ACME-001')"
        )
    if severity_str not in _ALLOWED_SEVERITIES:
        raise RegoRuleError(
            f"{where}: severity {severity_str!r} must be one of "
            f"{sorted(_ALLOWED_SEVERITIES)}"
        )
    if not provider:
        raise RegoRuleError(
            f"{where}: missing required METADATA field 'custom.provider'"
        )
    if provider not in REGO_ALLOWED_PROVIDERS:
        raise RegoRuleError(
            f"{where}: provider {provider!r} is not a recognized provider"
        )

    recommendation = custom.get("recommendation", "")
    docs_note = custom.get("docs_note", "")
    cwe = _to_str_tuple(custom.get("cwe", []))
    owasp = _to_str_tuple(custom.get("owasp", []))
    esf = _to_str_tuple(custom.get("esf", []))

    rule = Rule(
        id=rule_id,
        title=str(title),
        severity=Severity(severity_str),
        owasp=owasp,
        esf=esf,
        cwe=cwe,
        recommendation=str(recommendation),
        docs_note=str(docs_note),
    )
    return RegoRuleMetadata(
        rule=rule,
        provider=provider,
        package_path=package_path,
        source=source,
    )


def _to_str_tuple(val: Any) -> tuple[str, ...]:
    if isinstance(val, list):
        return tuple(str(v) for v in val)
    if isinstance(val, str) and val:
        return (val,)
    return ()


def load_rego_rules(
    paths: list[str] | tuple[str, ...] | None,
    builtin_ids: set[str] | None = None,
    yaml_custom_ids: set[str] | None = None,
) -> LoadedRegoRules:
    """Load Rego rules from ``.rego`` files under each path.

    Validates metadata annotations, checks ID collisions against
    built-in and YAML custom rules. Returns the loaded rules grouped
    by provider.
    """
    out = LoadedRegoRules()
    if not paths:
        return out

    opa = _find_opa()
    files = find_rego_files(paths)
    if not files:
        return out

    builtin = builtin_ids or set()
    yaml_ids = yaml_custom_ids or set()
    annotations = _run_opa_inspect(opa, files)

    seen_ids: dict[str, str] = {}

    for ann in annotations:
        meta = _parse_annotation(ann)
        if meta is None:
            continue

        rid = meta.rule.id
        if rid in builtin:
            raise RegoRuleError(
                f"{meta.source}: rule id {rid!r} collides with a "
                f"built-in check. Pick a different prefix."
            )
        if rid in yaml_ids:
            raise RegoRuleError(
                f"{meta.source}: rule id {rid!r} collides with a "
                f"YAML custom rule. Each rule id must be unique."
            )
        if rid in seen_ids:
            raise RegoRuleError(
                f"{meta.source}: rule id {rid!r} is already "
                f"defined in {seen_ids[rid]}."
            )
        seen_ids[rid] = meta.source
        out.by_provider.setdefault(meta.provider, []).append(meta)
        out.rules.append(meta.rule)

    out.sources = [str(f) for f in files]
    return out


__all__ = [
    "REGO_ALLOWED_PROVIDERS",
    "LoadedRegoRules",
    "RegoRuleMetadata",
    "find_rego_files",
    "load_rego_rules",
]
