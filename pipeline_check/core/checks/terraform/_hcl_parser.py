"""HCL2 source parser for direct .tf file scanning.

Synthesizes :class:`TerraformResource` objects from raw HCL, suitable for
feeding into :class:`TerraformContext`. Variable and local substitution is
best-effort: values that cannot be resolved at parse time remain as opaque
interpolation strings (``${var.X}``).

Requires the optional ``python-hcl2`` package
(``pip install pipeline-check[hcl]``).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .base import TerraformResource

try:
    import hcl2 as _hcl2
except ImportError:
    _hcl2 = None

_INTERP_RE = re.compile(r"\$\{(var|local)\.([a-zA-Z_][a-zA-Z0-9_]*)\}")
_INTERP_FULL_RE = re.compile(
    r"^\$\{(var|local)\.([a-zA-Z_][a-zA-Z0-9_]*)\}$"
)

_MODULE_DEPTH_LIMIT = 3


@dataclass
class HclParseResult:
    resources: list[TerraformResource] = field(default_factory=list)
    data_sources: list[TerraformResource] = field(default_factory=list)
    unresolved_refs: set[str] = field(default_factory=set)
    resources_with_unresolved: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)
    files_scanned: int = 0


def parse_tf_directory(path: Path) -> HclParseResult:
    """Parse all ``*.tf`` files in *path* and return synthesized resources."""
    if _hcl2 is None:
        raise ImportError(
            "The --tf-source flag requires the 'python-hcl2' package. "
            "Install it with: pip install 'pipeline-check[hcl]'"
        )
    return _parse_module(path, prefix="", depth=0, root=path.resolve())


def _parse_module(
    directory: Path, prefix: str, depth: int,
    *, root: Path | None = None,
) -> HclParseResult:
    result = HclParseResult()
    tf_files = sorted(directory.glob("*.tf"))
    if not tf_files:
        return result

    merged = _merge_parsed_files(tf_files, result)
    result.files_scanned = len(tf_files) - len(
        [w for w in result.warnings if "parse error" in w]
    )

    variables = _resolve_variables(merged)
    locals_ = _resolve_locals(merged, variables)

    unresolved: set[str] = set()
    managed, data = _synthesize_resources(
        merged, variables, locals_, prefix, unresolved,
    )
    result.resources.extend(managed)
    result.data_sources.extend(data)
    result.unresolved_refs.update(unresolved)

    for r in managed + data:
        if _values_contain_interpolation(r.values):
            result.resources_with_unresolved.add(r.address)

    if depth < _MODULE_DEPTH_LIMIT:
        _walk_child_modules(directory, merged, variables, locals_,
                            prefix, depth, result,
                            root=root or directory.resolve())

    return result


# ── File loading ────────────────────────────────────────────────────────


def _merge_parsed_files(
    files: list[Path], result: HclParseResult,
) -> dict[str, list[Any]]:
    merged: dict[str, list[Any]] = {}
    for tf_file in files:
        try:
            with open(tf_file, encoding="utf-8") as fh:
                parsed = _hcl2.load(fh)
        except Exception as exc:
            result.warnings.append(f"{tf_file}: HCL parse error: {exc}")
            continue
        for key, blocks in parsed.items():
            if not isinstance(blocks, list):
                continue
            merged.setdefault(key, []).extend(blocks)
    return merged


# ── Variable / local resolution ─────────────────────────────────────────


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def _clean_value(value: Any) -> Any:
    """Recursively strip HCL2 parser quote-wrapping from values."""
    if isinstance(value, str):
        return _strip_quotes(value)
    if isinstance(value, dict):
        return {
            (_strip_quotes(k) if isinstance(k, str) else k): _clean_value(v)
            for k, v in value.items()
            if k != "__is_block__"
        }
    if isinstance(value, list):
        return [_clean_value(item) for item in value]
    return value


def _resolve_variables(merged: dict[str, list[Any]]) -> dict[str, Any]:
    variables: dict[str, Any] = {}
    for block in merged.get("variable", []):
        if not isinstance(block, dict):
            continue
        for raw_name, attrs in block.items():
            if raw_name == "__is_block__":
                continue
            name = _strip_quotes(raw_name)
            if isinstance(attrs, dict) and "default" in attrs:
                variables[name] = _clean_value(attrs["default"])
    return variables


def _resolve_locals(
    merged: dict[str, list[Any]], variables: dict[str, Any],
) -> dict[str, Any]:
    raw: dict[str, Any] = {}
    for block in merged.get("locals", []):
        if not isinstance(block, dict):
            continue
        for k, v in block.items():
            if k == "__is_block__":
                continue
            raw[_strip_quotes(k)] = _clean_value(v)

    resolved: dict[str, Any] = {}
    for name, value in raw.items():
        substituted = _substitute_refs(value, variables, resolved)
        if not _contains_interpolation(substituted):
            resolved[name] = substituted
    return resolved


def _substitute_refs(
    value: Any,
    variables: dict[str, Any],
    locals_: dict[str, Any],
) -> Any:
    if isinstance(value, str):
        full = _INTERP_FULL_RE.match(value)
        if full:
            kind, name = full.group(1), full.group(2)
            source = variables if kind == "var" else locals_
            if name in source:
                return source[name]
            return value
        def _replace(m: re.Match[str]) -> str:
            kind, name = m.group(1), m.group(2)
            source = variables if kind == "var" else locals_
            if name in source:
                resolved = source[name]
                return str(resolved) if not isinstance(resolved, str) else resolved
            return m.group(0)
        return _INTERP_RE.sub(_replace, value)
    if isinstance(value, dict):
        return {k: _substitute_refs(v, variables, locals_) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute_refs(item, variables, locals_) for item in value]
    return value


def _contains_interpolation(value: Any) -> bool:
    if isinstance(value, str):
        return "${" in value
    if isinstance(value, dict):
        return any(_contains_interpolation(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_interpolation(item) for item in value)
    return False


def _values_contain_interpolation(values: dict[str, Any]) -> bool:
    return _contains_interpolation(values)


# ── Resource synthesis ──────────────────────────────────────────────────


def _synthesize_resources(
    merged: dict[str, list[Any]],
    variables: dict[str, Any],
    locals_: dict[str, Any],
    prefix: str,
    unresolved: set[str],
) -> tuple[list[TerraformResource], list[TerraformResource]]:
    managed: list[TerraformResource] = []
    data: list[TerraformResource] = []

    for block in merged.get("resource", []):
        if not isinstance(block, dict):
            continue
        for raw_type, type_body in block.items():
            if raw_type == "__is_block__" or not isinstance(type_body, dict):
                continue
            rtype = _strip_quotes(raw_type)
            for raw_name, raw_values in type_body.items():
                if raw_name == "__is_block__" or not isinstance(raw_values, dict):
                    continue
                rname = _strip_quotes(raw_name)
                values = _clean_value(raw_values)
                values = _substitute_refs(values, variables, locals_)
                _collect_unresolved(values, unresolved)
                address = f"{rtype}.{rname}" if not prefix else f"{prefix}{rtype}.{rname}"
                managed.append(TerraformResource(
                    address=address, type=rtype, name=rname, values=values,
                ))

    for block in merged.get("data", []):
        if not isinstance(block, dict):
            continue
        for raw_type, type_body in block.items():
            if raw_type == "__is_block__" or not isinstance(type_body, dict):
                continue
            dtype = _strip_quotes(raw_type)
            for raw_name, raw_values in type_body.items():
                if raw_name == "__is_block__" or not isinstance(raw_values, dict):
                    continue
                dname = _strip_quotes(raw_name)
                values = _clean_value(raw_values)
                values = _substitute_refs(values, variables, locals_)
                _collect_unresolved(values, unresolved)
                address = f"{prefix}data.{dtype}.{dname}"
                data.append(TerraformResource(
                    address=address, type=dtype, name=dname, values=values,
                ))

    return managed, data


def _collect_unresolved(value: Any, unresolved: set[str]) -> None:
    if isinstance(value, str):
        for m in _INTERP_RE.finditer(value):
            unresolved.add(f"{m.group(1)}.{m.group(2)}")
    elif isinstance(value, dict):
        for v in value.values():
            _collect_unresolved(v, unresolved)
    elif isinstance(value, list):
        for item in value:
            _collect_unresolved(item, unresolved)


# ── Child module walking ────────────────────────────────────────────────


def _walk_child_modules(
    directory: Path,
    merged: dict[str, list[Any]],
    variables: dict[str, Any],
    locals_: dict[str, Any],
    prefix: str,
    depth: int,
    result: HclParseResult,
    *,
    root: Path,
) -> None:
    for block in merged.get("module", []):
        if not isinstance(block, dict):
            continue
        for raw_name, attrs in block.items():
            if raw_name == "__is_block__" or not isinstance(attrs, dict):
                continue
            mod_name = _strip_quotes(raw_name)
            source = attrs.get("source")
            if isinstance(source, str):
                source = _strip_quotes(source)
            if not isinstance(source, str):
                continue
            if not (source.startswith(("./", "../"))):
                continue
            mod_dir = (directory / source).resolve()
            if not mod_dir.is_dir():
                continue
            try:
                mod_dir.relative_to(root)
            except ValueError:
                result.warnings.append(
                    f"module.{mod_name}: source {source!r} resolves "
                    f"outside the scan root, skipped"
                )
                continue
            child_prefix = f"{prefix}module.{mod_name}."
            child = _parse_module(mod_dir, child_prefix, depth + 1,
                                  root=root)
            result.resources.extend(child.resources)
            result.data_sources.extend(child.data_sources)
            result.unresolved_refs.update(child.unresolved_refs)
            result.resources_with_unresolved.update(
                child.resources_with_unresolved
            )
            result.warnings.extend(child.warnings)
            result.files_scanned += child.files_scanned
