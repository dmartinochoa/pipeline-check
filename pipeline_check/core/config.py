"""Configuration loading — pyproject.toml, .pipeline-check.yml, and env vars.

Precedence (highest wins):

1. CLI flags
2. Environment variables  (``PIPELINE_CHECK_<FLAG>`` / ``PIPELINE_CHECK_GATE_<FLAG>``)
3. Config file
4. Built-in defaults (``click`` ``default=``)

Config file search order (first match wins):

1. Explicit ``--config PATH``
2. ``.pipeline-check.yml`` / ``.pipeline-check.yaml`` at the cwd
3. ``pyproject.toml`` (``[tool.pipeline_check]`` section) at the cwd

Schema keys mirror CLI flag names with hyphens replaced by underscores.
Unknown keys are ignored (warned to stderr) rather than raising, so a
stray key from a newer version doesn't brick an older install. Gate
settings live under a ``[tool.pipeline_check.gate]`` sub-table (TOML) or
a ``gate:`` sub-mapping (YAML).

The returned dict is suitable for ``click.Context.default_map`` — which
means option names must match click parameter names. Anything we don't
recognise is dropped from the returned map.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

try:
    import tomllib  # py3.11+
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[import-not-found]

import yaml


# Keys that are allowed in a config file (and map directly to click option names).
_TOPLEVEL_KEYS: frozenset[str] = frozenset({
    "pipeline", "target", "checks", "region", "profile",
    "tf_plan", "gha_path", "gitlab_path", "bitbucket_path", "azure_path",
    "output", "output_file",
    "standards", "severity_threshold",
})

# Keys allowed under the "gate" sub-table.
_GATE_KEYS: frozenset[str] = frozenset({
    "fail_on", "min_grade", "max_failures",
    "fail_on_checks", "baseline", "ignore_file",
})

# Config-gate-key → CLI-option-name. Keeps CLI-facing names stable even if
# we rename internals.
_GATE_KEY_TO_CLI: dict[str, str] = {
    "fail_on": "fail_on",
    "min_grade": "min_grade",
    "max_failures": "max_failures",
    "fail_on_checks": "fail_on_checks",
    "baseline": "baseline",
    "ignore_file": "ignore_file",
}

# Environment-variable prefix.
_ENV_PREFIX = "PIPELINE_CHECK_"
_ENV_GATE_PREFIX = "PIPELINE_CHECK_GATE_"


def load_config(explicit_path: str | None = None, cwd: Path | None = None) -> dict[str, Any]:
    """Resolve configuration from file(s) + environment.

    Returns a flat dict keyed by click option name (e.g. ``"pipeline"``,
    ``"fail_on"``). This is the shape ``click.Context.default_map``
    expects, so the caller can hand it straight to the click entry
    point.
    """
    cwd = cwd or Path.cwd()
    file_cfg = _load_from_file(explicit_path, cwd)
    env_cfg = _load_from_env()

    # Env overrides file.
    merged: dict[str, Any] = {**file_cfg, **env_cfg}
    return merged


# ────────────────────────────────────────────────────────────────────────────
# File loaders
# ────────────────────────────────────────────────────────────────────────────


def _load_from_file(explicit_path: str | None, cwd: Path) -> dict[str, Any]:
    """Load a flat config dict from whichever file is found first."""
    if explicit_path:
        p = Path(explicit_path)
        if not p.exists():
            # Explicit path was given and doesn't exist — caller wants this
            # file in particular, so surface the error rather than silently
            # falling back to auto-discovery.
            raise FileNotFoundError(f"--config file not found: {p}")
        return _load_path(p)

    for candidate in (".pipeline-check.yml", ".pipeline-check.yaml"):
        p = cwd / candidate
        if p.exists():
            return _load_path(p)

    pyproject = cwd / "pyproject.toml"
    if pyproject.exists():
        return _load_pyproject(pyproject)

    return {}


def _load_path(p: Path) -> dict[str, Any]:
    suffix = p.suffix.lower()
    try:
        if suffix in (".yml", ".yaml"):
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        elif suffix == ".toml":
            with p.open("rb") as fh:
                doc = tomllib.load(fh)
            data = doc.get("tool", {}).get("pipeline_check", {}) or {}
        else:
            # Unknown extension — best effort: try YAML (it's a superset of JSON).
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError, tomllib.TOMLDecodeError) as exc:
        print(f"[config] could not parse {p}: {exc}", file=sys.stderr)
        return {}
    return _flatten(data, source=str(p))


def _load_pyproject(p: Path) -> dict[str, Any]:
    try:
        with p.open("rb") as fh:
            doc = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    section = doc.get("tool", {}).get("pipeline_check", {}) or {}
    if not section:
        return {}
    return _flatten(section, source=str(p))


def _flatten(raw: dict[str, Any], *, source: str) -> dict[str, Any]:
    """Flatten the nested config dict into click-option-name keys.

    Top-level keys and ``gate.*`` sub-keys are recognised; anything else
    is dropped with a stderr warning.
    """
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if key == "gate":
            if not isinstance(value, dict):
                _warn_unknown(source, "gate", "value must be a mapping")
                continue
            for gk, gv in value.items():
                if gk in _GATE_KEYS:
                    out[_GATE_KEY_TO_CLI[gk]] = _coerce(gk, gv)
                else:
                    _warn_unknown(source, f"gate.{gk}")
            continue
        if key in _TOPLEVEL_KEYS:
            out[key] = _coerce(key, value)
        else:
            _warn_unknown(source, key)
    return out


def _coerce(key: str, value: Any) -> Any:
    """Light coercion so tests/config files can express values naturally.

    - ``checks``, ``standards``, ``fail_on_checks`` always reach click as
      tuples (multiple=True) — accept a list in config and convert.
    - Everything else passes through as-is; click handles type conversion.
    """
    if key in ("checks", "standards", "fail_on_checks") and isinstance(value, list):
        return tuple(str(v) for v in value)
    return value


def _warn_unknown(source: str, key: str, reason: str = "unknown key") -> None:
    print(f"[config] ignoring {key!r} from {source}: {reason}", file=sys.stderr)


# ────────────────────────────────────────────────────────────────────────────
# Environment loader
# ────────────────────────────────────────────────────────────────────────────


def _load_from_env() -> dict[str, Any]:
    """Pull ``PIPELINE_CHECK_*`` env vars into the same flat dict shape.

    Example::

        PIPELINE_CHECK_PIPELINE=aws
        PIPELINE_CHECK_SEVERITY_THRESHOLD=HIGH
        PIPELINE_CHECK_GATE_FAIL_ON=CRITICAL
        PIPELINE_CHECK_STANDARDS=owasp_cicd_top_10,nist_ssdf
    """
    out: dict[str, Any] = {}
    for name, raw in os.environ.items():
        if name.startswith(_ENV_GATE_PREFIX):
            key = name[len(_ENV_GATE_PREFIX):].lower()
            if key in _GATE_KEYS:
                out[_GATE_KEY_TO_CLI[key]] = _coerce_env(key, raw)
        elif name.startswith(_ENV_PREFIX):
            key = name[len(_ENV_PREFIX):].lower()
            if key in _TOPLEVEL_KEYS:
                out[key] = _coerce_env(key, raw)
    return out


def _coerce_env(key: str, raw: str) -> Any:
    """Env vars arrive as strings; split the multi-value ones on commas."""
    if key in ("checks", "standards", "fail_on_checks"):
        return tuple(v.strip() for v in raw.split(",") if v.strip())
    if key == "max_failures":
        try:
            return int(raw)
        except ValueError:
            return raw
    return raw
