"""Configuration loading, pyproject.toml, .pipeline-check.yml, and env vars.

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

The returned dict is suitable for ``click.Context.default_map``, which
means option names must match click parameter names. Anything we don't
recognize is dropped from the returned map.
"""
from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml

from ._yaml_strict import safe_load_strict as _safe_load_strict
from .checks.base import VALID_SEVERITY_NAMES as _VALID_SEVERITIES

# Keys that are allowed in a config file (and map directly to click option names).
_TOPLEVEL_KEYS: frozenset[str] = frozenset({
    "pipeline", "target", "checks", "region", "profile",
    "tf_plan", "tf_source",
    "gha_path", "gitlab_path", "bitbucket_path", "azure_path",
    "circleci_path", "jenkinsfile_path", "cfn_template",
    "cloudbuild_path", "dockerfile_path", "k8s_path",
    "buildkite_path", "tekton_path", "argo_path", "argocd_path",
    "helm_path", "helm_values", "helm_set", "oci_manifest",
    "drone_path", "npm_path", "pypi_path", "maven_path", "nuget_path",
    # GHA reusable-workflow remote-ref resolver.
    "resolve_remote", "gh_token", "no_cache",
    "gha_search_path", "gha_resolve_depth",
    "output", "output_file",
    "standards", "severity_threshold", "min_confidence",
    "secret_patterns", "detect_entropy",
    # Custom rule files, paths to YAML rule definitions.
    "custom_rules",
    # OPA Rego rule directories.
    "rego_rules",
    # Per-rule severity overrides, see ``_parse_overrides``.
    "overrides",
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


#: Populated by ``_flatten`` each time a config file is parsed so
#: ``--config-check`` can report on the most recent load without
#: re-parsing. A list of ``(source, key, reason)`` tuples.
_LAST_UNKNOWN_KEYS: list[tuple[str, str, str]] = []

#: Path of the config file that was loaded (if any). Set by
#: ``_load_from_file`` so the CLI can announce which file was used.
_LAST_LOADED_SOURCE: str | None = None


def last_unknown_keys() -> list[tuple[str, str, str]]:
    """Return the unknown keys seen during the last ``load_config`` call."""
    return list(_LAST_UNKNOWN_KEYS)


def last_loaded_source() -> str | None:
    """Return the path of the config file loaded by the last ``load_config`` call."""
    return _LAST_LOADED_SOURCE


#: Per-rule overrides parsed from the last loaded config. Click's
#: ``default_map`` only carries CLI option names, so this map is
#: surfaced separately for the Scanner to consume.
_LAST_OVERRIDES: dict[str, dict[str, str]] = {}


def last_overrides() -> dict[str, dict[str, str]]:
    """Return the ``overrides:`` map parsed by the last ``load_config`` call."""
    return dict(_LAST_OVERRIDES)


def load_config(explicit_path: str | None = None, cwd: Path | None = None) -> dict[str, Any]:
    """Resolve configuration from file(s) + environment.

    Returns a flat dict keyed by click option name (e.g. ``"pipeline"``,
    ``"fail_on"``). This is the shape ``click.Context.default_map``
    expects, so the caller can hand it straight to the click entry
    point.

    The ``overrides:`` block is pulled out of the returned map (it
    isn't a CLI option) and is available via :func:`last_overrides`.
    """
    global _LAST_LOADED_SOURCE
    _LAST_UNKNOWN_KEYS.clear()
    _LAST_LOADED_SOURCE = None
    _LAST_OVERRIDES.clear()
    cwd = cwd or Path.cwd()
    file_cfg = _load_from_file(explicit_path, cwd)
    env_cfg = _load_from_env()

    # Env overrides file.
    merged: dict[str, Any] = {**file_cfg, **env_cfg}
    # Stash overrides for ``last_overrides()`` and drop from the click
    # default_map (click would warn about an unknown ``--overrides``
    # option otherwise).
    overrides_value = merged.pop("overrides", None)
    if isinstance(overrides_value, dict):
        _LAST_OVERRIDES.update(overrides_value)
    return merged


# ────────────────────────────────────────────────────────────────────────────
# File loaders
# ────────────────────────────────────────────────────────────────────────────


def _load_from_file(explicit_path: str | None, cwd: Path) -> dict[str, Any]:
    """Load a flat config dict from whichever file is found first."""
    global _LAST_LOADED_SOURCE
    if explicit_path:
        p = Path(explicit_path)
        if not p.exists():
            # Explicit path was given and doesn't exist, caller wants this
            # file in particular, so surface the error rather than silently
            # falling back to auto-discovery.
            raise FileNotFoundError(f"--config file not found: {p}")
        _LAST_LOADED_SOURCE = str(p)
        return _load_path(p)

    for candidate in (".pipeline-check.yml", ".pipeline-check.yaml"):
        p = cwd / candidate
        if p.exists():
            _LAST_LOADED_SOURCE = str(p)
            return _load_path(p)

    pyproject = cwd / "pyproject.toml"
    if pyproject.exists():
        result = _load_pyproject(pyproject)
        if result:
            _LAST_LOADED_SOURCE = str(pyproject)
        return result

    return {}


def _load_path(p: Path) -> dict[str, Any]:
    suffix = p.suffix.lower()
    try:
        if suffix in (".yml", ".yaml"):
            data = _safe_load_strict(p.read_text(encoding="utf-8")) or {}
        elif suffix == ".toml":
            with p.open("rb") as fh:
                doc = tomllib.load(fh)
            data = doc.get("tool", {}).get("pipeline_check", {}) or {}
        else:
            # Unknown extension, best effort: try YAML (it's a superset of JSON).
            data = _safe_load_strict(p.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError,
            tomllib.TOMLDecodeError) as exc:
        # UnicodeDecodeError (a ValueError, not an OSError) fires when the
        # config file isn't valid UTF-8; without it a latin-1/cp1252 file
        # crashes the eager config-load callback before the scan starts.
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

    Top-level keys and ``gate.*`` sub-keys are recognized; anything else
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
      tuples (multiple=True), accept a list in config and convert.
    - ``overrides`` arrives as a nested mapping; normalize the keys to
      upper-case and the severity values to upper-case strings so the
      Scanner can convert to ``Severity`` without re-validating.
    - Everything else passes through as-is; click handles type conversion.
    """
    list_keys = ("checks", "standards", "fail_on_checks", "secret_patterns", "custom_rules", "rego_rules")
    if key in list_keys and isinstance(value, list):
        return tuple(str(v) for v in value)
    if key == "overrides":
        return _parse_overrides(value)
    return value


def _parse_overrides(raw: Any) -> dict[str, dict[str, str]]:
    """Normalize an ``overrides:`` block into ``{CHECK-ID: {severity: SEV}}``.

    Accepted shape::

        overrides:
          GHA-016:
            severity: low
          K8S-024:
            severity: critical

    Unknown sub-keys, malformed values, and bad severities are dropped
    with an ``[config]`` warning rather than raising, the rest of the
    config should still load.
    """
    if not isinstance(raw, dict):
        print(
            f"[config] ignoring 'overrides': value must be a mapping, got "
            f"{type(raw).__name__}",
            file=sys.stderr,
        )
        return {}
    out: dict[str, dict[str, str]] = {}
    for check_id, body in raw.items():
        if not isinstance(check_id, str) or not check_id.strip():
            print(
                f"[config] ignoring overrides entry: check_id must be a "
                f"non-empty string, got {check_id!r}",
                file=sys.stderr,
            )
            continue
        if not isinstance(body, dict):
            print(
                f"[config] ignoring overrides entry for {check_id!r}: "
                f"value must be a mapping, got {type(body).__name__}",
                file=sys.stderr,
            )
            continue
        normalized: dict[str, str] = {}
        sev = body.get("severity")
        if sev is not None:
            sev_up = str(sev).upper().strip()
            if sev_up in _VALID_SEVERITIES:
                normalized["severity"] = sev_up
            else:
                print(
                    f"[config] ignoring overrides[{check_id!r}].severity: "
                    f"{sev!r} is not one of "
                    f"{sorted(_VALID_SEVERITIES)}",
                    file=sys.stderr,
                )
        unknown = set(body) - {"severity"}
        for k in sorted(unknown):
            print(
                f"[config] ignoring overrides[{check_id!r}].{k}: unknown "
                f"sub-key (only 'severity' is supported today)",
                file=sys.stderr,
            )
        if normalized:
            out[check_id.upper().strip()] = normalized
    return out


def _warn_unknown(source: str, key: str, reason: str = "unknown key") -> None:
    _LAST_UNKNOWN_KEYS.append((source, key, reason))
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
    if key in ("checks", "standards", "fail_on_checks", "secret_patterns", "custom_rules",
                "rego_rules", "helm_values", "helm_set", "gha_search_path"):
        return tuple(v.strip() for v in raw.split(",") if v.strip())
    if key == "max_failures":
        try:
            return int(raw)
        except ValueError:
            return raw
    return raw
