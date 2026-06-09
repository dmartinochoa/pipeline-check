"""Per-rule policy-as-code overlay.

A *policy* is a named scan profile, a YAML file that bundles:

- a rule filter (``checks:`` whitelist, glob patterns supported),
- a standards filter (``standards:``),
- gate thresholds (``gate.fail_on``, ``gate.min_grade``, ``gate.max_failures``,
  ``gate.fail_on_checks``),
- per-rule severity overrides (``overrides:``).

Real teams already wire up tiered scan profiles by hand (one set of
flags for pre-commit, another for the PR gate, another for the release
gate). The CI YAML balloons fast; we collapse that into named files the
repo can review.

Usage
-----

Drop YAML files under ``policies/`` (or ``.pipeline-check/policies/``)::

    # policies/pre-merge.yml
    name: pre-merge
    description: PR gate -- full pack, HIGH-fail
    gate:
      fail_on: HIGH

    # policies/release-gate.yml
    name: release-gate
    description: release gate -- attestation rules on, MEDIUM-fail
    standards: [owasp_cicd_top_10, slsa]
    gate:
      fail_on: MEDIUM
    overrides:
      ATTEST-001:
        severity: CRITICAL

Then pick one per CI lane::

    pipeline_check --policy pre-merge
    pipeline_check --policy release-gate
    pipeline_check --list-policies

Precedence: policy values are *defaults*. Anything set by the config
file, environment variables, or explicit CLI flags wins over the
policy. That lets a single ``--max-failures 5`` on the command line
tighten the bar without rewriting the YAML.
"""
from __future__ import annotations

import hashlib
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ._yaml_strict import safe_load_strict as _safe_load_strict
from .checks.base import VALID_SEVERITY_NAMES as _VALID_SEVERITIES

#: Remote-policy fetch bounds. A policy pack is a small YAML file; the cap
#: protects against a pathological / hostile endpoint streaming gigabytes.
_POLICY_FETCH_TIMEOUT = 15.0
_MAX_POLICY_BYTES = 256 * 1024

#: Search roots, in priority order, for policy YAML files relative to
#: cwd. First existing directory wins; later directories are skipped so
#: a repo migrating from one layout to the other doesn't double-count.
POLICY_DIRS: tuple[str, ...] = (
    "policies",
    ".pipeline-check/policies",
)

_POLICY_SUFFIXES: tuple[str, ...] = (".yml", ".yaml")

_VALID_GRADES: frozenset[str] = frozenset({"A", "B", "C", "D"})

_GATE_KEYS: frozenset[str] = frozenset({
    "fail_on", "min_grade", "max_failures", "fail_on_checks",
})

_TOPLEVEL_KEYS: frozenset[str] = frozenset({
    "name", "description", "checks", "standards", "gate", "overrides",
})

#: Curated policy packs shipped with the tool, so the common compliance /
#: release gates work by name (``--policy slsa-l3``) without authoring a
#: file. Each entry uses the same schema as an on-disk policy and is
#: validated through the same loader. A local policy of the same name
#: (under :data:`POLICY_DIRS`) shadows the built-in. The ``standards``
#: filter only focuses finding annotation (the full rule pack still runs
#: and scores), so a framework pack narrows the compliance evidence
#: without reducing coverage.
BUILTIN_PACKS: dict[str, dict[str, Any]] = {
    "pr-gate": {
        "name": "pr-gate",
        "description": "Pre-merge gate: full rule pack, block on HIGH and CRITICAL.",
        "gate": {"fail_on": "HIGH"},
    },
    "release-gate": {
        "name": "release-gate",
        "description": "Release gate: block on MEDIUM+ and require grade B or better.",
        "gate": {"fail_on": "MEDIUM", "min_grade": "B"},
    },
    "slsa-l3": {
        "name": "slsa-l3",
        "description": "SLSA Build L3 focus: provenance, signing, isolation; block on HIGH+.",
        "standards": ["slsa", "owasp_cicd_top_10"],
        "gate": {"fail_on": "HIGH"},
    },
    "pci-dss": {
        "name": "pci-dss",
        "description": "PCI DSS v4.0 evidence run; block on HIGH+.",
        "standards": ["pci_dss_v4", "owasp_cicd_top_10"],
        "gate": {"fail_on": "HIGH"},
    },
    "supply-chain-strict": {
        "name": "supply-chain-strict",
        "description": (
            "Strict supply-chain gate: pinning, provenance, dependency "
            "integrity; block on MEDIUM+ and require grade B+."
        ),
        "standards": [
            "owasp_cicd_top_10", "slsa", "cis_supply_chain", "s2c2f",
        ],
        "gate": {"fail_on": "MEDIUM", "min_grade": "B"},
        # GHA-001 (third-party action not pinned to a SHA) is the
        # canonical pinning rule; a strict supply-chain gate treats an
        # unpinned action as a hard stop.
        "overrides": {"GHA-001": {"severity": "critical"}},
    },
}


class PolicyError(Exception):
    """A policy file could not be resolved or parsed."""


@dataclass(slots=True)
class Policy:
    """A named scan profile loaded from a YAML file.

    Attributes mirror the YAML schema directly. ``source`` is the path
    the policy was loaded from, useful for ``--list-policies`` and for
    error messages downstream.
    """

    name: str
    source: str
    description: str | None = None
    checks: tuple[str, ...] = ()
    standards: tuple[str, ...] = ()
    fail_on: str | None = None
    min_grade: str | None = None
    max_failures: int | None = None
    fail_on_checks: tuple[str, ...] = ()
    overrides: dict[str, dict[str, str]] = field(default_factory=dict)


def discover_policies(cwd: Path | None = None) -> list[Policy]:
    """Enumerate every readable policy under the first known search root.

    Walks :data:`POLICY_DIRS` in order; the first directory that exists
    wins, every ``.yml`` / ``.yaml`` file inside it is returned. Files
    that fail to parse are skipped with a stderr warning so one broken
    policy doesn't hide the rest from ``--list-policies``.
    """
    cwd = cwd or Path.cwd()
    for relative in POLICY_DIRS:
        base = cwd / relative
        if not base.is_dir():
            continue
        out: list[Policy] = []
        seen: set[str] = set()
        for path in sorted(base.iterdir()):
            if path.suffix.lower() not in _POLICY_SUFFIXES:
                continue
            stem = path.stem.lower()
            if stem in seen:
                # ``foo.yml`` and ``foo.yaml`` both present: keep the
                # first (alphabetical order puts .yaml after .yml).
                continue
            try:
                pol = _load_policy_file(path)
            except PolicyError as exc:
                print(f"[policy] skipping {path}: {exc}", file=sys.stderr)
                continue
            seen.add(stem)
            out.append(pol)
        return out
    return []


def load_policy(name_or_path: str, cwd: Path | None = None) -> Policy:
    """Resolve and load a policy by short name or by file path.

    Resolution order:

    0. ``name_or_path`` is an ``https://`` URL, fetch and load a shareable
       remote policy pack.
    1. ``name_or_path`` matches an existing file on disk, load it
       directly.
    2. Walk :data:`POLICY_DIRS` looking for ``<name>.yml`` /
       ``<name>.yaml``. First hit wins.
    3. A built-in pack of that name.

    Raises :class:`PolicyError` when no candidate matches or the YAML
    parse / shape check fails.
    """
    if name_or_path.lower().startswith(("https://", "http://")):
        return _load_policy_url(name_or_path)
    cwd = cwd or Path.cwd()
    p = Path(name_or_path)
    if p.is_file():
        return _load_policy_file(p)
    name = p.name.strip()
    if not name:
        raise PolicyError(f"empty policy name: {name_or_path!r}")
    # Reject path-traversal smuggling. A bare name shouldn't contain
    # separators or ``..``; if the caller really has a file, they
    # should pass the path verbatim (handled by step 1 above).
    if any(sep in name for sep in ("/", "\\")) or ".." in name:
        raise PolicyError(
            f"policy name {name!r} must be a bare identifier; "
            f"pass a path to load a file directly"
        )
    for relative in POLICY_DIRS:
        base = cwd / relative
        if not base.is_dir():
            continue
        for suffix in _POLICY_SUFFIXES:
            candidate = base / f"{name}{suffix}"
            if candidate.is_file():
                return _load_policy_file(candidate)
    builtin = _builtin_policy(name)
    if builtin is not None:
        return builtin
    raise PolicyError(
        f"policy {name!r} not found in any of: "
        + ", ".join(POLICY_DIRS)
        + f"; built-in packs: {', '.join(sorted(BUILTIN_PACKS))}"
    )


def policy_to_config_map(policy: Policy) -> dict[str, Any]:
    """Convert a Policy into the click ``default_map`` shape.

    The returned dict maps click option names (e.g. ``"fail_on"``) to
    values. Merge this into ``ctx.default_map`` to make the policy the
    baseline for every option that isn't overridden by the config file,
    environment, or an explicit CLI flag.

    ``overrides`` is *not* included here because click has no
    ``--overrides`` option; the CLI pulls them off the ``Policy``
    object directly and merges with the config-file overrides.
    """
    out: dict[str, Any] = {}
    if policy.checks:
        out["checks"] = tuple(policy.checks)
    if policy.standards:
        out["standards"] = tuple(policy.standards)
    if policy.fail_on:
        out["fail_on"] = policy.fail_on
    if policy.min_grade:
        out["min_grade"] = policy.min_grade
    if policy.max_failures is not None:
        out["max_failures"] = policy.max_failures
    if policy.fail_on_checks:
        out["fail_on_checks"] = tuple(policy.fail_on_checks)
    return out


def _builtin_policy(name: str) -> Policy | None:
    """Build the built-in pack named *name*, or ``None`` if there isn't one.

    Routed through :func:`_from_dict` so a pack is validated exactly like
    an on-disk policy (a malformed severity / grade in :data:`BUILTIN_PACKS`
    trips the same checks, caught by the test suite).
    """
    raw = BUILTIN_PACKS.get(name)
    if raw is None:
        return None
    # Copy so the loader can't mutate the shared constant.
    return _from_dict(dict(raw), Path(f"<built-in:{name}>"))


def builtin_policies() -> list[Policy]:
    """Every built-in pack, in declaration order. Used by ``--list-policies``."""
    out: list[Policy] = []
    for name in BUILTIN_PACKS:
        pol = _builtin_policy(name)
        if pol is not None:
            out.append(pol)
    return out


# ────────────────────────────────────────────────────────────────────────────
# Internal: file loading and schema coercion.
# ────────────────────────────────────────────────────────────────────────────


def _policy_cache_dir() -> Path:
    """Cache directory for fetched remote policy packs."""
    try:
        import platformdirs

        base = Path(platformdirs.user_cache_dir("pipeline-check"))
    except Exception:
        base = Path.home() / ".cache" / "pipeline-check"
    return base / "policies"


def _load_policy_url(url: str) -> Policy:
    """Fetch and load a shareable policy pack from an ``https://`` URL.

    HTTPS only (the fetch reuses the redirect-hardened opener that the
    other remote resolvers use). The response is size-capped, validated
    through the same schema loader as an on-disk policy, and cached so a
    later offline run still resolves the gate. A successful fetch always
    refreshes the cache; the cache is only read back when the network
    fetch fails.

    A remote policy can only *configure the gate* (thresholds, rule
    filters, severity overrides), never run code, but note that it can
    also *weaken* the gate, so the source URL is printed by the CLI when
    a policy loads.
    """
    if not url.lower().startswith("https://"):
        raise PolicyError(
            f"a remote policy must be fetched over https; refused: {url}"
        )
    cache = _policy_cache_dir() / (
        hashlib.sha256(url.encode("utf-8")).hexdigest() + ".yml"
    )
    text: str | None = None
    raw_bytes: bytes | None = None
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "pipeline-check"}
        )
        from .checks._primitives.safe_http import urlopen_https_only

        with urlopen_https_only(req, timeout=_POLICY_FETCH_TIMEOUT) as resp:
            raw_bytes = resp.read(_MAX_POLICY_BYTES + 1)
        if len(raw_bytes) > _MAX_POLICY_BYTES:
            raise PolicyError(
                f"remote policy is too large (> {_MAX_POLICY_BYTES} bytes): {url}"
            )
    except (urllib.error.URLError, OSError) as exc:
        # Network failure: fall back to the last good cached copy if any.
        if cache.is_file():
            text = cache.read_text(encoding="utf-8")
        else:
            raise PolicyError(
                f"could not fetch remote policy {url}: {exc}"
            ) from exc

    if raw_bytes is not None:
        # A successful fetch that isn't valid UTF-8 is a bad response, not a
        # network failure, so surface it rather than silently serving a stale
        # cached copy (which could mask a changed or hijacked endpoint).
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PolicyError(
                f"remote policy {url} is not valid UTF-8: {exc}"
            ) from exc
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(text, encoding="utf-8")
        except OSError:
            pass  # caching is best-effort
    if text is None:
        # Unreachable: a successful fetch decodes into text, a failed fetch
        # either restored it from cache or raised. Guards the type narrowing.
        raise PolicyError(f"could not resolve remote policy {url}")
    try:
        raw = _safe_load_strict(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"could not parse remote policy {url}: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(
            f"remote policy {url}: top-level value must be a mapping"
        )
    pol = _from_dict(raw, Path(url))
    # ``str(Path(url))`` collapses ``//`` to ``/``; keep the verbatim URL
    # so the ``[policy] loaded … from <url>`` notice is accurate.
    pol.source = url
    return pol


def _load_policy_file(path: Path) -> Policy:
    try:
        raw = _safe_load_strict(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"could not parse {path}: {exc}") from exc
    if raw is None:
        raise PolicyError(f"{path}: file is empty")
    if not isinstance(raw, dict):
        raise PolicyError(
            f"{path}: top-level value must be a mapping, got "
            f"{type(raw).__name__}"
        )
    return _from_dict(raw, path)


def _from_dict(raw: dict[str, Any], path: Path) -> Policy:
    unknown = set(raw) - _TOPLEVEL_KEYS
    for key in sorted(unknown):
        print(
            f"[policy] ignoring unknown key {key!r} in {path}",
            file=sys.stderr,
        )

    name_raw = raw.get("name") or path.stem
    if not isinstance(name_raw, str) or not name_raw.strip():
        raise PolicyError(f"{path}: 'name' must be a non-empty string")
    name = name_raw.strip()

    description_raw = raw.get("description")
    description: str | None
    if description_raw is None:
        description = None
    elif isinstance(description_raw, str):
        description = description_raw.strip() or None
    else:
        raise PolicyError(
            f"{path}: 'description' must be a string, got "
            f"{type(description_raw).__name__}"
        )

    checks = _coerce_id_list(raw.get("checks"), path, "checks")
    standards = _coerce_id_list(
        raw.get("standards"), path, "standards", upper=False,
    )

    gate_raw = raw.get("gate")
    if gate_raw is None:
        fail_on = min_grade = None
        max_failures = None
        fail_on_checks: tuple[str, ...] = ()
    else:
        if not isinstance(gate_raw, dict):
            raise PolicyError(
                f"{path}: 'gate' must be a mapping, got "
                f"{type(gate_raw).__name__}"
            )
        gate_unknown = set(gate_raw) - _GATE_KEYS
        for key in sorted(gate_unknown):
            print(
                f"[policy] ignoring unknown gate key {key!r} in {path}",
                file=sys.stderr,
            )
        fail_on = _coerce_severity(
            gate_raw.get("fail_on"), path, "gate.fail_on",
        )
        min_grade = _coerce_grade(gate_raw.get("min_grade"), path)
        max_failures = _coerce_int(gate_raw.get("max_failures"), path)
        fail_on_checks = _coerce_id_list(
            gate_raw.get("fail_on_checks"), path, "gate.fail_on_checks",
        )

    overrides = _coerce_overrides(raw.get("overrides"), path)

    return Policy(
        name=name,
        source=str(path),
        description=description,
        checks=checks,
        standards=standards,
        fail_on=fail_on,
        min_grade=min_grade,
        max_failures=max_failures,
        fail_on_checks=fail_on_checks,
        overrides=overrides,
    )


def _coerce_id_list(
    raw: Any, path: Path, key: str, upper: bool = True,
) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise PolicyError(
            f"{path}: {key!r} must be a list, got {type(raw).__name__}"
        )
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            continue
        s = item.strip()
        if not s:
            continue
        out.append(s.upper() if upper else s)
    return tuple(out)


def _coerce_severity(raw: Any, path: Path, key: str) -> str | None:
    if raw is None:
        return None
    s = str(raw).upper().strip()
    if s not in _VALID_SEVERITIES:
        raise PolicyError(
            f"{path}: {key} {raw!r} is not one of "
            f"{sorted(_VALID_SEVERITIES)}"
        )
    return s


def _coerce_grade(raw: Any, path: Path) -> str | None:
    if raw is None:
        return None
    s = str(raw).upper().strip()
    if s not in _VALID_GRADES:
        raise PolicyError(
            f"{path}: gate.min_grade {raw!r} must be one of "
            f"{sorted(_VALID_GRADES)}"
        )
    return s


def _coerce_int(raw: Any, path: Path) -> int | None:
    if raw is None:
        return None
    # ``bool`` is a subclass of ``int`` in Python; reject explicitly so
    # ``max_failures: true`` doesn't silently become ``1``.
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise PolicyError(
            f"{path}: gate.max_failures {raw!r} must be a non-negative integer"
        )
    # ``raw`` is now an int (not bool); the narrowing above doesn't
    # tell mypy that, so the explicit ``int()`` round-trip keeps the
    # return type concrete without changing runtime semantics.
    value = int(raw)
    if value < 0:
        raise PolicyError(
            f"{path}: gate.max_failures must be non-negative, got {value}"
        )
    return value


def _coerce_overrides(raw: Any, path: Path) -> dict[str, dict[str, str]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PolicyError(
            f"{path}: 'overrides' must be a mapping, got "
            f"{type(raw).__name__}"
        )
    out: dict[str, dict[str, str]] = {}
    for cid, body in raw.items():
        if not isinstance(cid, str) or not cid.strip():
            continue
        if not isinstance(body, dict):
            print(
                f"[policy] ignoring overrides[{cid!r}] in {path}: "
                f"value must be a mapping",
                file=sys.stderr,
            )
            continue
        normalized: dict[str, str] = {}
        sev = body.get("severity")
        if sev is not None:
            s = str(sev).upper().strip()
            if s in _VALID_SEVERITIES:
                normalized["severity"] = s
            else:
                print(
                    f"[policy] ignoring overrides[{cid!r}].severity in "
                    f"{path}: {sev!r} not in "
                    f"{sorted(_VALID_SEVERITIES)}",
                    file=sys.stderr,
                )
        unknown = set(body) - {"severity"}
        for k in sorted(unknown):
            print(
                f"[policy] ignoring overrides[{cid!r}].{k} in {path}: "
                f"unknown sub-key (only 'severity' is supported today)",
                file=sys.stderr,
            )
        if normalized:
            out[cid.upper().strip()] = normalized
    return out
