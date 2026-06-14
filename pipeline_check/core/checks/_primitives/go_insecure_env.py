"""Shared detection for CI env settings that disable Go module verification.

Reused by per-provider rules (GHA-110, GL-037, CC-033) that flag a CI
pipeline setting one of the Go toolchain's integrity-disabling
environment variables, the env-var twin of GOMOD-001 (a ``go.sum`` is
committed but the runner is told to ignore it).

Two entry points, mirroring how each provider exposes configuration:

* :func:`insecure_settings_in_env` takes a declared env / variables
  map (``{NAME: value}``) from a workflow / job / step scope.
* :func:`insecure_settings_in_script` takes a shell ``run:`` body and
  extracts ``export NAME=VALUE`` and ``NAME=VALUE cmd`` assignments.

Both return a list of short human-readable labels describing each
offending setting; an empty list means clean.

Detection (all HIGH-signal, the build can no longer prove a downloaded
module matches what ``go.sum`` / the checksum database recorded):

* ``GOFLAGS`` containing ``-insecure`` (fetch modules over plain HTTP,
  TLS validation skipped).
* ``GOSUMDB=off`` (the checksum transparency database is disabled).
* ``GONOSUMCHECK`` truthy (legacy switch that skips the sum check).
* ``GOINSECURE=<glob>`` (insecure HTTP fetch for matching modules).
* ``GOPRIVATE`` / ``GONOSUMDB`` set to a *broad* glob (``*``, a public
  TLD wildcard, or a whole public host), which turns the proxy + sum-db
  off for everything rather than a scoped internal namespace. A scoped
  value (``corp.example.com/team/*``) is the normal private-module
  config and is not flagged (the GOMOD-014 over-broad-glob angle).

``GOPROXY`` is deliberately not flagged: ``off`` is restrictive (no
network fetch) and ``direct`` still verifies against ``go.sum`` /
the sum database, so neither is an integrity bypass on its own.
"""
from __future__ import annotations

import re

_TRUTHY = {"1", "true", "on", "yes"}

# ``export FOO=bar``, a leading ``FOO=bar cmd`` env-prefix, and the
# persistent ``go env -w FOO=bar`` form (which writes the setting into
# the Go env config, the canonical way to disable verification durably).
# Value is captured up to whitespace / quote close; quoted values are
# unwrapped by the caller-side strip.
_EXPORT_RE = re.compile(
    r"(?:^|;|&&|\|\||\bexport\s+|\bgo\s+env\s+-w\s+)\s*"
    r"(?P<name>GO[A-Z_]+)\s*=\s*"
    r"(?P<value>\"[^\"]*\"|'[^']*'|\S*)",
    re.MULTILINE,
)


def _truthy(value: str) -> bool:
    return value.strip().strip("\"'").lower() in _TRUTHY


def _is_broad_glob(value: str) -> bool:
    """Return ``True`` when a ``GOPRIVATE`` / ``GOINSECURE`` /
    ``GONOSUMDB`` glob covers everything or a whole public host, rather
    than a scoped internal namespace.

    Broad: ``*``; any comma element that is ``*``; a public TLD wildcard
    (``*.com``); or a host with a single trailing ``/*`` (``github.com/*``,
    the entire host). Scoped (``host/org/*`` or deeper) is not broad.
    """
    for raw in value.replace("\"", "").replace("'", "").split(","):
        elem = raw.strip()
        if not elem:
            continue
        if elem == "*":
            return True
        if elem.startswith("*"):  # *.com, *foo
            return True
        # host[/seg...]/* is broad only when the wildcard sits at the
        # host level (host/*), i.e. one path segment before the /*.
        if elem.endswith("/*"):
            segments = elem[:-2].split("/")
            if len(segments) <= 1:
                return True
    return False


def _classify(name: str, value: str) -> str | None:
    """Return an offender label for one ``NAME=value`` setting, else None."""
    name = name.strip().upper()
    val = value.strip().strip("\"'")
    low = val.lower()
    if name == "GOFLAGS" and "-insecure" in val:
        return "GOFLAGS=-insecure (modules fetched over plain HTTP, TLS off)"
    if name == "GOSUMDB" and low == "off":
        return "GOSUMDB=off (checksum transparency database disabled)"
    if name == "GONOSUMCHECK" and _truthy(val):
        return "GONOSUMCHECK set (module sum check disabled)"
    if name == "GOINSECURE" and val:
        return f"GOINSECURE={val} (insecure HTTP fetch for matching modules)"
    if name == "GOPRIVATE" and _is_broad_glob(val):
        return f"GOPRIVATE={val} (proxy + sum-db skipped for all matching)"
    if name == "GONOSUMDB" and _is_broad_glob(val):
        return f"GONOSUMDB={val} (sum-db check skipped for all matching)"
    return None


def insecure_settings_in_env(env: object) -> list[str]:
    """Return offender labels for a declared env / variables map.

    Accepts any mapping of ``{NAME: value}``; non-dict input (or
    non-string keys / values) is ignored so a malformed document
    doesn't raise.
    """
    if not isinstance(env, dict):
        return []
    out: list[str] = []
    for name, value in env.items():
        if not isinstance(name, str):
            continue
        # Coerce scalars (YAML may load ``off`` as a bool, ``1`` as int).
        text = value if isinstance(value, str) else _scalar_text(value)
        label = _classify(name, text)
        if label is not None:
            out.append(label)
    return out


def _scalar_text(value: object) -> str:
    # YAML 1.1 coerces bareword ``off``/``no``/``false`` → False and
    # ``on``/``yes``/``true`` → True, while a quoted "off" stays a
    # string. ``GOSUMDB: off`` (the disabling form) therefore arrives
    # as False, so map False → "off"; True → "true" feeds the
    # GONOSUMCHECK truthy check.
    if value is True:
        return "true"
    if value is False:
        return "off"
    if isinstance(value, (int, float)):
        return str(value)
    return ""


_COMMENT_RE = re.compile(r"(?m)(?:^|(?<=\s))#[^\n]*")


def _strip_shell_comments(script: str) -> str:
    """Remove shell comments (``# ...`` through end of line) from *script*.

    Only strips a ``#`` that is either at the start of a line or preceded
    by whitespace, which excludes ``#`` inside strings and URL fragments
    (``https://host/path#anchor``). This is an approximation sufficient
    for the CI-script patterns the primitive targets.
    """
    return _COMMENT_RE.sub("", script)


def insecure_settings_in_script(script: str) -> list[str]:
    """Return offender labels for ``export NAME=VALUE`` / ``NAME=VALUE cmd``
    assignments found in a shell ``run:`` body."""
    clean = _strip_shell_comments(script)
    out: list[str] = []
    for m in _EXPORT_RE.finditer(clean):
        label = _classify(m.group("name"), m.group("value"))
        if label is not None:
            out.append(label)
    return out
