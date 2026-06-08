"""Helm chart rendering shim.

Shells out to the local ``helm`` binary (Helm 3) to render a chart
into a multi-doc Kubernetes manifest stream. The rendered text is
fed through ``KubernetesContext.from_yaml_stream`` so the existing
K8s rule pack can score it without modification.

User-supplied ``--helm-set KEY=VALUE`` strings are validated before
they reach ``helm template``: the keys must match Helm's documented
path syntax (alphanumeric, dot, bracket-index, dash, underscore) and
the values must not contain unescaped helm ``--set`` separators
(``,``) or shell-injection-flavored metacharacters (``$()``, backticks,
embedded newlines). The subprocess is invoked with a list argv so
the local shell never sees the value, but ``helm`` itself parses
``--set`` strings with its own separator rules; rejecting metachars
up front prevents a single override smuggling additional fields into
the rendered manifest.

Helm 2 is rejected on principle: it has been EOL since November 2020
and its server-side ``tiller`` model isn't representative of how
charts get rendered in modern CI pipelines.

The renderer parses ``# Source: <chart>/templates/<file>.yaml``
comments that ``helm template`` injects above each rendered doc and
returns the per-doc list aligned with the YAML stream order. The K8s
``Manifest.source_template`` field surfaces this in finding output
so a "privileged container" report points at the actual template
file rather than ``<rendered>``.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import yaml


class HelmRenderError(RuntimeError):
    """Raised when ``helm template`` cannot produce manifests.

    Carries the original stderr text so the caller can surface it as
    a scan-time warning or a synthetic finding without re-invoking
    the binary.
    """

    def __init__(self, message: str, stderr: str = "") -> None:
        super().__init__(message)
        self.stderr = stderr


# Helm's documented key syntax: alphanumerics, dot for object paths,
# brackets for list indices, underscore, and dash. Anything else (a
# bare space, a comma, a backtick, etc.) is rejected so a malicious
# override can't smuggle a second override past helm's ``--set`` parser.
_HELM_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\[\]\-]*$")
# Values are looser, but a tight blocklist on the characters that
# would either split helm's parser (``,``) or escape into shell-like
# expansions (`` ` ``, ``$(``, ``$``, newlines, ``;``) is enough to
# catch the smuggling shapes without breaking legitimate values like
# image tags or numeric replicas. ``\\`` (helm's escape character)
# is also rejected because we don't try to interpret it.
_HELM_VALUE_BAD_RE = re.compile(r"[,`;\n\r]|\$\(|\\\\")


def _validate_set_overrides(set_overrides: list[str] | None) -> None:
    """Reject ``--helm-set KEY=VALUE`` entries with metacharacters
    that would let one override smuggle others past helm's ``--set``
    parser. Raises :class:`HelmRenderError` on the first bad entry."""
    for kv in set_overrides or ():
        if "=" not in kv:
            raise HelmRenderError(
                f"--helm-set {kv!r} is not a KEY=VALUE pair"
            )
        key, _, value = kv.partition("=")
        if not _HELM_KEY_RE.match(key):
            raise HelmRenderError(
                f"--helm-set key {key!r} contains unsafe characters; "
                f"allowed: letters, digits, dot, dash, underscore, "
                f"brackets for list indices"
            )
        if _HELM_VALUE_BAD_RE.search(value):
            raise HelmRenderError(
                f"--helm-set value for {key!r} contains a metacharacter "
                f"(``,`` / backtick / ``$(`` / ``;`` / newline / ``\\\\``) "
                f"that would interact with helm's --set parser or a shell"
            )


@dataclass(frozen=True, slots=True)
class RenderResult:
    """Output of one ``helm template`` invocation."""

    yaml: str
    #: Per-doc list aligned with ``yaml.safe_load_all(yaml)`` ordering.
    #: Each entry is the chart-relative template path that produced
    #: the doc, or ``None`` for docs without a recognizable
    #: ``# Source:`` header.
    source_templates: list[str | None]


_SOURCE_RE = re.compile(r"^#\s*Source:\s*(\S+)\s*$")
_DOC_DELIM = re.compile(r"^---\s*$", re.MULTILINE)


def helm_available() -> str | None:
    """Return the path to the ``helm`` binary, or ``None`` if absent."""
    return shutil.which("helm")


def helm_version() -> str:
    """Return the major version digit reported by ``helm version --short``.

    Raises HelmRenderError if the binary is missing or its output
    isn't parseable. The major-version split is enough to reject
    Helm 2, the v2 / v3 boundary is the load-bearing one.
    """
    binary = helm_available()
    if not binary:
        raise HelmRenderError(
            "helm binary not found on PATH. Install Helm 3 from "
            "https://helm.sh/docs/intro/install/."
        )
    try:
        proc = subprocess.run(
            [binary, "version", "--short"],
            capture_output=True,
            text=True,
            # Cold runs on Windows CI can spend most of this budget in
            # Defender scanning helm.exe before the process even starts;
            # 30s is a comfortable ceiling without making real failures
            # feel hung.
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HelmRenderError(f"helm version probe failed: {exc}") from exc
    out = (proc.stdout or proc.stderr).strip()
    # Output examples: "v3.13.2+g2a2fb3b", "Client: v2.17.0+gxyz".
    match = re.search(r"v(\d+)\.\d+", out)
    if not match:
        raise HelmRenderError(
            f"could not parse helm version from output: {out!r}"
        )
    major = match.group(1)
    if major == "2":
        raise HelmRenderError(
            "Helm 2 is not supported. Helm 2 has been EOL since "
            "November 2020. Upgrade to Helm 3."
        )
    return major


def render_chart(
    chart_path: str | Path,
    values_files: list[str] | None = None,
    set_overrides: list[str] | None = None,
    release_name: str = "pipeline-check",
    namespace: str = "default",
    timeout_seconds: int = 60,
) -> RenderResult:
    """Render *chart_path* via ``helm template`` and return the YAML stream.

    Parameters
    ----------
    chart_path:
        Directory containing ``Chart.yaml`` (or a packaged ``.tgz``).
    values_files:
        Optional list of ``-f`` value-file arguments forwarded verbatim.
    set_overrides:
        Optional list of ``--set KEY=VALUE`` arguments forwarded verbatim.
        Each list entry should be a single ``key=value`` pair; the caller
        is responsible for the syntax helm expects.
    release_name:
        Synthetic release name. Templates that use ``.Release.Name``
        will see this string. The default is intentionally identifiable
        so rendered output that leaks into logs is recognizable as a
        scanner artifact.
    namespace:
        Synthetic install namespace. ``"default"`` matches what most
        charts assume when no namespace is configured.
    timeout_seconds:
        Hard cap on the helm subprocess. Generous default so big
        charts don't false-fail; lower it for hot-loop scans.
    """
    binary = helm_available()
    if not binary:
        raise HelmRenderError(
            "helm binary not found on PATH. Install Helm 3 from "
            "https://helm.sh/docs/intro/install/."
        )
    # Probe the version once per call. Cheap (sub-100ms locally) and
    # gives a clean error before we hand a chart to a Helm 2 binary.
    helm_version()

    chart = Path(chart_path)
    if not chart.exists():
        raise HelmRenderError(
            f"--helm-path {chart} does not exist. Pass a chart "
            "directory (one containing Chart.yaml) or a packaged "
            "chart .tgz."
        )

    # Defensive: reject ``--helm-set`` entries with metacharacters that
    # would interact with helm's --set parser or a shell. See the
    # module docstring for the threat shape.
    _validate_set_overrides(set_overrides)

    cmd: list[str] = [
        binary, "template", release_name, str(chart),
        "--namespace", namespace,
    ]
    for vf in values_files or ():
        cmd.extend(["-f", vf])
    for kv in set_overrides or ():
        cmd.extend(["--set", kv])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise HelmRenderError(
            f"helm template timed out after {timeout_seconds}s"
        ) from exc
    except OSError as exc:
        raise HelmRenderError(f"helm template invocation failed: {exc}") from exc

    if proc.returncode != 0:
        # helm puts the actionable error on stderr; surface its first
        # non-empty line so the user can see the template error.
        first_err = next(
            (line for line in (proc.stderr or "").splitlines() if line.strip()),
            "(no stderr)",
        )
        raise HelmRenderError(
            f"helm template failed: {first_err}",
            stderr=proc.stderr or "",
        )

    yaml_text = proc.stdout or ""
    sources = _extract_source_templates(yaml_text)
    return RenderResult(yaml=yaml_text, source_templates=sources)


def _extract_source_templates(yaml_text: str) -> list[str | None]:
    """Parse ``# Source:`` headers, one per ``---``-separated doc.

    ``helm template`` emits a stream like:

        ---
        # Source: mychart/templates/serviceaccount.yaml
        apiVersion: v1
        kind: ServiceAccount
        ...
        ---
        # Source: mychart/templates/deployment.yaml
        apiVersion: apps/v1
        kind: Deployment
        ...

    The split aligns with ``yaml.safe_load_all`` because both consume
    ``---`` document separators identically. A leading ``---`` (or its
    absence) yields an empty first segment that ``safe_load_all``
    elides as ``None``; we drop empty segments here too so the index
    alignment stays correct.
    """
    out: list[str | None] = []
    segments = _DOC_DELIM.split(yaml_text)
    for seg in segments:
        # Skip entirely blank/whitespace segments. ``safe_load_all``
        # yields ``None`` for these and they're filtered out before
        # the K8s manifest converter sees them, so we must skip them
        # here too to keep the per-doc index alignment.
        if not seg.strip():
            continue
        match = None
        for line in seg.splitlines():
            stripped = line.lstrip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                m = _SOURCE_RE.match(stripped)
                if m:
                    match = m.group(1)
                    break
                # Other comment lines may precede the Source: marker;
                # keep scanning.
                continue
            # First non-comment, non-blank line, no Source: header
            # in this segment.
            break
        out.append(match)
    return out


# ── Offline fallback (no helm binary) ────────────────────────────

# A Go-template action ``{{ ... }}`` (non-greedy, single line). Helm
# templates are overwhelmingly single-line actions; a multi-line action
# leaves a stray brace that makes its document fail to parse, which the
# caller drops per-document.
_TEMPLATE_ACTION_RE = re.compile(r"\{\{.*?\}\}")
# Placeholder substituted for an inline action that contributes a value
# (``name: {{ .Release.Name }}`` -> ``name: pipelinecheck``). A bare word
# is a valid YAML scalar as a string, and is read as a string in
# numeric / bool positions, which the K8s rules tolerate.
_TEMPLATE_PLACEHOLDER = "pipelinecheck"


def _neutralize_template(text: str) -> str:
    """Best-effort strip of Go-template syntax so a chart template parses
    as plain YAML without the ``helm`` binary.

    Two line shapes:

    * Lines that are ONLY a template action once the braces are removed
      (control flow like ``{{- if .Values.x }}`` / ``{{ end }}`` /
      ``{{ range }}``, or a standalone expression) are dropped. Dropping
      ``if`` / ``end`` keeps the guarded block unconditionally, which is
      what a static security scan wants: it sees the dangerous branch.
    * Lines mixing literal YAML with an inline action
      (``name: {{ .Release.Name }}-x``) keep the literal and replace the
      action with a placeholder scalar.

    This recovers literal ``securityContext`` / ``hostPath`` /
    ``privileged`` fields, which is where the security signal lives.
    Heavily-templated structure (``{{ toYaml .Values.resources | nindent
    8 }}``) collapses to a placeholder, which is acceptable for a static
    scan.
    """
    out: list[str] = []
    for line in text.splitlines():
        had_action = "{{" in line
        bare = _TEMPLATE_ACTION_RE.sub("", line).strip()
        if had_action and bare in ("", "-"):
            # Control-only or pure-expression line: drop it.
            continue
        out.append(_TEMPLATE_ACTION_RE.sub(_TEMPLATE_PLACEHOLDER, line))
    return "\n".join(out)


def render_chart_offline(chart_path: str | Path) -> RenderResult:
    """Parse a chart's ``templates/*.yaml`` WITHOUT the helm binary.

    Fallback for environments where ``helm`` isn't installed (most CI
    images, many dev machines). Go-template expressions are neutralized
    (see :func:`_neutralize_template`) and each template file is parsed
    independently so one un-parseable file doesn't sink the rest. The
    output mirrors ``helm template``'s ``# Source:``-headed multi-doc
    stream so the source-template parser and the K8s rule pack run
    unchanged.

    Raises :class:`HelmRenderError` when the chart has no ``templates/``
    directory or no template file survives neutralization + parse.
    """
    chart = Path(chart_path)
    templates_dir = chart / "templates"
    if not templates_dir.is_dir():
        raise HelmRenderError(
            f"{chart}: no templates/ directory for offline parse"
        )
    parts: list[str] = []
    for tpl in sorted(templates_dir.rglob("*.y*ml")):
        if not tpl.is_file():
            continue
        try:
            raw = tpl.read_text(encoding="utf-8")
        except OSError:
            continue
        neutralized = _neutralize_template(raw)
        if not neutralized.strip():
            continue
        # Drop files that still don't parse (multi-line actions, helm
        # named-template includes, ...) rather than failing the chart.
        try:
            list(yaml.safe_load_all(neutralized))
        except (yaml.YAMLError, RecursionError, MemoryError):
            continue
        rel = tpl.relative_to(chart).as_posix()
        parts.append(f"# Source: {chart.name}/{rel}\n{neutralized}")
    if not parts:
        raise HelmRenderError(
            f"{chart}: offline parse produced no usable manifests"
        )
    yaml_text = "\n---\n".join(parts)
    return RenderResult(
        yaml=yaml_text,
        source_templates=_extract_source_templates(yaml_text),
    )


__all__ = [
    "HelmRenderError",
    "RenderResult",
    "helm_available",
    "helm_version",
    "render_chart",
    "render_chart_offline",
]
