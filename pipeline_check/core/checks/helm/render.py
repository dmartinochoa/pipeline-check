"""Helm chart rendering shim.

Shells out to the local ``helm`` binary (Helm 3) to render a chart
into a multi-doc Kubernetes manifest stream. The rendered text is
fed through ``KubernetesContext.from_yaml_stream`` so the existing
K8s rule pack can score it without modification.

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


class HelmRenderError(RuntimeError):
    """Raised when ``helm template`` cannot produce manifests.

    Carries the original stderr text so the caller can surface it as
    a scan-time warning or a synthetic finding without re-invoking
    the binary.
    """

    def __init__(self, message: str, stderr: str = "") -> None:
        super().__init__(message)
        self.stderr = stderr


@dataclass(frozen=True)
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
    Helm 2 — the v2 / v3 boundary is the load-bearing one.
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
            timeout=10,
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
            # First non-comment, non-blank line — no Source: header
            # in this segment.
            break
        out.append(match)
    return out


__all__ = [
    "HelmRenderError",
    "RenderResult",
    "helm_available",
    "helm_version",
    "render_chart",
]
