"""Helm chart context.

Composes a :class:`KubernetesContext` from one or more rendered Helm
charts. The helm provider returns this context so the existing K8s
rule pack runs unmodified — every K8S-* check sees the rendered
manifests as if they had been read off disk.

Each chart referenced by ``--helm-path`` is rendered once via
``helm template``. A repo with multiple charts can either be scanned
chart-by-chart, or by pointing at the parent directory: in the
parent-dir case we walk for every ``Chart.yaml`` at depth ≤ 2 (so
``charts/myapp/Chart.yaml`` is picked up, but a vendored
``charts/myapp/charts/redis/Chart.yaml`` subchart is not). The
subchart is still rendered as part of its parent — Helm handles the
dependency recursion — so skipping it here just avoids rendering
the same content twice.
"""
from __future__ import annotations

from pathlib import Path

from ..kubernetes.base import KubernetesContext, Manifest
from .render import HelmRenderError, render_chart


class HelmContext(KubernetesContext):
    """KubernetesContext sourced from one or more rendered Helm charts.

    Subclasses ``KubernetesContext`` so the existing
    ``KubernetesManifestChecks`` orchestrator (and every K8S-* rule)
    accepts it without isinstance checks.
    """

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        values_files: list[str] | None = None,
        set_overrides: list[str] | None = None,
    ) -> HelmContext:
        """Render the chart(s) at *path* and parse the resulting stream.

        *path* is either a chart directory (one containing
        ``Chart.yaml``), a packaged ``.tgz`` chart, or a parent
        directory holding multiple charts (one ``Chart.yaml`` per
        immediate subdirectory).

        Render failures don't raise out of context construction — they
        land in ``ctx.warnings`` so the scanner can finish and surface
        a clean "chart X failed to render" warning alongside whatever
        other charts succeeded.
        """
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--helm-path {root} does not exist. Pass a chart "
                "directory (one containing Chart.yaml), a packaged "
                "chart .tgz, or a parent directory holding multiple "
                "charts."
            )

        chart_paths = _discover_charts(root)
        if not chart_paths:
            raise ValueError(
                f"--helm-path {root} contains no Chart.yaml. Pass a "
                "chart directory or a parent directory holding charts."
            )

        manifests: list[Manifest] = []
        warnings: list[str] = []
        scanned = 0
        skipped = 0
        for chart in chart_paths:
            try:
                result = render_chart(
                    chart,
                    values_files=values_files,
                    set_overrides=set_overrides,
                )
            except HelmRenderError as exc:
                warnings.append(f"{chart}: helm render failed: {exc}")
                skipped += 1
                continue
            sub = KubernetesContext.from_yaml_stream(
                result.yaml,
                path_hint=str(chart),
                source_templates=result.source_templates,
            )
            warnings.extend(sub.warnings)
            manifests.extend(sub.manifests)
            scanned += 1
        ctx = cls(manifests)
        ctx.files_scanned = scanned
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


def _discover_charts(root: Path) -> list[Path]:
    """Return the list of chart directories (or .tgz files) to render.

    Three input shapes:

    1. *root* is a ``Chart.yaml``-bearing directory → render it.
    2. *root* is a ``.tgz`` file → pass through; helm renders packaged
       charts directly.
    3. *root* is a directory without ``Chart.yaml`` → look one level
       down for any subdirectory that has its own ``Chart.yaml``.
    """
    if root.is_file():
        if root.suffix.lower() == ".tgz":
            return [root]
        return []
    if (root / "Chart.yaml").is_file():
        return [root]
    out: list[Path] = []
    for child in sorted(root.iterdir()):
        if child.is_dir() and (child / "Chart.yaml").is_file():
            out.append(child)
    return out


__all__ = ["HelmContext"]
