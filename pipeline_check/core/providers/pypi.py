"""pypi provider, scans requirements*.txt / *.in on disk.

    pipeline_check --pipeline pypi --pypi-path path/to/requirements.txt

No registry pull, no install, no PyPI API access; text-only static
analysis of pip requirements file shapes.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.pypi.base import PypiContext
from ..checks.pypi.pipelines import PypiChecks
from ..inventory import Component
from .base import BaseProvider


class PypiProvider(BaseProvider):
    """pypi provider, parses pip requirements files."""

    NAME = "pypi"

    def build_context(
        self,
        pypi_path: str | None = None,
        **_: Any,
    ) -> PypiContext:
        if not pypi_path:
            raise ValueError(
                "The pypi provider requires --pypi-path <file-or-dir> "
                "pointing at a requirements.txt or a directory "
                "containing one."
            )
        return PypiContext.from_path(pypi_path)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [PypiChecks]

    def inventory(self, context: PypiContext) -> list[Component]:
        out: list[Component] = []
        for rf in context.files:
            metadata: dict[str, Any] = {
                "kind": "requirements.txt",
                "requirement_count": len(rf.lines),
                "option_count": len(rf.options),
            }
            out.append(Component(
                provider=self.NAME, type="requirements.txt",
                identifier=rf.path, source=rf.path, metadata=metadata,
            ))
        return out
