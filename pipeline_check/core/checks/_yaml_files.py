"""Read + parse a batch of YAML files with uniform error handling.

Every workflow-provider context loader (``buildkite/base.py``,
``drone/base.py``, ``tekton/base.py``, ``argo/base.py``, …) used to
repeat the same 12-line loop verbatim:

    for f in files:
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            warnings.append(f"{f}: read error: {exc}")
            skipped += 1
            continue
        try:
            data = safe_load_yaml_lines(text)
        except yaml.YAMLError as exc:
            first_line = str(exc).split("\\n", 1)[0]
            warnings.append(f"{f}: YAML parse error: {first_line}")
            skipped += 1
            continue
        ...

This module owns the read + parse + warning accumulation; callers
still do file discovery and per-doc filtering (a Buildkite document
must declare ``steps``, a Drone document must declare
``kind: pipeline``, etc.) so the provider-specific bits stay in
provider code.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ._yaml_lines import safe_load_all_with_lines, safe_load_yaml_lines

_MAX_YAML_BYTES = 5 * 1024 * 1024  # 5 MB guard against alias-expansion bombs


@dataclass(frozen=True, slots=True)
class LoadedYamlFile:
    """One successfully parsed YAML file.

    ``docs`` carries the parse output as a list:
      - For single-doc inputs the list has exactly one entry (the
        top-level mapping / sequence / scalar).
      - For multi-doc streams the list carries one entry per
        ``---``-separated document, paired with the source line the
        document started on (so callers can record per-doc line info
        without re-parsing the file).

    The ``doc_lines`` field is only populated when the loader was
    invoked with ``multi_doc=True``; it's ``None`` for single-doc
    loads. The shape is deliberately decoupled from
    :func:`safe_load_all_with_lines` so callers stay agnostic to the
    underlying yaml-loader API.
    """

    path: Path
    docs: list[Any]
    doc_lines: list[int] | None = None


def load_yaml_files(
    files: Iterable[Path],
    *,
    multi_doc: bool = False,
) -> tuple[list[LoadedYamlFile], list[str], int]:
    """Read + parse each path in *files*.

    Returns ``(loaded, warnings, skipped_count)``:

    * ``loaded`` is a list of :class:`LoadedYamlFile` for every file
      that read + parsed cleanly. The order matches the input
      iterable so provider-specific preferred-vs-fallback ordering is
      preserved verbatim.
    * ``warnings`` collects one short, file-pointing message per
      read or YAML-parse failure. The prose matches the legacy
      per-provider strings (``<path>: read error: <exc>`` and
      ``<path>: YAML parse error: <first-line>``) so existing tests
      that grep these formats keep matching.
    * ``skipped_count`` is the count of files that produced a warning
      (a file that parses but fails the caller's per-doc filter is
      *not* counted here — that's the caller's bookkeeping).

    *multi_doc* selects between :func:`safe_load_yaml_lines` (single
    document; the loaded list has length 1) and
    :func:`safe_load_all_with_lines` (one entry per ``---`` body).
    Both loaders preserve PyYAML line markers on the constructed
    mappings so per-finding ``_line_of(...)`` calls still work.
    """
    loaded: list[LoadedYamlFile] = []
    warnings: list[str] = []
    skipped = 0
    for f in files:
        try:
            size = f.stat().st_size
        except OSError:
            size = 0
        if size > _MAX_YAML_BYTES:
            warnings.append(
                f"{f}: skipped (file size {size:,} bytes exceeds "
                f"{_MAX_YAML_BYTES:,} byte limit)"
            )
            skipped += 1
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            warnings.append(f"{f}: read error: {exc}")
            skipped += 1
            continue
        try:
            if multi_doc:
                pairs = list(safe_load_all_with_lines(text))
            else:
                data = safe_load_yaml_lines(text)
        except yaml.YAMLError as exc:
            first_line = str(exc).split("\n", 1)[0]
            warnings.append(f"{f}: YAML parse error: {first_line}")
            skipped += 1
            continue
        if multi_doc:
            loaded.append(LoadedYamlFile(
                path=f,
                docs=[doc for _line, doc in pairs],
                doc_lines=[line for line, _doc in pairs],
            ))
        else:
            loaded.append(LoadedYamlFile(path=f, docs=[data]))
    return loaded, warnings, skipped
