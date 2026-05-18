"""Helm chart-supply-chain TODO fixers (HELM-001/002/003).

Helm fixers are comment-only because the structural change each rule
asks for can't be applied by text-patching ``Chart.yaml`` alone:

- HELM-001 (apiVersion: v1) needs a v1→v2 schema migration that
  moves dependencies out of ``requirements.yaml`` and adds
  ``Chart.lock`` , not a single-line edit.
- HELM-002 (missing Chart.lock digests) needs ``helm dependency
  update`` to actually fetch the deps and compute their sha256s.
- HELM-003 (non-HTTPS dep repo) needs the maintainer to confirm the
  dep is also published over HTTPS / OCI before the URL flip is
  safe; rewriting ``http://`` to ``https://`` blindly can break
  ``helm dependency build``.

In each case the fixer drops a TODO marker above the offending line
so the change is visible in review and ``--fix`` keeps a sensible
exit-code story alongside the K8s / Dockerfile fixers.
"""
from __future__ import annotations

import re

from ..checks.base import Finding
from . import register
from ._impl import _insert_comment_above

_TODO_HELM_001 = (
    "TODO(pipeline-check HELM-001): bump to ``apiVersion: v2`` and "
    "migrate any sibling ``requirements.yaml`` entries into the "
    "``dependencies:`` list, then run ``helm dependency update``"
)

# Match the top-level ``apiVersion: v1`` line in Chart.yaml. The
# value capture deliberately rejects whitespace and ``#`` so an
# inline comment doesn't trip the regex.
_HELM_API_V1_RE = re.compile(
    r"^(?P<indent>\s*)apiVersion\s*:\s*[\"']?v1[\"']?\s*(?:#[^\n]*)?$",
    re.MULTILINE,
)


@register("HELM-001")
def _fix_helm001_api_version(content: str, finding: Finding) -> str | None:
    """Insert a TODO above ``apiVersion: v1`` in Chart.yaml.

    Idempotent via the marker check. Multiple matches in one file
    (rare , a chart should have one ``apiVersion`` key) each get a
    comment above them.
    """
    if _TODO_HELM_001 in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _HELM_API_V1_RE.finditer(content):
        indent = m.group("indent")
        edits.append((m.start(), f"{indent}# {_TODO_HELM_001}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


_TODO_HELM_002 = (
    "TODO(pipeline-check HELM-002): commit a ``Chart.lock`` with a "
    "``sha256:`` digest per entry , re-run ``helm dependency update`` "
    "after every change to this list"
)

# Match the ``dependencies:`` key at the top level of Chart.yaml.
# Anchoring to BOL + a single ``dependencies`` key avoids matching
# nested mappings (e.g. a ``spec.dependencies:`` field in some
# chart-of-charts shapes).
_HELM_DEPENDENCIES_RE = re.compile(
    r"^(?P<indent>\s*)dependencies\s*:\s*(?:#[^\n]*)?$",
    re.MULTILINE,
)


@register("HELM-002")
def _fix_helm002_dependencies_lock(content: str, finding: Finding) -> str | None:
    """Insert a TODO above the ``dependencies:`` key in Chart.yaml.

    Covers all three HELM-002 failure shapes (no Chart.lock at all,
    Chart.lock missing entries, Chart.lock entries without digests)
    by anchoring at the dependency manifest's root rather than a
    specific failure mode in Chart.lock , the human action is the
    same in every case (``helm dependency update``).
    """
    if _TODO_HELM_002 in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _HELM_DEPENDENCIES_RE.finditer(content):
        indent = m.group("indent")
        edits.append((m.start(), f"{indent}# {_TODO_HELM_002}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


_TODO_HELM_003 = (
    "TODO(pipeline-check HELM-003): switch this repository to "
    "``https://``, ``oci://``, or a ``file://`` sibling; plaintext "
    "fetch lets an on-path attacker swap the dependency tarball"
)

# Match a ``repository: <url>`` line whose URL is on a non-HTTPS,
# non-OCI, non-file scheme. Only the four common plaintext schemes
# need to fire here; safe URLs simply don't match.
_HELM_PLAINTEXT_REPO_RE = re.compile(
    r"^(?P<indent>\s*)repository\s*:\s*[\"']?"
    r"(?:http|git|ftp|rsync)://[^\s\"'#]*"
    r"[\"']?\s*(?:#[^\n]*)?$",
    re.MULTILINE,
)


@register("HELM-003")
def _fix_helm003_plaintext_repo(content: str, finding: Finding) -> str | None:
    """Insert a TODO above each ``repository: <plaintext-url>`` line.

    Multiple deps on the same chart each get their own comment so a
    review with several offenders is unambiguous.
    """
    if _TODO_HELM_003 in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _HELM_PLAINTEXT_REPO_RE.finditer(content):
        indent = m.group("indent")
        edits.append((m.start(), f"{indent}# {_TODO_HELM_003}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)
