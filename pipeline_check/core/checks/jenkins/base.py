"""Jenkins context and base check.

Jenkins pipelines are Groovy, not YAML. We deliberately avoid any
attempt to parse Groovy as an AST — the surface is too dynamic, and
real Jenkinsfiles routinely embed shell, JSON, and freeform Groovy
expressions inside ``script {}`` blocks where a parser would lose
fidelity. Instead, every check operates on the raw text via the
shared regex helpers, which is the same trade-off the YAML providers
make for ``run:`` blocks.

Two minimal facts are extracted up-front:

- ``stages``: a list of ``(stage_name, body_text)`` pairs derived by
  scanning for ``stage('Name') { ... }`` blocks. Used by deploy-gate
  checks that need to reason about per-stage content (e.g. "is there
  an ``input`` step before the deploy stage?").
- ``library_refs``: every ``@Library('<spec>')`` reference, used by
  the dependency-pinning check.

Anything else (artifact-signing, SBOM, secret scanning) reads the
flat text and reuses the cross-provider helpers in ``checks.base``
and ``checks._secrets``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..base import BaseCheck


_LIBRARY_RE = re.compile(r"@Library\(\s*['\"]([^'\"]+)['\"]\s*\)")
# Matches ``stage('Name') { ... }`` non-greedily, capturing the inner
# block. Groovy allows nested braces; we use a depth-aware pass below
# rather than a regex to avoid pathological cases.
_STAGE_HEAD_RE = re.compile(r"stage\(\s*['\"]([^'\"]+)['\"]\s*\)\s*\{")


@dataclass(frozen=True)
class Jenkinsfile:
    """A parsed Jenkinsfile (text + minimally-extracted facts)."""

    path: str
    text: str
    library_refs: list[str] = field(default_factory=list)
    stages: list[tuple[str, str]] = field(default_factory=list)


class JenkinsContext:
    """Loaded set of Jenkinsfiles."""

    def __init__(self, files: list[Jenkinsfile]) -> None:
        self.files = files

    @classmethod
    def from_path(cls, path: str | Path) -> "JenkinsContext":
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--jenkinsfile-path {root} does not exist. Pass a "
                f"Jenkinsfile or a directory containing one."
            )
        if root.is_file():
            paths = [root]
        else:
            paths = sorted(
                p for p in root.rglob("*")
                if p.is_file() and (p.name == "Jenkinsfile" or p.suffix.lower() in {".jenkinsfile", ".groovy"})
            )
        files: list[Jenkinsfile] = []
        for p in paths:
            try:
                text = p.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            files.append(Jenkinsfile(
                path=str(p),
                text=text,
                library_refs=_LIBRARY_RE.findall(text),
                stages=_extract_stages(text),
            ))
        return cls(files)


class JenkinsBaseCheck(BaseCheck):
    """Base class for Jenkins pipeline checks."""

    PROVIDER = "jenkins"

    def __init__(self, ctx: JenkinsContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: JenkinsContext = ctx


def _extract_stages(text: str) -> list[tuple[str, str]]:
    """Yield ``(name, body)`` for every ``stage('Name') { ... }`` in *text*.

    Walks Groovy braces depth-aware so a stage containing nested
    blocks (``script { ... }``, ``steps { ... }``) is captured in
    full. Lines inside string literals can contain unmatched braces;
    we intentionally don't try to handle that — the false-positive
    cost on declarative Jenkinsfiles (which avoid that idiom) is
    negligible compared to the false-negative cost of skipping the
    whole stage parser when one weird literal trips us up.
    """
    out: list[tuple[str, str]] = []
    for head in _STAGE_HEAD_RE.finditer(text):
        name = head.group(1)
        i = head.end()  # position right after the opening `{`
        depth = 1
        while i < len(text) and depth > 0:
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        body = text[head.end():i - 1] if depth == 0 else text[head.end():]
        out.append((name, body))
    return out
