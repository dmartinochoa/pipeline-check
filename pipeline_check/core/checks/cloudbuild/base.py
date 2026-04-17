"""Google Cloud Build context and base check.

Parses ``cloudbuild.yaml`` documents from disk. Each file normalises
into a :class:`Pipeline` wrapping the parsed document; checks
subclass :class:`CloudBuildBaseCheck` and iterate
``self.ctx.pipelines``.

Cloud Build's pipeline file shape (highlights):

    steps:
      - name: 'gcr.io/cloud-builders/docker'
        args: [...]
        secretEnv: [...]
        env: [...]
        dir: 'subpath'
        id: 'build-image'
    options:
      logging: CLOUD_LOGGING_ONLY
      dynamicSubstitutions: true
      pool: {name: projects/.../workerPools/secure-pool}
    substitutions:
      _DEPLOY_TARGET: production
    availableSecrets:
      secretManager:
        - versionName: projects/$PROJECT_ID/secrets/api-key/versions/latest
          env: API_KEY
    serviceAccount: projects/.../serviceAccounts/builder@...
    timeout: 1800s

The parser is intentionally lenient — a document missing the
``steps`` key (SAM-template style top-level include files) is
skipped. Unlike GitLab, there is no "hidden template" convention
in Cloud Build, so every parsable document is in scope.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..base import BaseCheck, safe_load_yaml

# Top-level keys Cloud Build recognises. Everything else is either a
# user substitution override (via ``substitutions:``) or out-of-spec.
_TOPLEVEL_KEYWORDS: set[str] = {
    "steps", "images", "artifacts", "timeout", "options",
    "substitutions", "logsBucket", "serviceAccount", "tags",
    "availableSecrets", "secrets", "queueTtl",
}


@dataclass(frozen=True)
class Pipeline:
    """A parsed Cloud Build YAML document."""

    path: str
    data: dict[str, Any]


class CloudBuildContext:
    """Loaded set of Cloud Build YAML documents."""

    def __init__(self, pipelines: list[Pipeline]) -> None:
        self.pipelines = pipelines
        self.files_scanned: int = len(pipelines)
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> CloudBuildContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--cloudbuild-path {root} does not exist. Pass a "
                "cloudbuild.yaml file or a directory containing one."
            )
        if root.is_file():
            files = [root]
        else:
            files = sorted(
                p for p in root.rglob("*")
                if p.is_file() and p.name in {"cloudbuild.yaml", "cloudbuild.yml"}
            )
            if not files:
                files = sorted(
                    p for p in root.rglob("*")
                    if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
                )
        pipelines: list[Pipeline] = []
        warnings: list[str] = []
        skipped = 0
        for f in files:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"{f}: read error: {exc}")
                skipped += 1
                continue
            try:
                data = safe_load_yaml(text)
            except yaml.YAMLError as exc:
                first_line = str(exc).split("\n", 1)[0]
                warnings.append(f"{f}: YAML parse error: {first_line}")
                skipped += 1
                continue
            if not isinstance(data, dict):
                continue
            # Heuristic gate: a Cloud Build file must declare ``steps``.
            # Skipping anything else avoids double-scanning CloudFormation
            # templates that happen to sit next to a cloudbuild.yaml.
            if not isinstance(data.get("steps"), list):
                continue
            pipelines.append(Pipeline(path=str(f), data=data))
        ctx = cls(pipelines)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class CloudBuildBaseCheck(BaseCheck):
    """Base class for Cloud Build rule modules."""

    PROVIDER = "cloudbuild"

    def __init__(self, ctx: CloudBuildContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: CloudBuildContext = ctx


# ── Helpers shared by multiple rule modules ────────────────────────────

def iter_steps(doc: dict[str, Any]) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield ``(index, step_dict)`` for every step in the document."""
    steps = doc.get("steps") or []
    if not isinstance(steps, list):
        return
    for idx, step in enumerate(steps):
        if isinstance(step, dict):
            yield idx, step


def step_name(step: dict[str, Any], fallback_idx: int) -> str:
    """Return a stable human name for a step — prefers the ``id`` field."""
    sid = step.get("id")
    if isinstance(sid, str) and sid.strip():
        return sid.strip()
    return f"steps[{fallback_idx}]"


def step_strings(step: dict[str, Any]) -> list[str]:
    """Return every string-valued field from a step as a flat list.

    Used by rules that pattern-match inside ``args``, ``entrypoint``,
    and similar text-bearing fields. The ``name`` (image ref) is
    intentionally excluded — image-pinning checks care about it but
    script-injection / secret-leak checks would otherwise false-match
    on registry hostnames.
    """
    out: list[str] = []
    ent = step.get("entrypoint")
    if isinstance(ent, str):
        out.append(ent)
    args = step.get("args")
    if isinstance(args, list):
        for a in args:
            if isinstance(a, str):
                out.append(a)
    elif isinstance(args, str):
        out.append(args)
    # ``env`` and ``secretEnv`` hold VAR=value pairs and secret refs
    # respectively; include them so secret-leak scans see both forms.
    for key in ("env", "secretEnv"):
        v = step.get(key)
        if isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    out.append(item)
    return out
