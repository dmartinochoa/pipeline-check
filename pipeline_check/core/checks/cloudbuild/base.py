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

The parser is intentionally lenient, a document missing the
``steps`` key (SAM-template style top-level include files) is
skipped. Unlike GitLab, there is no "hidden template" convention
in Cloud Build, so every parsable document is in scope.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .._yaml_files import load_yaml_files
from .._yaml_lines import line_of as _line_of
from ..base import BaseCheck, Location

# Top-level keys Cloud Build recognizes. Everything else is either a
# user substitution override (via ``substitutions:``) or out-of-spec.
TOPLEVEL_KEYWORDS: set[str] = {
    "steps", "images", "artifacts", "timeout", "options",
    "substitutions", "logsBucket", "serviceAccount", "tags",
    "availableSecrets", "secrets", "queueTtl",
}


@dataclass(frozen=True, slots=True)
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
        loaded, warnings, skipped = load_yaml_files(files)
        pipelines: list[Pipeline] = []
        for entry in loaded:
            data = entry.docs[0]
            if not isinstance(data, dict):
                continue
            # Heuristic gate: a Cloud Build file must declare ``steps``.
            # Skipping anything else avoids double-scanning CloudFormation
            # templates that happen to sit next to a cloudbuild.yaml.
            if not isinstance(data.get("steps"), list):
                continue
            pipelines.append(Pipeline(path=str(entry.path), data=data))
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
    """Return a stable human name for a step, prefers the ``id`` field."""
    sid = step.get("id")
    if isinstance(sid, str) and sid.strip():
        return sid.strip()
    return f"steps[{fallback_idx}]"


def step_location(path: str, step: dict[str, Any]) -> Location:
    """Build a :class:`Location` pointing at *step* in *path*.

    Returns a path-only ``Location`` when the loader didn't preserve
    line markers (defensive for non-line-aware test loaders).
    """
    line = _line_of(step)
    return Location(path=path, start_line=line, end_line=line)


def pipeline_publishes(doc: dict[str, Any]) -> bool:
    """True when *doc* publishes an image / artifact externally.

    Cloud Build YAML doesn't use ``docker push`` as a contiguous
    substring (the verb lives in ``args:`` while the builder name
    sits on ``name:``), so the cross-provider ``produces_artifacts``
    heuristic misses these pipelines. This helper recognizes three
    publish shapes Cloud Build users actually ship:

      * top-level ``images:`` array — Cloud Build's built-in push hook
      * a step whose ``name:`` is ``gcr.io/cloud-builders/docker`` and
        whose ``args`` start with ``push`` / ``buildx`` (the latter
        with ``--push`` or ``imagetools push``)
      * a shell-builder step (``ubuntu``, ``alpine``, ``gcloud``) whose
        joined ``args`` blob matches a docker-push command

    Keeping the structural recognizer here means GCB-009 / GCB-015 /
    GCB-017 (and any future "applies only to publishing pipelines"
    rule) get the same publish-detection contract without each rule
    reimplementing it.
    """
    images = doc.get("images")
    if isinstance(images, list) and any(
        isinstance(x, str) and x.strip() for x in images
    ):
        return True
    for _idx, step in iter_steps(doc):
        if _step_pushes_image(step):
            return True
    return False


_DOCKER_BUILDER_PREFIX = "gcr.io/cloud-builders/docker"
_DOCKER_PUSH_BLOB_RE = re.compile(
    r"\bdocker(?:\s+buildx(?:\s+imagetools)?)?\s+push\b"
    r"|\bdocker\s+buildx\s+build\b[^|]*--push\b",
)


def _step_pushes_image(step: dict[str, Any]) -> bool:
    """Structural recognizer for Cloud Build push steps.

    Duplicates the helper inside ``gcb024_images_missing`` so that
    rule's import graph doesn't reach out of its own module. The two
    copies share a comment marker so a future refactor can collapse
    them.
    """
    name = step.get("name")
    args = step.get("args")
    if (
        isinstance(name, str)
        and name.startswith(_DOCKER_BUILDER_PREFIX)
        and isinstance(args, list)
        and len(args) >= 1
    ):
        first = args[0] if isinstance(args[0], str) else ""
        if first == "push":
            return True
        if first == "buildx":
            tail = [a for a in args[1:] if isinstance(a, str)]
            if "--push" in tail:
                return True
            if tail and tail[0] == "imagetools" and "push" in tail:
                return True
    if isinstance(args, list):
        joined = " ".join(a for a in args if isinstance(a, str))
        if _DOCKER_PUSH_BLOB_RE.search(joined):
            return True
    return False


def step_strings(step: dict[str, Any]) -> list[str]:
    """Return every string-valued field from a step as a flat list.

    Used by rules that pattern-match inside ``args``, ``entrypoint``,
    and similar text-bearing fields. The ``name`` (image ref) is
    intentionally excluded, image-pinning checks care about it but
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
