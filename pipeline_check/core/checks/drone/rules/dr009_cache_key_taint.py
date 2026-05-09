"""DR-009. Cache plugin key embeds an attacker-controllable Drone variable."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Pipeline, is_plugin_step, iter_steps, step_label

RULE = Rule(
    id="DR-009",
    title=(
        "Cache plugin key embeds an attacker-controllable Drone "
        "variable"
    ),
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-3"),
    esf=("ESF-D-INJECTION", "ESF-S-IMMUTABLE"),
    cwe=("CWE-349",),  # Acceptance of Extraneous Untrusted Data
    recommendation=(
        "Don't embed PR-controlled or branch-controlled Drone "
        "variables in cache keys. The canonical safe shape is "
        "to key on commit-stable inputs only: a checksum of the "
        "lockfile (``${DRONE_REPO_BRANCH}-${DRONE_COMMIT_SHA}`` "
        "is unique enough; ``${DRONE_BRANCH}`` alone is "
        "attacker-controllable). When two builds need to share "
        "a cache, key on the dependency manifest's hash, not on "
        "any branch / PR / repo metadata that a fork PR can "
        "shape. If a fork PR's cache write can ever be read "
        "back by a trusted-context build (the same key on a "
        "different branch), the attacker can inject malicious "
        "build artifacts into the trusted run."
    ),
    docs_note=(
        "Drone has no first-party cache keyword; pipelines use "
        "plugin steps (``drone-cache``, ``drone-volume-cache``, "
        "``drone-s3-cache``, etc.) configured via "
        "``settings:``. The rule fires on any plugin step whose "
        "``settings.cache_key`` (or related ``key``, ``mount``, "
        "``filename``, ``restore_keys``) interpolates a "
        "tainted Drone variable. Tainted vocabulary mirrors "
        "DR-003: ``$DRONE_BRANCH``, ``$DRONE_PULL_REQUEST*``, "
        "``$DRONE_COMMIT_*MESSAGE``, ``$DRONE_TAG_MESSAGE``, "
        "and the fork-PR-shaped ``$DRONE_REPO_*`` family. The "
        "attack model is well-documented (GHA-011 catches the "
        "same shape on the GitHub Actions side)."
    ),
    known_fp=(
        "Plugins that namespace cache reads by branch on the "
        "*write* side and never read across branches (a "
        "deliberate cache partitioning) are technically safe, "
        "the attacker can poison their own branch's cache but "
        "can't reach the trusted-branch one. The rule has no "
        "way to verify partition boundaries at scan time; "
        "suppress via ignore-file scoped to the specific "
        "step name when the partitioning is audited.",
    ),
)


# Match a tainted Drone variable inside a cache-key string.
# Mirrors DR-003's ``_TAINTED_VARS`` list but spelled inline
# so the rule stays self-contained and doesn't import a
# private detail from DR-003.
_TAINTED_DRONE_VARS = (
    "DRONE_BRANCH",
    "DRONE_SOURCE_BRANCH",
    "DRONE_TARGET_BRANCH",
    "DRONE_PULL_REQUEST",
    "DRONE_PULL_REQUEST_TITLE",
    "DRONE_PULL_REQUEST_BRANCH",
    "DRONE_TAG",
    "DRONE_TAG_MESSAGE",
    "DRONE_COMMIT_MESSAGE",
    "DRONE_COMMIT_AUTHOR",
    "DRONE_COMMIT_AUTHOR_NAME",
    "DRONE_COMMIT_AUTHOR_EMAIL",
    "DRONE_COMMIT_REF",
    "DRONE_REPO",
    "DRONE_REPO_NAME",
    "DRONE_REPO_NAMESPACE",
    "DRONE_REPO_OWNER",
)

_VAR_GROUP = "|".join(re.escape(v) for v in _TAINTED_DRONE_VARS)
_TAINT_RE = re.compile(
    rf"\$\{{?(?P<name>{_VAR_GROUP})\}}?\b",
)

# Cache-related keys we scan inside a plugin step's ``settings:``
# block. The list is union of every cache-plugin's documented
# key-naming convention; ``drone-cache`` uses ``cache_key``,
# ``drone-volume-cache`` uses ``key``, several use
# ``restore_keys`` or ``filename`` for path-shaped artifacts.
_CACHE_KEY_FIELDS: frozenset[str] = frozenset({
    "cache_key", "key", "restore_keys", "filename", "mount",
    "rebuild_keys", "archive_format",
})

# Plugin image refs that signal a cache-plugin step. The rule
# only fires on these images even if the settings happen to
# contain a tainted token; non-cache plugins might legitimately
# embed branch metadata in non-cache settings.
_CACHE_PLUGIN_IMAGES: tuple[str, ...] = (
    "drone-cache",
    "drone-volume-cache",
    "drone-s3-cache",
    "drone-gcs-cache",
    "meltwater/drone-cache",
    "drillster/drone-volume-cache",
    "appleboy/drone-rsync",
)


def _is_cache_plugin(image: Any) -> bool:
    """True when *image* matches a known cache-plugin shape."""
    if not isinstance(image, str):
        return False
    lc = image.lower()
    for needle in _CACHE_PLUGIN_IMAGES:
        if needle in lc:
            return True
    return False


def _flatten_settings_strings(
    settings: dict[str, Any], keys: frozenset[str],
) -> list[tuple[str, str]]:
    """Yield ``(key_name, raw_value)`` for every string value
    under one of the named *keys*.

    Lists of strings are flattened; nested dicts and non-string
    leaves are ignored. We only look at the keys named in
    *keys* so an unrelated ``settings.message`` doesn't fire.
    """
    out: list[tuple[str, str]] = []
    for k, v in settings.items():
        if not isinstance(k, str) or k not in keys:
            continue
        if isinstance(v, str):
            out.append((k, v))
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    out.append((k, item))
    return out


def check(pipeline: Pipeline) -> Finding:
    offenders: list[str] = []
    for idx, step in iter_steps(pipeline):
        if not is_plugin_step(step):
            continue
        if not _is_cache_plugin(step.get("image")):
            continue
        settings = step.get("settings")
        if not isinstance(settings, dict):
            continue
        for field, value in _flatten_settings_strings(
            settings, _CACHE_KEY_FIELDS,
        ):
            for m in _TAINT_RE.finditer(value):
                offenders.append(
                    f"steps.{step_label(step, idx)}."
                    f"settings.{field}: ${m.group('name')}"
                )
                break  # one finding per (step, field) is enough
    passed = not offenders
    desc = (
        "No cache plugin embeds a tainted Drone variable in "
        "its key."
        if passed else
        f"{len(offenders)} cache plugin step(s) embed a "
        f"tainted Drone variable in the cache key: "
        f"{'; '.join(offenders[:3])}"
        f"{'...' if len(offenders) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
