"""GCB-016. Step ``dir:`` field contains a parent-directory escape (``..``)."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GCB-016",
    title="Step dir field contains parent-directory escape (..)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7", "CICD-SEC-4"),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-22",),
    recommendation=(
        "Replace ``..`` traversals in ``dir:`` with absolute paths "
        "rooted under ``/workspace`` (e.g. ``dir: /workspace/sub``) "
        "or split the work across multiple steps that each set "
        "``dir:`` to an exact subdirectory. The Cloud Build worker "
        "starts each step with the workspace mounted at "
        "``/workspace``; a ``..`` escape from there reaches the "
        "builder image's root filesystem and any credentials the "
        "image carries."
    ),
    docs_note=(
        "Cloud Build doesn't sandbox the ``dir:`` value beyond a "
        "join against ``/workspace``. ``dir: ../etc`` resolves to "
        "``/etc`` inside the builder container, which is rarely the "
        "intent. The check fires on any literal ``..`` segment; "
        "single-dot ``./`` and absolute paths are fine."
    ),
    exploit_example=(
        "# Vulnerable: a step sets dir: to a path that escapes the\n"
        "# /workspace mount.\n"
        "steps:\n"
        "  - name: gcr.io/cloud-builders/gcloud@sha256:abc123...\n"
        "    dir: ../secrets\n"
        "    args: [run, deploy, app]\n"
        "\n"
        "# Attack: Cloud Build mounts the repo at /workspace and\n"
        "# joins dir: against it with no sandboxing, so dir: ../secrets\n"
        "# resolves to /secrets in the builder image, outside the\n"
        "# checkout. A step (or injected build logic) reads or writes\n"
        "# the builder image's own filesystem, including credentials\n"
        "# baked into the image, instead of staying in the source tree.\n"
        "\n"
        "# Safe: keep dir: under /workspace with an absolute path or\n"
        "# an exact subdirectory.\n"
        "steps:\n"
        "  - name: gcr.io/cloud-builders/gcloud@sha256:abc123...\n"
        "    dir: /workspace/app\n"
        "    args: [run, deploy, app]"
    ),
)


def _has_escape(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parts = value.replace("\\", "/").split("/")
    return ".." in parts


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    steps = doc.get("steps")
    if isinstance(steps, list):
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            d = step.get("dir")
            if _has_escape(d):
                step_id = step.get("id") or f"steps[{idx}]"
                offenders.append(f"{step_id}: dir={d!r}")
    passed = not offenders
    desc = (
        "No step's ``dir`` field contains a parent-directory escape."
        if passed else
        f"{len(offenders)} step(s) traverse out of /workspace via "
        f"``..``: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
