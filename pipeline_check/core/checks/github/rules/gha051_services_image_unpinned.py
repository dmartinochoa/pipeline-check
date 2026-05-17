"""GHA-051. ``services.<name>.image`` not pinned by digest."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

RULE = Rule(
    id="GHA-051",
    title="services / container image is not pinned by digest",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-PIN-DEPS",),
    cwe=("CWE-829", "CWE-1357"),
    recommendation=(
        "Replace every ``services.<name>.image:`` (and the same "
        "field on a job-level ``container:`` block) with a "
        "``<image>@sha256:<digest>`` reference. The services / "
        "container runs alongside the workflow on the same "
        "runner and sees the same secret environment, so a "
        "swapped sidecar image is the same shape of attack as a "
        "swapped action: arbitrary code on the runner under the "
        "workflow's identity. Use a registry that returns "
        "immutable digests (``docker buildx imagetools inspect"
        "`` resolves a tag to a digest), pin to that digest, "
        "then re-pin on the next intentional upgrade — exactly "
        "the workflow GHA-001 already documents for "
        "``uses: actions/...@<sha>``."
    ),
    docs_note=(
        "Walks ``jobs.<id>.services.<name>.image`` and "
        "``jobs.<id>.container.image`` (the two places a "
        "GitHub-hosted runner pulls a third-party image at job "
        "start). Flags any reference that isn't pinned by "
        "``@sha256:<digest>``: bare tags (``postgres:16``), "
        "``latest``, no-tag (``redis``), and "
        "``mcr.microsoft.com/dotnet/sdk:8.0``-style tag pins "
        "all fail.\n\n"
        "Complements DF-001 (Dockerfile ``FROM`` pinning), "
        "GHA-001 (action ``uses:`` pinning), and GHA-040 "
        "(known-compromised action refs). Where those catch "
        "your own code pulling a third party, GHA-051 catches "
        "the *runner* pulling a third-party image to host the "
        "workflow alongside your code — same trust shape, "
        "different ingress."
    ),
    known_fp=(
        "Workflows that pull from an org-internal private "
        "registry where the registry itself enforces image "
        "immutability sometimes pin by tag deliberately. The "
        "safer pattern is still ``@sha256:``: the registry's "
        "immutability is a separate trust boundary you'd need "
        "to audit, while a digest pin is self-verifying. "
        "Suppress with a rationale that names the registry and "
        "the audit channel.",
    ),
)


# A pinned reference contains ``@sha256:`` followed by 64 hex chars.
# The strict form rejects truncated digests as well as tag-style refs.
_DIGEST_PIN_RE = re.compile(r"@sha256:[0-9a-f]{64}\b", re.IGNORECASE)


def _is_pinned(image: Any) -> bool:
    if not isinstance(image, str):
        return False
    return bool(_DIGEST_PIN_RE.search(image))


def _scan_image(node: Any, breadcrumb: str) -> str | None:
    """Return a breadcrumb label when *node* declares an unpinned
    image, or ``None``."""
    if not isinstance(node, dict):
        return None
    image = node.get("image")
    if image is None:
        return None
    if _is_pinned(image):
        return None
    if not isinstance(image, str):
        return f"{breadcrumb}.image"
    return f"{breadcrumb}.image ({image})"


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        c = _scan_image(
            job.get("container"),
            breadcrumb=f"jobs.{job_id}.container",
        )
        if c is not None:
            offenders.append(c)
        services = job.get("services")
        if isinstance(services, dict):
            for svc_name, svc in services.items():
                hit = _scan_image(
                    svc, breadcrumb=f"jobs.{job_id}.services.{svc_name}",
                )
                if hit is not None:
                    offenders.append(hit)
    passed = not offenders
    desc = (
        "Every services / container image is pinned by ``@sha256:`` "
        "digest."
        if passed else
        f"{len(offenders)} services / container image(s) are "
        f"unpinned: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The runner pulls "
        f"whatever the tag currently resolves to, so a tag "
        f"rewrite on the upstream is arbitrary code on the runner."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
