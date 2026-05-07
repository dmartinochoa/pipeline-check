"""GCB-021 — Build runs on the shared default Cloud Build worker pool."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GCB-021",
    title="No private worker pool — build runs on the shared default pool",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-NETWORK-SEG", "ESF-D-ISOLATION"),
    cwe=("CWE-668",),
    recommendation=(
        "Set ``options.pool.name: projects/<PROJECT>/locations/"
        "<REGION>/workerPools/<NAME>`` to bind the build to a private "
        "worker pool inside your VPC. The default pool runs on a "
        "shared Google-managed network with public-internet egress "
        "and ingress paths Google chooses, which makes egress "
        "filtering, VPC-SC perimeters, and source-IP allowlists on "
        "internal endpoints impossible. A private pool also gives "
        "you the option to disable external IPs and to log the "
        "build's network activity through your own VPC flow logs."
    ),
    docs_note=(
        "Cloud Build runs in a shared Google-managed pool by default. "
        "Switching to a *private worker pool* is the prerequisite for "
        "every other network-perimeter control: egress restriction "
        "to specific peered networks, ingress blocking of public "
        "endpoints, and traffic interoperation with VPC Service "
        "Controls. Both ``options.pool.name`` and the legacy "
        "``options.workerPool`` field are accepted."
    ),
    known_fp=(
        "OSS / sample / one-off builds that legitimately have no "
        "private network and no internal endpoints to protect. "
        "Suppress with a brief ``.pipelinecheckignore`` rationale "
        "rather than disabling at the catalog level.",
    ),
)


def _has_worker_pool(doc: dict[str, Any]) -> bool:
    options = doc.get("options")
    if not isinstance(options, dict):
        return False
    # New-style: ``options.pool.name``.
    pool = options.get("pool")
    if isinstance(pool, dict):
        name = pool.get("name")
        if isinstance(name, str) and name.strip():
            return True
    # Legacy: ``options.workerPool``.
    legacy = options.get("workerPool")
    if isinstance(legacy, str) and legacy.strip():
        return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    if _has_worker_pool(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Private worker pool configured under ``options``.",
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=(
            "No ``options.pool.name`` (or legacy ``options.workerPool``) "
            "set — the build runs on Google's shared default pool with "
            "public-internet egress and no VPC perimeter."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
