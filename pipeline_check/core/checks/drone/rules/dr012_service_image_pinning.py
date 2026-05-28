"""DR-012. Service container image not pinned to digest."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    Pipeline,
    is_container_pipeline,
    iter_services,
    step_label,
    step_location,
)

RULE = Rule(
    id="DR-012",
    title="Service container image not pinned to digest",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin every entry under ``services:`` to an immutable "
        "digest (``image: postgres@sha256:<64-hex>``). Drone's "
        "``services:`` block declares sidecar containers that run "
        "alongside the pipeline (databases, message brokers, "
        "object stores used by integration tests); they pull from "
        "the same registries as ``steps:`` containers and share "
        "the same patch-release-smuggle exposure window. The "
        "existing DR-001 only audits ``steps:``, so a pipeline "
        "with SHA-pinned steps and tag-pinned services has "
        "half the supply-chain control surface."
    ),
    docs_note=(
        "Iterates ``services:`` on every container-flavored "
        "pipeline (``type: docker`` / ``kubernetes``) and fires "
        "when a service's ``image:`` value is missing the "
        "``@sha256:<digest>`` immutable-pin suffix. Service "
        "containers run with the same network access as the "
        "pipeline's steps but are typically left at floating "
        "tags (``postgres:15``, ``redis:7``) because "
        "convention follows the application's docker-compose "
        "files; the build-time supply-chain risk is identical "
        "to DR-001's surface."
    ),
    known_fp=(
        "Dev / fixture pipelines that intentionally track the "
        "upstream service's latest minor for compatibility "
        "testing may legitimately use a tag pin. Suppress per "
        "service with a one-line rationale; production-shaped "
        "pipelines should not be suppressed.",
    ),
    incident_refs=(
        "Mirrors DR-001 / DR-005 (step image / plugin pinning) "
        "and BK-001 / TKN-001 / ARGO-001 in the equivalent "
        "patterns: every container in the pipeline's blast "
        "radius should resolve through an immutable digest, not "
        "a floating tag the upstream registry can re-resolve.",
    ),
    exploit_example=(
        "# Vulnerable: service uses a floating tag.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: integration-test\n"
        "services:\n"
        "  - name: db\n"
        "    image: postgres:15\n"
        "steps:\n"
        "  - name: test\n"
        "    image: golang:1.22@sha256:abc123...\n"
        "    commands: [go test ./...]\n"
        "\n"
        "# Attack: a poisoned postgres:15 patch lands in the\n"
        "# registry. The next build picks up the bad image as the\n"
        "# `db` service; the malicious service writes attacker-\n"
        "# controlled data into the test fixture stream, which\n"
        "# the test step consumes.\n"
        "\n"
        "# Safe: digest pin.\n"
        "services:\n"
        "  - name: db\n"
        "    image: postgres:15@sha256:def456...\n"
    ),
)


_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")


def check(pipeline: Pipeline) -> Finding:
    if not is_container_pipeline(pipeline):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path,
            description=(
                f"Pipeline type {pipeline.data.get('type')!r} has no "
                f"services to audit."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    services = list(iter_services(pipeline))
    if not services:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path,
            description="Pipeline declares no services.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations = []
    for idx, svc in services:
        image = svc.get("image")
        if not isinstance(image, str) or not image:
            continue
        if _DIGEST_RE.search(image):
            continue
        name = step_label(svc, idx, kind="services")
        offenders.append(f"{name}: {image}")
        locations.append(step_location(pipeline.path, svc))
    passed = not offenders
    desc = (
        f"Every service image on {pipeline.path} is digest-pinned."
        if passed else
        f"{len(offenders)} service(s) use floating image tags: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Each next build "
        f"resolves the tag against the registry's current "
        f"content."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
