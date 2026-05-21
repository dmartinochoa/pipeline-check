"""TKN-001. Step images must be digest-pinned (``image@sha256:<digest>``)."""
from __future__ import annotations

import re

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import TektonContext, step_name, task_steps

RULE = Rule(
    id="TKN-001",
    title="Tekton step image not pinned to a digest",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin every step image to a content-addressable digest "
        "(``gcr.io/tekton-releases/git-init@sha256:<digest>``). Tag-"
        "only references (``alpine:3.18``) and rolling tags "
        "(``alpine:latest``) let a compromised registry update redirect "
        "the step at the next pull, with no audit trail in the Task "
        "manifest."
    ),
    docs_note=(
        "Applies to ``Task`` and ``ClusterTask`` kinds. The image must "
        "contain ``@sha256:`` followed by a 64-char hex digest. Any "
        "tag-only reference, including ``:latest``, fails."
    ),
    exploit_example=(
        "# Vulnerable: ``ubuntu:22.04`` is a mutable tag. Whoever\n"
        "# controls the registry can repoint it on the next 22.04.x\n"
        "# refresh; the next TaskRun pulls the swap silently.\n"
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "metadata: { name: build }\n"
        "spec:\n"
        "  steps:\n"
        "    - name: compile\n"
        "      image: ubuntu:22.04\n"
        "      script: |\n"
        "        make build\n"
        "\n"
        "# Safe: pin to the immutable sha256 digest. The leading\n"
        "# comment documents which tag the digest corresponds to.\n"
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "metadata: { name: build }\n"
        "spec:\n"
        "  steps:\n"
        "    - name: compile\n"
        "      image: ubuntu@sha256:abc123...  # ubuntu:22.04, refreshed YYYY-MM-DD\n"
        "      script: |\n"
        "        make build"
    ),
)

_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")


def check(ctx: TektonContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    examined = 0
    for doc in ctx.docs:
        if doc.kind not in ("Task", "ClusterTask"):
            continue
        examined += 1
        for idx, step in enumerate(task_steps(doc)):
            image = step.get("image")
            if not isinstance(image, str) or not image.strip():
                continue
            if not _DIGEST_RE.search(image):
                offenders.append(
                    f"{doc.kind}/{doc.name} {step_name(step, idx)}: {image}"
                )
                line = _line_of(step) if isinstance(step, dict) else None
                locations.append(Location(
                    path=doc.path, start_line=line, end_line=line,
                    doc_index=doc.doc_index,
                ))
    passed = not offenders
    if examined == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description="No Task / ClusterTask documents to check.",
            recommendation="No action required.", passed=True,
        )
    desc = (
        "Every step image is digest-pinned."
        if passed else
        f"{len(offenders)} step image(s) not digest-pinned: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
