"""ARGO-001. Template container images must be digest-pinned."""
from __future__ import annotations

import re

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ArgoContext, iter_containers, iter_templates, template_name

RULE = Rule(
    id="ARGO-001",
    title="Argo template container image not pinned to a digest",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin every container / script template image to a content-"
        "addressable digest (``alpine@sha256:<digest>``). Tag-only "
        "references (``alpine:3.18``) and rolling tags "
        "(``alpine:latest``) let a compromised registry update "
        "redirect the workflow's containers at the next pull, with "
        "no audit trail in the WorkflowTemplate."
    ),
    docs_note=(
        "Walks ``spec.templates[].container``, "
        "``spec.templates[].script``, and "
        "``spec.templates[].containerSet.containers[]``. The image "
        "must contain ``@sha256:`` followed by a 64-char hex digest."
    ),
    exploit_example=(
        "# Vulnerable: ``alpine:3.18`` is a mutable tag. The Alpine\n"
        "# maintainers (or a registry compromise / namespace hijack)\n"
        "# repoint the tag on the next 3.18.x point release; every\n"
        "# Workflow run after that pulls the new image without any\n"
        "# audit trail in the manifest.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: WorkflowTemplate\n"
        "metadata: { name: build }\n"
        "spec:\n"
        "  templates:\n"
        "    - name: build\n"
        "      container:\n"
        "        image: alpine:3.18\n"
        "        command: [./build.sh]\n"
        "\n"
        "# Safe: pin to the content-addressable digest. Renovate's\n"
        "# docker-tag ecosystem bumps the digest in reviewable PRs\n"
        "# so the pin doesn't drift behind security patches.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: WorkflowTemplate\n"
        "metadata: { name: build }\n"
        "spec:\n"
        "  templates:\n"
        "    - name: build\n"
        "      container:\n"
        "        image: alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b\n"
        "        command: [./build.sh]"
    ),
)

_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}\b")


def check(ctx: ArgoContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for doc in ctx.docs:
        for idx, tmpl in enumerate(iter_templates(doc)):
            for container in iter_containers(tmpl):
                image = container.get("image")
                offending = False
                if not isinstance(image, str) or not image.strip():
                    offenders.append(
                        f"{doc.kind}/{doc.name} "
                        f"{template_name(tmpl, idx)}: <missing image>"
                    )
                    offending = True
                elif not _DIGEST_RE.search(image):
                    offenders.append(
                        f"{doc.kind}/{doc.name} "
                        f"{template_name(tmpl, idx)}: {image}"
                    )
                    offending = True
                if offending:
                    line = _line_of(container) if isinstance(container, dict) else None
                    locations.append(Location(
                        path=doc.path, start_line=line, end_line=line,
                        doc_index=doc.doc_index,
                    ))
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Argo documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "Every template container image is digest-pinned."
        if passed else
        f"{len(offenders)} container image(s) not digest-pinned: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
