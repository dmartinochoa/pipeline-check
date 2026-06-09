"""MODEL-003. Base model loaded from a local unverified weights blob.

An Ollama ``Modelfile`` ``FROM ./model.gguf`` / ``FROM /models/x.safetensors``
imports a raw weights file checked into (or sitting next to) the repo. A
binary blob carries no registry provenance and no integrity check in the
Modelfile, so a reviewer can't tell whether it is the file it claims to be,
and a ``.bin`` / ``.pt`` / ``.pth`` import is pickle-backed (arbitrary-code
deserialization at load). The OpenSSF "binary artifacts" hygiene signal,
applied to model weights.
"""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ModelfileContext, from_refs, ref_is_local

RULE = Rule(
    id="MODEL-003",
    title="Base model loaded from a local unverified weights blob",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494", "CWE-829"),
    recommendation=(
        "Source the base model from a pinned registry / hub reference "
        "(MODEL-001) with a recorded digest rather than a loose local "
        "weights file, or, if a local file is required, record and verify "
        "its checksum out of band and prefer GGUF / safetensors over "
        "pickle-backed ``.bin`` / ``.pt`` formats. A committed binary blob "
        "has no provenance a reviewer can check."
    ),
    docs_note=(
        "Fires on a ``FROM`` whose reference is a local path "
        "(``./``, ``/``, ``~/``, ``../``) or a bare weights filename "
        "(``.gguf`` / ``.safetensors`` / ``.bin`` / ``.pt`` / ``.pth``). "
        "Pickle-backed extensions are called out in the finding because they "
        "deserialize arbitrary code at load."
    ),
)

_PICKLE_EXT_RE = re.compile(r"\.(?:bin|pt|pth)$", re.IGNORECASE)


def check(ctx: ModelfileContext) -> list[Finding]:
    findings: list[Finding] = []
    for mf in ctx.modelfiles:
        offenders: list[str] = []
        locations: list[Location] = []
        pickle_seen = False
        for line_no, ref in from_refs(mf):
            if ref_is_local(ref):
                offenders.append(ref)
                locations.append(
                    Location(path=mf.path, start_line=line_no, end_line=line_no)
                )
                if _PICKLE_EXT_RE.search(ref):
                    pickle_seen = True
        passed = not offenders
        pickle_note = (
            " One is a pickle-backed format that deserializes arbitrary code "
            "at load." if pickle_seen else ""
        )
        desc = (
            "No base model is loaded from a local weights blob."
            if passed else
            f"{len(offenders)} base model(s) are loaded from a local "
            f"weights file with no registry provenance: "
            f"{', '.join(offenders[:5])}"
            f"{'…' if len(offenders) > 5 else ''}.{pickle_note}"
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=mf.path, description=desc,
            recommendation=RULE.recommendation, passed=passed,
            locations=locations,
        ))
    return findings
