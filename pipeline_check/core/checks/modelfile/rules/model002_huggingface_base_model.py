"""MODEL-002. Base model pulled straight from a third-party hub.

An Ollama ``Modelfile`` ``FROM hf.co/...`` / ``FROM huggingface.co/...``
pulls weights directly from a third-party hub, bypassing the curated
Ollama library. HuggingFace hosts user-uploaded models, and the GGUF /
safetensors a Modelfile imports can carry a baked-in template, system
prompt, or (for non-GGUF imports) pickle-backed weights, all sourced from
an account you don't control. It is the model-registry parallel of pulling
a base image from an untrusted registry, and it pairs with the CI-side
trust rules (GHA-120 / GL-045 ``trust_remote_code``).
"""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ModelfileContext, from_refs, ref_is_hub

RULE = Rule(
    id="MODEL-002",
    title="Base model pulled from a third-party hub",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-494", "CWE-829"),
    recommendation=(
        "Treat a ``hf.co`` / ``huggingface.co`` base model as an untrusted "
        "dependency: vet the uploader, prefer a first-party or curated "
        "Ollama-library model, and if the hub model is required pin it to an "
        "``@sha256:`` digest (MODEL-001), prefer GGUF / safetensors over "
        "pickle-backed formats, and review the baked-in ``TEMPLATE`` / "
        "``SYSTEM`` the import carries."
    ),
    docs_note=(
        "Fires on a ``FROM`` whose reference begins with ``hf.co/`` or "
        "``huggingface.co/``. This is the source-trust axis; whether that "
        "same reference is also unpinned is reported separately by "
        "MODEL-001."
    ),
)


def check(ctx: ModelfileContext) -> list[Finding]:
    findings: list[Finding] = []
    for mf in ctx.modelfiles:
        offenders: list[str] = []
        locations: list[Location] = []
        for line_no, ref in from_refs(mf):
            if ref_is_hub(ref):
                offenders.append(ref)
                locations.append(
                    Location(path=mf.path, start_line=line_no, end_line=line_no)
                )
        passed = not offenders
        desc = (
            "No base model is pulled directly from a third-party hub."
            if passed else
            f"{len(offenders)} base model(s) are pulled directly from a "
            f"third-party hub (hf.co / huggingface.co), bypassing the "
            f"curated registry: {', '.join(offenders[:5])}"
            f"{'…' if len(offenders) > 5 else ''}."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=mf.path, description=desc,
            recommendation=RULE.recommendation, passed=passed,
            locations=locations,
        ))
    return findings
