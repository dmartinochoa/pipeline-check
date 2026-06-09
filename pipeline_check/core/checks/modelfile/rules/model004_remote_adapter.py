"""MODEL-004. LoRA adapter applied from a remote source.

An Ollama ``Modelfile`` ``ADAPTER`` layer fine-tunes the base model's
behavior. When the adapter is pulled from a remote source (a third-party
hub or any registry-style reference rather than a local file), an untrusted
or mutable adapter can re-steer the model, smuggle a jailbreak, or shift
outputs, with no provenance recorded in the Modelfile. Adapters change what
the model *does*, so a remote one deserves the same pin-and-verify
treatment as the base model (MODEL-001 / MODEL-002).
"""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ModelfileContext, adapter_refs, ref_is_hub, ref_is_local

RULE = Rule(
    id="MODEL-004",
    title="LoRA adapter applied from a remote source",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-494", "CWE-829"),
    recommendation=(
        "Vet and pin the adapter the same way as the base model: prefer a "
        "local, checksum-verified adapter file, or pin a remote one to an "
        "``@sha256:`` digest and review who controls it. An adapter "
        "re-steers the model's behavior, so an untrusted or mutable one is a "
        "behavior-injection vector."
    ),
    docs_note=(
        "Fires on an ``ADAPTER`` whose reference is not a local file (a "
        "``hf.co`` / ``huggingface.co`` pull or a bare registry-style name). "
        "A local adapter file does not fire; pin / verify it out of band."
    ),
)


def check(ctx: ModelfileContext) -> list[Finding]:
    findings: list[Finding] = []
    for mf in ctx.modelfiles:
        offenders: list[str] = []
        locations: list[Location] = []
        for line_no, ref in adapter_refs(mf):
            if not ref_is_local(ref):
                kind = "hub" if ref_is_hub(ref) else "remote"
                offenders.append(f"{ref} ({kind})")
                locations.append(
                    Location(path=mf.path, start_line=line_no, end_line=line_no)
                )
        passed = not offenders
        desc = (
            "No adapter is applied from a remote source."
            if passed else
            f"{len(offenders)} adapter(s) are pulled from a remote source, "
            f"so an untrusted or mutable adapter can re-steer the model: "
            f"{', '.join(offenders[:5])}"
            f"{'…' if len(offenders) > 5 else ''}."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=mf.path, description=desc,
            recommendation=RULE.recommendation, passed=passed,
            locations=locations,
        ))
    return findings
