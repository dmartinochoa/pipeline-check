"""MODEL-001. Base model pulled by a mutable (unpinned) reference.

An Ollama ``Modelfile`` ``FROM`` line names a base model with no immutable
pin: a bare name (``FROM llama3``, which resolves to ``:latest``) or an
explicit ``:latest`` tag. Without a pinned tag or ``@sha256:`` digest the
registry serves whatever that name points at *now*, so the publisher (or
whoever compromises the account or the upstream) can swap the weights, the
template, or the system prompt under an unchanged Modelfile.

The model-registry analog of pinning an action to a SHA (GHA-001) or a
container image to a digest, and the Modelfile-side complement of the
CI-script pinning rules (GHA-121 / GL-046).
"""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ModelfileContext, from_refs, ref_is_local, ref_tag

RULE = Rule(
    id="MODEL-001",
    title="Base model pulled without a pinned reference",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-494", "CWE-829"),
    recommendation=(
        "Pin the base model to an immutable reference. Prefer an "
        "``@sha256:`` digest (``FROM library/llama3@sha256:...``); failing "
        "that, pin a specific, stable tag (``FROM llama3:8b-instruct-q4_0``) "
        "rather than a bare name or ``:latest``, both of which the publisher "
        "can move. A pinned reference is what makes a swapped-weights or "
        "swapped-template attack show up as a diff in your Modelfile instead "
        "of landing silently on the next pull."
    ),
    docs_note=(
        "Fires on a ``FROM`` whose reference is a registry / hub model "
        "(``llama3``, ``library/llama3``, ``hf.co/org/model``) carrying no "
        "tag or an explicit ``:latest``. Does NOT fire on a specific tag, an "
        "``@sha256:`` digest, or a local weights file (covered by "
        "MODEL-003). Pulling a third-party hub model is sharpened separately "
        "by MODEL-002."
    ),
)


def _unpinned(ref: str) -> bool:
    if ref_is_local(ref):
        return False
    tag = ref_tag(ref)
    return tag is None or tag.lower() == "latest"


def check(ctx: ModelfileContext) -> list[Finding]:
    findings: list[Finding] = []
    for mf in ctx.modelfiles:
        offenders: list[str] = []
        locations: list[Location] = []
        for line_no, ref in from_refs(mf):
            if _unpinned(ref):
                offenders.append(ref)
                locations.append(
                    Location(path=mf.path, start_line=line_no, end_line=line_no)
                )
        passed = not offenders
        desc = (
            "Every FROM base model is pinned to a tag or digest."
            if passed else
            f"{len(offenders)} base model(s) are pulled by a mutable "
            f"reference (no tag or :latest), so the registry can serve "
            f"swapped weights on the next pull: {', '.join(offenders[:5])}"
            f"{'…' if len(offenders) > 5 else ''}."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=mf.path, description=desc,
            recommendation=RULE.recommendation, passed=passed,
            locations=locations,
        ))
    return findings
