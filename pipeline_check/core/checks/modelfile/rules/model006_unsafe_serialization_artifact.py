"""MODEL-006. A committed model-weight file uses a code-executing format.

Model weights checked into the repo in a pickle- or code-carrying format
(``.pkl`` / ``.pickle`` / ``.pt`` / ``.pth`` / ``.ckpt`` / ``.joblib`` /
``.dill`` / ``.keras``, plus ``.bin`` / ``.h5`` / ``.hdf5`` when the file
looks like a model) deserialize arbitrary code the moment they are
loaded: Python pickle reconstructs objects by running their ``__reduce__``,
and a Keras ``.h5`` / ``.keras`` can smuggle code through a Lambda layer.
A committed blob also carries no provenance a reviewer can check, so a
poisoned weight file looks identical to a clean one in the diff.

This is the tree-wide complement to MODEL-003: MODEL-003 fires on a
Modelfile ``FROM ./weights.pt`` *reference*, this fires on the weight
*file* existing in the repo whether or not a Modelfile points at it. The
fix is the same one the ML ecosystem has converged on: ship weights as
safetensors or GGUF, which store tensors and metadata only and cannot
execute code at load.

Deliberately a format / provenance check, not pickle-opcode
disassembly. Whether a given pickle is *actually* malicious is the job of
a dedicated model scanner (ModelScan / ModelAudit), the same boundary
that keeps image-CVE layer scanning out of this tool.
"""
from __future__ import annotations

from ...base import Finding, Location, Severity, summarize_offenders
from ...rule import Rule
from ..base import ModelfileContext

RULE = Rule(
    id="MODEL-006",
    title="Committed model weights in a code-executing serialization format",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-502", "CWE-494", "CWE-829"),
    recommendation=(
        "Ship model weights as safetensors or GGUF, which store tensors "
        "and metadata only and can't execute code at load, rather than a "
        "pickle-backed format (``.pkl`` / ``.pt`` / ``.pth`` / ``.ckpt`` / "
        "``.joblib`` / ``.dill``) or a Keras ``.h5`` / ``.keras`` whose "
        "Lambda layers can carry code. If a legacy format is unavoidable, "
        "record and verify the file's checksum out of band and load it in "
        "a job scoped to no production secrets. A committed binary blob "
        "carries no provenance a reviewer can check."
    ),
    docs_note=(
        "Fires on a committed weight file, anywhere in the scanned tree, "
        "whose extension deserializes code at load: ``.pkl`` / ``.pickle`` "
        "/ ``.pt`` / ``.pth`` / ``.ckpt`` / ``.joblib`` / ``.dill`` / "
        "``.keras`` on the extension alone, and the ambiguous ``.bin`` / "
        "``.h5`` / ``.hdf5`` only when the name looks like a model "
        "(``pytorch_model.bin``) or a model config / Modelfile sits "
        "alongside. ``.safetensors`` / ``.gguf`` / ``.onnx`` are the safe "
        "formats and never fire. A format / provenance check, not "
        "pickle-opcode analysis (ModelScan / ModelAudit own that). The "
        "tree-wide complement of MODEL-003's Modelfile ``FROM`` reference."
    ),
    known_fp=(
        "Committing a model in a pickle format is often intentional (a "
        "small ``.pkl`` preprocessor, a legacy ``.pt`` checkpoint). The "
        "finding is a format-hygiene signal, not proof of tampering; "
        "suppress with a rationale where safetensors / GGUF isn't an "
        "option and the file's checksum is verified out of band.",
    ),
)


def check(ctx: ModelfileContext) -> list[Finding]:
    offenders = ctx.weight_blobs
    passed = not offenders
    if passed:
        desc = (
            "No committed model weights use a code-executing serialization "
            "format."
        )
        locations: list[Location] = []
    else:
        labels = [f"{b.path} ({b.ext})" for b in offenders]
        desc = (
            f"{len(offenders)} committed model artifact(s) use a "
            f"code-executing serialization format that deserializes "
            f"arbitrary code at load: {summarize_offenders(labels, limit=5)}. "
            "Prefer safetensors / GGUF."
        )
        locations = [
            Location(path=b.path, start_line=1, end_line=1)
            for b in offenders[:20]
        ]
    return [RULE.finding(ctx.root, desc, passed=passed, locations=locations)]
