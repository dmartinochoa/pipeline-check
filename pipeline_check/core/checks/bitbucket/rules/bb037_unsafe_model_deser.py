"""BB-037. Unsafe deserialization of a fetched artifact (pickle RCE).

Loading a model / artifact through a pickle-backed deserializer executes
arbitrary Python embedded in the file at load time. In a Bitbucket
``script:`` the artifact is routinely *downloaded* (a Hugging Face
checkpoint, a release asset, an ``hf_hub_download`` path) rather than
locally produced, so it is remote code execution under the pipeline's
secrets. ``torch.load`` used the pickle path by default before PyTorch
2.6; ``pickle.load`` / ``joblib.load`` have no safe mode;
``numpy.load(..., allow_pickle=True)`` opts back into it explicitly.

Two firing shapes (see ``_primitives/unsafe_deser``): an explicit unsafe
opt-in (``weights_only=False`` / ``allow_pickle=True``) always fires, and a
remote fetch alongside a pickle-backed loader with no safe path in the same
step fires as the download-then-unpickle RCE vector.

The Bitbucket analog of GHA-122 / GL-047, and the deserialization leg of
the Bitbucket AI/model pack alongside BB-035 (``trust_remote_code``).
"""
from __future__ import annotations

from typing import Any

from ..._primitives.unsafe_deser import unsafe_deser_label
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_steps, step_scripts_all

RULE = Rule(
    id="BB-037",
    title="Unsafe deserialization of a fetched artifact (pickle RCE)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-502", "CWE-494", "CWE-829"),
    recommendation=(
        "Load models / artifacts through a non-executing format: prefer "
        "``safetensors``, or pass ``weights_only=True`` to ``torch.load`` "
        "(default in PyTorch 2.6+). Never ``pickle.load`` / ``joblib.load`` "
        "/ ``numpy.load(allow_pickle=True)`` a file fetched at build time, "
        "and pin + checksum any model you must deserialize."
    ),
    docs_note=(
        "Fires per ``script:`` step in two shapes (shared with GHA-122 / "
        "GL-047 via ``_primitives/unsafe_deser``): an explicit unsafe opt-in "
        "(``weights_only=False`` / ``allow_pickle=True``) always; or a remote "
        "fetch (curl / wget / ``hf_hub_download`` / ``snapshot_download`` / "
        "``huggingface-cli download`` / ``requests``) alongside a "
        "pickle-backed loader (``torch.load`` / ``pickle.load(s)`` / "
        "``joblib.load``) with no safe path (``weights_only=True`` or "
        "safetensors) in the same step. A bare local load with no fetch does "
        "not fire."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for loc, step in iter_steps(doc):
        body = "\n".join(step_scripts_all(step))
        label = unsafe_deser_label(body)
        if label is not None:
            offenders.append(f"{loc}: {label}")
            line = _line_of(step) if isinstance(step, dict) else None
            locations.append(Location(path=path, start_line=line, end_line=line))
    passed = not offenders
    desc = (
        "No step deserializes a fetched artifact through pickle without the "
        "safe path."
        if passed else
        f"{len(offenders)} step(s) run an unsafe deserialization that "
        f"executes arbitrary code embedded in the artifact at load time: "
        f"{', '.join(offenders[:5])}{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
