"""ADO-036. Unsafe deserialization of a fetched artifact (pickle RCE).

Loading a model / artifact through a pickle-backed deserializer executes
arbitrary Python embedded in the file at load time. In an Azure Pipelines
script the artifact is routinely *downloaded* (a Hugging Face checkpoint,
a release asset, an ``hf_hub_download`` path) rather than locally
produced, so it is remote code execution under the job's service-connection
credentials and secrets. ``torch.load`` used the pickle path by default
before PyTorch 2.6; ``pickle.load`` / ``joblib.load`` have no safe mode;
``numpy.load(..., allow_pickle=True)`` opts back into it explicitly.

Two firing shapes (see ``_primitives/unsafe_deser``): an explicit unsafe
opt-in (``weights_only=False`` / ``allow_pickle=True``) always fires, and a
remote fetch alongside a pickle-backed loader with no safe path in the same
script body fires as the download-then-unpickle RCE vector.

The Azure DevOps analog of GHA-122 / GL-047, and the deserialization leg of
the Azure AI/model pack alongside ADO-034 (``trust_remote_code``).
"""
from __future__ import annotations

from typing import Any

from ..._primitives.unsafe_deser import unsafe_deser_label
from ..._yaml_lines import line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="ADO-036",
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
        "Fires per script body (``script`` / ``bash`` / ``pwsh`` / "
        "``powershell`` or a task-based step's ``inputs.script``) in two "
        "shapes (shared with GHA-122 / GL-047 via "
        "``_primitives/unsafe_deser``): an explicit unsafe opt-in "
        "(``weights_only=False`` / ``allow_pickle=True``) always; or a remote "
        "fetch (curl / wget / ``hf_hub_download`` / ``snapshot_download`` / "
        "``huggingface-cli download`` / ``requests``) alongside a "
        "pickle-backed loader (``torch.load`` / ``pickle.load(s)`` / "
        "``joblib.load``) with no safe path (``weights_only=True`` or "
        "safetensors) in the same body. A bare local load with no fetch does "
        "not fire."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    seen_lines: set[int] = set()
    for job_loc, job in iter_jobs(doc):
        for step_loc, step in iter_steps(job):
            bodies: list[str] = [
                step[key] for key in ("script", "bash", "pwsh", "powershell")
                if isinstance(step.get(key), str)
            ]
            inputs = step.get("inputs")
            if isinstance(inputs, dict) and isinstance(inputs.get("script"), str):
                bodies.append(inputs["script"])
            for body in bodies:
                label = unsafe_deser_label(body)
                if label is None:
                    continue
                offenders.append(f"{job_loc}.{step_loc}: {label}")
                step_line = line_of(step)
                if step_line is not None and step_line not in seen_lines:
                    seen_lines.add(step_line)
                    locations.append(Location(
                        path=path, start_line=step_line, end_line=step_line,
                    ))
                break
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
