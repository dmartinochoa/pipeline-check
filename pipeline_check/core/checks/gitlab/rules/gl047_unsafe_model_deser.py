"""GL-047. Unsafe deserialization of a fetched artifact (pickle RCE).

Loading a model / artifact through a pickle-backed deserializer executes
arbitrary Python embedded in the file at load time. In a GitLab CI
``script`` the artifact is routinely *downloaded* (a Hugging Face
checkpoint, a release asset, an ``hf_hub_download`` path) rather than
locally produced, so it is remote code execution under the job's
``CI_JOB_TOKEN`` and secrets. ``torch.load`` used the pickle path by
default before PyTorch 2.6; ``pickle.load`` / ``joblib.load`` have no safe
mode; ``numpy.load(..., allow_pickle=True)`` opts back into it explicitly.

Two firing shapes (see ``_primitives/unsafe_deser``): an explicit unsafe
opt-in (``weights_only=False`` / ``allow_pickle=True``) always fires, and a
remote fetch alongside a pickle-backed loader with no safe path in the same
job fires as the download-then-unpickle RCE vector.

The GitLab analog of GHA-122, and the deserialization leg of the GitLab
AI/model pack alongside GL-045 (``trust_remote_code``) and GL-046 (unpinned
model ref).
"""
from __future__ import annotations

from typing import Any

from ..._primitives.unsafe_deser import unsafe_deser_label
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, job_scripts

RULE = Rule(
    id="GL-047",
    title="Unsafe deserialization of a fetched artifact (pickle RCE)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-502", "CWE-494", "CWE-829"),
    recommendation=(
        "Don't deserialize a downloaded artifact through pickle. Load "
        "weights with safetensors, or pass ``weights_only=True`` to "
        "``torch.load`` (the PyTorch 2.6+ default) so only tensors, not "
        "arbitrary Python, are unpickled. Drop ``allow_pickle=True`` from "
        "``numpy.load``. If a pickle / joblib artifact is unavoidable, pin "
        "and verify its source (a pinned model revision, a checksum, or a "
        "signature) and load it in a job scoped to no production secrets, "
        "not one carrying the ``CI_JOB_TOKEN`` and pipeline credentials."
    ),
    docs_note=(
        "Fires per job (across ``script`` / ``before_script`` / "
        "``after_script``) in two shapes. **(A) Explicit unsafe opt-in**, "
        "always: ``weights_only=False`` on a load, or ``allow_pickle=True`` "
        "on ``numpy.load`` / ``np.load``. **(B) Fetch + unpickle**, only "
        "when both appear in the same job: a remote fetch (``curl`` / "
        "``wget`` / ``hf_hub_download`` / ``snapshot_download`` / "
        "``huggingface-cli download`` / ``hf download`` / ``requests.get`` "
        "/ ``urlretrieve`` / ``urlopen``) alongside a pickle-backed loader "
        "(``torch.load`` / ``pickle.load`` / ``pickle.loads`` / "
        "``joblib.load``).\n\n"
        "Does NOT fire when the job takes the safe path "
        "(``weights_only=True``, or safetensors via ``safe_open`` / "
        "``load_file``), nor on a bare ``torch.load`` / ``pickle.load`` "
        "with no remote fetch in the same job (a load of a locally "
        "produced, trusted artifact)."
    ),
    known_fp=(
        "A job that downloads a non-pickle file for one purpose and "
        "separately unpickles a trusted local file for another would match "
        "shape B by co-location. Split the two concerns into separate jobs, "
        "or suppress on the specific job with a rationale naming the "
        "artifact's verified source.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for job_id, job in iter_jobs(doc):
        body = "\n".join(job_scripts(job))
        label = unsafe_deser_label(body)
        if label is not None:
            offenders.append(f"{job_id}: {label}")
            line = _line_of(job)
            locations.append(Location(path=path, start_line=line, end_line=line))
    passed = not offenders
    desc = (
        "No job deserializes a fetched artifact through pickle without the "
        "safe path."
        if passed else
        f"{len(offenders)} job(s) run an unsafe deserialization that "
        f"executes arbitrary code embedded in the artifact at load time: "
        f"{', '.join(offenders[:5])}{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
