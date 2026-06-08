"""GHA-122. Unsafe deserialization of a fetched artifact (pickle RCE).

Loading a model / artifact through a pickle-backed deserializer executes
arbitrary Python embedded in the file at load time. In CI, where the file
is routinely *downloaded* (a Hugging Face checkpoint, a release asset, an
``hf_hub_download`` path) rather than locally produced, that is remote
code execution under the job's secrets and token. ``torch.load`` used the
pickle path by default before PyTorch 2.6; ``pickle.load`` / ``joblib.load``
have no safe mode; ``numpy.load(..., allow_pickle=True)`` opts back into
it explicitly.

Two firing shapes, both scoped to one ``run:`` step:

  A. **Explicit unsafe opt-in** (always fires): ``weights_only=False`` on
     a load, or ``allow_pickle=True`` on ``numpy.load``. These are
     unambiguous "I accept arbitrary code execution" switches.

  B. **Fetch + unpickle** (fires only together): the step both fetches a
     remote artifact (``curl`` / ``wget`` / ``hf_hub_download`` /
     ``snapshot_download`` / ``huggingface-cli download`` / ``requests``)
     AND deserializes via a pickle-backed loader (``torch.load`` /
     ``pickle.load(s)`` / ``joblib.load``), with no safe path
     (``weights_only=True`` or safetensors) in the same step. The
     download-then-unpickle pair is the actual RCE vector; a pickle load
     of a purely local, self-produced file does not fetch and does not
     fire.

Pairs with GHA-120 (``trust_remote_code``) and GHA-121 (unpinned model
ref) as the deserialization leg of the AI/LLM-pipeline pack.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-122",
    title="Unsafe deserialization of a fetched artifact (pickle RCE)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-502", "CWE-494", "CWE-829"),
    recommendation=(
        "Don't deserialize a downloaded artifact through pickle. Load "
        "weights with safetensors, or pass ``weights_only=True`` to "
        "``torch.load`` (the PyTorch 2.6+ default) so only tensors, not "
        "arbitrary Python, are unpickled. Drop ``allow_pickle=True`` from "
        "``numpy.load``. If a pickle / joblib artifact is unavoidable, "
        "pin and verify its source (a pinned model revision, a checksum, "
        "or a signature) and load it in a sandboxed job with no production "
        "secrets, not on the default runner with the workflow token in "
        "scope."
    ),
    docs_note=(
        "Fires per ``run:`` step in two shapes. **(A) Explicit unsafe "
        "opt-in**, always: ``weights_only=False`` on a load, or "
        "``allow_pickle=True`` on ``numpy.load`` / ``np.load``. **(B) "
        "Fetch + unpickle**, only when both appear in the same step: a "
        "remote fetch (``curl`` / ``wget`` / ``hf_hub_download`` / "
        "``snapshot_download`` / ``huggingface-cli download`` / ``hf "
        "download`` / ``requests.get`` / ``urlretrieve`` / ``urlopen``) "
        "alongside a pickle-backed loader (``torch.load`` / "
        "``pickle.load`` / ``pickle.loads`` / ``joblib.load``).\n\n"
        "Does NOT fire when the step takes the safe path "
        "(``weights_only=True``, or safetensors via ``safe_open`` / "
        "``load_file``), nor on a bare ``torch.load`` / ``pickle.load`` "
        "with no remote fetch in the same step (a load of a locally "
        "produced, trusted artifact). The fetch-and-unpickle coupling is "
        "what raises it from a hygiene nudge to a code-execution finding."
    ),
    known_fp=(
        "A step that downloads a non-pickle file for one purpose and "
        "separately unpickles a trusted local file for another would "
        "match shape B by co-location. Split the two concerns into "
        "separate steps, or suppress on the specific step with a "
        "rationale naming the artifact's verified source.",
    ),
)

# Explicit, unambiguous opt-ins to unsafe deserialization.
_EXPLICIT_UNSAFE_RE = re.compile(
    r"weights_only\s*=\s*False|allow_pickle\s*=\s*True",
    re.IGNORECASE,
)

# Pickle-backed loaders (the unsafe deserialization sinks).
_PICKLE_LOADER_RE = re.compile(
    r"\b(?:torch\.load|c?pickle\.loads?|joblib\.load)\s*\(",
    re.IGNORECASE,
)

# A remote artifact fetch in the same step.
_FETCH_RE = re.compile(
    r"\b(?:curl|wget)\b"
    r"|\b(?:hf_hub_download|snapshot_download|urlretrieve|urlopen)\s*\("
    r"|\brequests\.(?:get|post)\s*\("
    r"|\bhuggingface-cli\s+download\b"
    r"|\bhf\s+download\b",
    re.IGNORECASE,
)

# The safe path: tensor-only torch load, or safetensors.
_SAFE_PATH_RE = re.compile(
    r"weights_only\s*=\s*True|\bsafetensors\b|\b(?:safe_open|load_file)\s*\(",
    re.IGNORECASE,
)


def _unsafe_deser_label(body: str) -> str | None:
    """Return a short label for the unsafe shape in *body*, or ``None``."""
    if _EXPLICIT_UNSAFE_RE.search(body):
        return "explicit unsafe opt-in (weights_only=False / allow_pickle=True)"
    if (
        _PICKLE_LOADER_RE.search(body)
        and _FETCH_RE.search(body)
        and not _SAFE_PATH_RE.search(body)
    ):
        return "fetched artifact deserialized via pickle"
    return None


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    anchor_jobs: dict[str, None] = {}
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            label = _unsafe_deser_label(run)
            if label is not None:
                offenders.append(f"{job_id}[{idx}]: {label}")
                locations.append(step_location(path, step))
                anchor_jobs[job_id] = None
    passed = not offenders
    desc = (
        "No step deserializes a fetched artifact through pickle without "
        "the safe path."
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
        job_anchors=tuple(anchor_jobs),
    )
