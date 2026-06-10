"""HARNESS-011. Unsafe deserialization of a fetched artifact (pickle RCE)."""
from __future__ import annotations

from ..._primitives.unsafe_deser import unsafe_deser_label
from ...base import Finding, Severity
from ...rule import Rule
from ..base import HarnessPipeline, iter_steps, step_command_text, step_label

RULE = Rule(
    id="HARNESS-011",
    title="Unsafe deserialization of a fetched artifact (pickle RCE)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-502", "CWE-494", "CWE-829"),
    recommendation=(
        "Don't deserialize a downloaded artifact through pickle. Load "
        "weights with safetensors, or pass ``weights_only=True`` to "
        "``torch.load`` (the PyTorch 2.6+ default) so only tensors, not "
        "arbitrary Python, are unpickled. Drop ``allow_pickle=True`` from "
        "``numpy.load``. If a pickle / joblib artifact is unavoidable, pin "
        "and verify its source (a pinned revision, a checksum, a "
        "signature) and load it in an isolated stage with no production "
        "secrets."
    ),
    docs_note=(
        "Reuses the shared ``unsafe_deser`` detector (with GHA-122 / "
        "GL-047 / BB-037 / ADO-036) over each step's ``command``. Fires in "
        "two shapes: (A) an explicit unsafe opt-in (``weights_only=False`` "
        "on a load, or ``allow_pickle=True`` on ``numpy.load``), always; "
        "and (B) a remote fetch (``curl`` / ``wget`` / ``hf_hub_download`` "
        "/ ``snapshot_download`` / ``huggingface-cli download`` / "
        "``requests.get`` / ``urlretrieve``) together with a pickle-backed "
        "loader (``torch.load`` / ``pickle.load(s)`` / ``joblib.load``) in "
        "the same step, with no safe path (``weights_only=True`` / "
        "safetensors). A bare local unpickle with no fetch does not fire."
    ),
    exploit_example=(
        "# Vulnerable: fetch a checkpoint and unpickle it -- arbitrary\n"
        "# Python embedded in the file runs under the run's secrets.\n"
        "- step:\n"
        "    type: Run\n"
        "    identifier: load\n"
        "    spec:\n"
        "      image: python@sha256:...\n"
        "      command: |\n"
        "        curl -fsSL -o m.pt https://example.com/m.pt\n"
        "        python -c 'import torch; torch.load(\"m.pt\")'\n"
        "\n"
        "# Safe: safetensors, or torch.load(..., weights_only=True).\n"
    ),
)


def check(pipeline: HarnessPipeline) -> Finding:
    offenders: list[str] = []
    for stage_id, step in iter_steps(pipeline):
        text = step_command_text(step)
        if not text:
            continue
        label = unsafe_deser_label(text)
        if label:
            offenders.append(f"{step_label(stage_id, step)} ({label})")
    passed = not offenders
    desc = (
        "No step unsafely deserializes a fetched artifact."
        if passed else
        f"{len(offenders)} step(s) unsafely deserialize an artifact "
        f"(pickle-backed load of fetched / opt-in-unsafe data, code "
        f"execution): {'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
