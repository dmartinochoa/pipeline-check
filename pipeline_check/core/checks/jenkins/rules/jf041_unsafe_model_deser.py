"""JF-041. Unsafe deserialization of a fetched artifact (pickle RCE)."""
from __future__ import annotations

from ..._primitives.unsafe_deser import unsafe_deser_label
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import SHELL_STEP_RE

RULE = Rule(
    id="JF-041",
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
        "and verify its source (a pinned revision, a checksum, a "
        "signature) and load it in a stage with no production credentials "
        "bound."
    ),
    docs_note=(
        "Reuses the shared ``unsafe_deser`` detector (with GHA-122 / "
        "GL-047 / BB-037 / ADO-036 / HARNESS-011) over each ``sh`` / "
        "``bat`` / ``powershell`` step body. Fires in two shapes: (A) an "
        "explicit unsafe opt-in (``weights_only=False`` on a load, or "
        "``allow_pickle=True`` on ``numpy.load``), always; and (B) a remote "
        "fetch (``curl`` / ``wget`` / ``hf_hub_download`` / "
        "``snapshot_download`` / ``huggingface-cli download`` / "
        "``requests.get`` / ``urlretrieve``) together with a pickle-backed "
        "loader (``torch.load`` / ``pickle.load(s)`` / ``joblib.load``) in "
        "the same step, with no safe path (``weights_only=True`` / "
        "safetensors). A bare local unpickle with no fetch does not fire."
    ),
    exploit_example=(
        "// Vulnerable: fetch a checkpoint and unpickle it -- arbitrary\n"
        "// Python embedded in the file runs on the agent under the\n"
        "// build's secrets.\n"
        "sh '''curl -fsSL -o m.pt https://example.com/m.pt\n"
        "      python -c \"import torch; torch.load('m.pt')\"'''\n"
        "\n"
        "// Safe: safetensors, or torch.load(..., weights_only=True).\n"
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    text = jf.text_no_comments
    for m in SHELL_STEP_RE.finditer(text):
        body = (
            m.group("triple_d") or m.group("triple_s")
            or m.group("dq") or m.group("sq") or ""
        )
        label = unsafe_deser_label(body)
        if label:
            line_no = text[: m.start()].count("\n") + 1
            offenders.append(f"line {line_no} ({label})")
            locations.append(Location(
                path=jf.path, start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        "No step unsafely deserializes a fetched artifact."
        if passed else
        f"{len(offenders)} step(s) unsafely deserialize an artifact "
        f"(pickle-backed load of fetched / opt-in-unsafe data, code "
        f"execution on the agent): {'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
