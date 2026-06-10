"""HARNESS-010. ML model loaded with trust_remote_code (code execution)."""
from __future__ import annotations

from ..._primitives.model_trust import TRUST_REMOTE_CODE_RE
from ...base import Finding, Severity
from ...rule import Rule
from ..base import HarnessPipeline, iter_steps, step_command_text, step_label

RULE = Rule(
    id="HARNESS-010",
    title="ML model loaded with trust_remote_code (code execution)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-494", "CWE-829"),
    recommendation=(
        "Load models with ``trust_remote_code=False`` (the library "
        "default). If a model genuinely needs custom code, vet it and pin "
        "an exact revision (a commit SHA, not a tag or branch), run the "
        "load in an isolated stage with no production secrets, and prefer "
        "safetensors weights over pickle."
    ),
    docs_note=(
        "Fires on ``trust_remote_code=True`` / ``--trust-remote-code`` in a "
        "step ``command`` (the shared ``model_trust`` detector, with "
        "GHA-120 / GL-045 / BB-035 / ADO-034). The transformers / "
        "huggingface_hub loader executes the model repo's own Python at "
        "load time, so an untrusted or unpinned model is arbitrary code "
        "execution in the pipeline with the run's secrets and connectors "
        "in scope."
    ),
    exploit_example=(
        "# Vulnerable: the loader runs the model repo's own modeling_*.py\n"
        "# at load time -- a poisoned / typosquatted model is RCE in CI.\n"
        "- step:\n"
        "    type: Run\n"
        "    identifier: load\n"
        "    spec:\n"
        "      image: python@sha256:...\n"
        "      command: |\n"
        "        python -c 'from transformers import AutoModel; \\\n"
        "          AutoModel.from_pretrained(\"x/y\", trust_remote_code=True)'\n"
        "\n"
        "# Safe: trust_remote_code=False (the default) + a pinned revision.\n"
    ),
)


def check(pipeline: HarnessPipeline) -> Finding:
    offenders: list[str] = []
    for stage_id, step in iter_steps(pipeline):
        text = step_command_text(step)
        if text and TRUST_REMOTE_CODE_RE.search(text):
            offenders.append(step_label(stage_id, step))
    passed = not offenders
    desc = (
        "No step loads a model with trust_remote_code enabled."
        if passed else
        f"{len(offenders)} step(s) load an ML model with trust_remote_code "
        f"enabled, executing the model repo's own Python at load time: "
        f"{'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
