"""JF-039. ML model loaded with trust_remote_code (code execution).

The Jenkins analog of GHA-120 / GL-045 / BB-035 / ADO-034 / HARNESS-010,
and the model-load face of JF-037 (agentic-CLI prompt injection). A
``sh`` / ``bat`` / ``powershell`` step loads a Hugging Face model with
``trust_remote_code=True`` (or ``--trust-remote-code``), so the
transformers / huggingface_hub loader executes the model repo's own
``modeling_*.py`` at load time. A poisoned, typosquatted, or simply
unpinned model is then arbitrary code execution on the Jenkins agent,
with the build's credentials and the controller in reach. Brings the
model-load supply-chain coverage the other CI providers carry to the
Jenkinsfile.
"""
from __future__ import annotations

from ..._primitives.model_trust import TRUST_REMOTE_CODE_RE
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import SHELL_STEP_RE

RULE = Rule(
    id="JF-039",
    title="ML model loaded with trust_remote_code (code execution)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-494", "CWE-829"),
    recommendation=(
        "Load models with ``trust_remote_code=False`` (the library "
        "default). If a model genuinely needs custom code, vet it and pin "
        "an exact revision (a commit SHA, not a tag or branch), run the "
        "load in a stage with no production credentials bound, and prefer "
        "safetensors weights over pickle."
    ),
    docs_note=(
        "Fires on ``trust_remote_code=True`` / ``--trust-remote-code`` in a "
        "``sh`` / ``bat`` / ``powershell`` step body (the shared "
        "``model_trust`` detector, with GHA-120 / GL-045 / BB-035 / "
        "ADO-034 / HARNESS-010). Groovy quoting does not defang it: the "
        "loader runs the model repo's own Python regardless of how the "
        "command string is quoted, so both single- and double-quoted step "
        "bodies are flagged. The transformers / huggingface_hub loader "
        "executes that code at load time, so an untrusted or unpinned model "
        "is arbitrary code execution on the agent with the build's "
        "credentials in scope."
    ),
    exploit_example=(
        "// Vulnerable: the loader runs the model repo's own modeling_*.py\n"
        "// at load time -- a poisoned / typosquatted model is RCE on the agent.\n"
        "sh '''python -c \"from transformers import AutoModel; \\\n"
        "  AutoModel.from_pretrained('x/y', trust_remote_code=True)\"'''\n"
        "\n"
        "// Safe: trust_remote_code=False (the default) + a pinned revision.\n"
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
        if TRUST_REMOTE_CODE_RE.search(body):
            line_no = text[: m.start()].count("\n") + 1
            offenders.append(f"line {line_no}")
            locations.append(Location(
                path=jf.path, start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        "No step loads a model with trust_remote_code enabled."
        if passed else
        f"Step(s) at {', '.join(offenders)} load an ML model with "
        f"trust_remote_code enabled, executing the model repo's own Python "
        f"at load time, so a poisoned or unpinned model is code execution "
        f"on the Jenkins agent."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
