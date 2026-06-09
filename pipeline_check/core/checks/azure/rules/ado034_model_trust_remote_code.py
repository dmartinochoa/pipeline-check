"""ADO-034. ML model loaded with trust_remote_code (code execution).

``trust_remote_code=True`` (or ``--trust-remote-code``) tells the
transformers / huggingface_hub loader to execute the *model repo's own
Python* (``modeling_*.py``, custom pipelines) at load time. In an Azure
Pipelines ``script:`` / ``bash:`` / ``pwsh:`` step that is arbitrary code
execution sourced from a model registry: a poisoned or typosquatted
model, or a compromised upstream, runs with the agent's service-connection
credentials and secrets. Pinning the revision limits the blast radius but
does not remove the execution path; the safe default is the library
default (``trust_remote_code=False``).

The Azure DevOps analog of GHA-120 / GL-045 / BB-035, completing the
``trust_remote_code`` coverage across the script-based CI providers.
"""
from __future__ import annotations

from typing import Any

from ..._primitives.model_trust import TRUST_REMOTE_CODE_RE
from ..._yaml_lines import line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="ADO-034",
    title="ML model loaded with trust_remote_code (code execution)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-494", "CWE-829"),
    recommendation=(
        "Load models with ``trust_remote_code=False`` (the library "
        "default). If a model genuinely needs custom code, vet it and pin "
        "an exact revision (a commit SHA, not a tag or branch), run the "
        "load in a job scoped to no production service connections, and "
        "prefer safetensors weights over pickle."
    ),
    docs_note=(
        "Fires on ``trust_remote_code=True`` / ``--trust-remote-code`` in a "
        "step's ``script`` / ``bash`` / ``pwsh`` / ``powershell`` body or a "
        "task-based step's ``inputs.script``. The transformers / "
        "huggingface_hub loader executes the model repo's own Python at "
        "load time, so an untrusted or unpinned model is arbitrary code "
        "execution on the agent with its credentials in scope."
    ),
)


def _step_bodies(step: dict[str, Any]) -> list[str]:
    bodies = [
        step[key] for key in ("script", "bash", "pwsh", "powershell")
        if isinstance(step.get(key), str)
    ]
    inputs = step.get("inputs")
    if isinstance(inputs, dict) and isinstance(inputs.get("script"), str):
        bodies.append(inputs["script"])
    return bodies


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    seen_step_lines: set[int] = set()
    for job_loc, job in iter_jobs(doc):
        for step_loc, step in iter_steps(job):
            if any(TRUST_REMOTE_CODE_RE.search(b) for b in _step_bodies(step)):
                offenders.append(f"{job_loc}.{step_loc}")
                line = line_of(step)
                if line is not None and line not in seen_step_lines:
                    seen_step_lines.add(line)
                    locations.append(
                        Location(path=path, start_line=line, end_line=line)
                    )
    passed = not offenders
    desc = (
        "No step loads a model with trust_remote_code enabled."
        if passed else
        "A step loads an ML model with trust_remote_code enabled, which "
        "executes the model repo's own Python at load time, in: "
        f"{', '.join(sorted(set(offenders))[:5])}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
