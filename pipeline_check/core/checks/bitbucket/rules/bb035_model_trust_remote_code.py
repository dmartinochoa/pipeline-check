"""BB-035. ML model loaded with trust_remote_code (code execution).

``trust_remote_code=True`` (or ``--trust-remote-code``) tells the
transformers / huggingface_hub loader to execute the *model repo's own
Python* (``modeling_*.py``, custom pipelines) at load time. In a Bitbucket
Pipelines ``script:`` that is arbitrary code execution sourced from a model
registry: a poisoned or typosquatted model, or a compromised upstream,
runs with the step's repository / deployment credentials. Pinning the
revision limits the blast radius but does not remove the execution path;
the safe default is the library default (``trust_remote_code=False``).

The Bitbucket analog of GHA-120 / GL-045.
"""
from __future__ import annotations

from typing import Any

from ..._primitives.model_trust import TRUST_REMOTE_CODE_RE
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_steps, step_scripts_all

RULE = Rule(
    id="BB-035",
    title="ML model loaded with trust_remote_code (code execution)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-494", "CWE-829"),
    recommendation=(
        "Load models with ``trust_remote_code=False`` (the library "
        "default). If a model genuinely needs custom code, vet it and pin "
        "an exact revision (a commit SHA, not a tag or branch), run the "
        "load in a step scoped to no production deployment credentials, "
        "and prefer safetensors weights over pickle."
    ),
    docs_note=(
        "Fires on ``trust_remote_code=True`` / ``--trust-remote-code`` in a "
        "step's ``script``. The transformers / huggingface_hub loader "
        "executes the model repo's own Python at load time, so an untrusted "
        "or unpinned model is arbitrary code execution in the pipeline with "
        "the step's credentials in scope."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for loc, step in iter_steps(doc):
        if any(TRUST_REMOTE_CODE_RE.search(s) for s in step_scripts_all(step)):
            offenders.append(loc)
            line = _line_of(step) if isinstance(step, dict) else None
            locations.append(Location(path=path, start_line=line, end_line=line))
    passed = not offenders
    desc = (
        "No step loads a model with trust_remote_code enabled."
        if passed else
        "A step loads an ML model with trust_remote_code enabled, which "
        "executes the model repo's own Python at load time, in: "
        f"{', '.join(sorted(set(offenders)))}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
