"""GL-045. ML model loaded with trust_remote_code (code execution).

``trust_remote_code=True`` (or ``--trust-remote-code``) tells the
transformers / huggingface_hub loader to execute the *model repo's own
Python* (``modeling_*.py``, custom pipelines) at load time. In a GitLab
CI ``script:`` that is arbitrary code execution sourced from a model
registry: a poisoned or typosquatted model, or a compromised upstream,
runs with the job's ``CI_JOB_TOKEN`` and secrets. Pinning the revision
limits the blast radius but does not remove the execution path; the safe
default is the library default (``trust_remote_code=False``).

The GitLab analog of GHA-120.
"""
from __future__ import annotations

import re
from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, job_scripts

RULE = Rule(
    id="GL-045",
    title="ML model loaded with trust_remote_code (code execution)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-494", "CWE-829"),
    recommendation=(
        "Load models with ``trust_remote_code=False`` (the library "
        "default). If a model genuinely needs custom code, vet it and pin "
        "an exact revision (a commit SHA, not a tag or branch), run the "
        "load in a job scoped to no production secrets, and prefer "
        "safetensors weights over pickle."
    ),
    docs_note=(
        "Fires on ``trust_remote_code=True`` / ``--trust-remote-code`` in a "
        "job's ``script`` / ``before_script`` / ``after_script``. The "
        "transformers / huggingface_hub loader executes the model repo's "
        "own Python at load time, so an untrusted or unpinned model is "
        "arbitrary code execution in CI with the job's ``CI_JOB_TOKEN`` "
        "and secrets."
    ),
)

_TRUST_REMOTE_RE = re.compile(
    r"trust_remote_code\s*=\s*True|--trust[-_]remote[-_]code\b",
    re.IGNORECASE,
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for job_id, job in iter_jobs(doc):
        if any(_TRUST_REMOTE_RE.search(line) for line in job_scripts(job)):
            offenders.append(job_id)
            line = _line_of(job)
            locations.append(Location(path=path, start_line=line, end_line=line))
    passed = not offenders
    desc = (
        "No job loads a model with trust_remote_code enabled."
        if passed else
        "A job loads an ML model with trust_remote_code enabled, which "
        "executes the model repo's own Python at load time, in: "
        f"{', '.join(offenders[:5])}{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
