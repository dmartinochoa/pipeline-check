"""GHA-120. ML model loaded with trust_remote_code (code execution).

``trust_remote_code=True`` (or ``--trust-remote-code``) tells the
transformers / huggingface_hub loader to execute the *model repo's own
Python* (``modeling_*.py``, custom pipelines) at load time. In CI that is
arbitrary code execution sourced from a model registry: a poisoned or
typosquatted model, or a compromised upstream, runs with the job's
secrets and token. Pinning the revision limits the blast radius but does
not remove the execution path; the safe default is the library default
(``trust_remote_code=False``).
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-120",
    title="ML model loaded with trust_remote_code (code execution)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-494", "CWE-829"),
    recommendation=(
        "Load models with ``trust_remote_code=False`` (the library "
        "default). If a model genuinely needs custom code, vet it and pin "
        "an exact revision (a commit SHA, not a tag or branch), run the "
        "load in a sandboxed job with no production secrets, and prefer "
        "safetensors weights over pickle."
    ),
    docs_note=(
        "Fires on ``trust_remote_code=True`` / ``--trust-remote-code`` in a "
        "``run:`` step. The transformers / huggingface_hub loader executes "
        "the model repo's own Python at load time, so an untrusted or "
        "unpinned model is arbitrary code execution in CI with the job's "
        "secrets and token."
    ),
)

_TRUST_REMOTE_RE = re.compile(
    r"trust_remote_code\s*=\s*True|--trust[-_]remote[-_]code\b",
    re.IGNORECASE,
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    anchor_jobs: dict[str, None] = {}
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if isinstance(run, str) and _TRUST_REMOTE_RE.search(run):
                offenders.append(f"{job_id}[{idx}]")
                locations.append(step_location(path, step))
                anchor_jobs[job_id] = None
    passed = not offenders
    desc = (
        "No step loads a model with trust_remote_code enabled."
        if passed else
        "A step loads an ML model with trust_remote_code enabled, which "
        "executes the model repo's own Python at load time, in: "
        f"{', '.join(offenders)}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        job_anchors=tuple(anchor_jobs),
    )
