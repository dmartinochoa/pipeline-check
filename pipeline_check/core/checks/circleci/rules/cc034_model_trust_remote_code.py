"""CC-034. ML model loaded with trust_remote_code (code execution)."""
from __future__ import annotations

from typing import Any

from ..._primitives.model_trust import TRUST_REMOTE_CODE_RE
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_run_commands

RULE = Rule(
    id="CC-034",
    title="ML model loaded with trust_remote_code (code execution)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-494", "CWE-829"),
    recommendation=(
        "Load models with ``trust_remote_code=False`` (the library "
        "default). If a model genuinely needs custom code, vet it and pin "
        "an exact revision (a commit SHA, not a tag or branch), run the "
        "load in a job with no production context bound, and prefer "
        "safetensors weights over pickle."
    ),
    docs_note=(
        "Scans every ``run:`` command across all jobs for "
        "``trust_remote_code=True`` / ``--trust-remote-code`` (the shared "
        "``model_trust`` detector, with GHA-120 / GL-045 / BB-035 / "
        "ADO-034 / HARNESS-010 / JF-039). The transformers / "
        "huggingface_hub loader executes the model repo's own Python at "
        "load time, so an untrusted or unpinned model is arbitrary code "
        "execution on the runner with the job's context secrets and OIDC "
        "in scope. The first AI model-load rule for CircleCI."
    ),
    exploit_example=(
        "# Vulnerable: the loader runs the model repo's own modeling_*.py\n"
        "# at load time -- a poisoned / typosquatted model is RCE on the runner.\n"
        "jobs:\n"
        "  train:\n"
        "    docker:\n"
        "      - image: cimg/python:3.12\n"
        "    steps:\n"
        "      - run: python -c \"from transformers import AutoModel; "
        "AutoModel.from_pretrained('x/y', trust_remote_code=True)\"\n"
        "\n"
        "# Safe: trust_remote_code=False (the default) + a pinned revision.\n"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for cmd in iter_run_commands(job):
            if TRUST_REMOTE_CODE_RE.search(cmd):
                offenders.append(job_id)
                break
    passed = not offenders
    desc = (
        "No run step loads a model with trust_remote_code enabled."
        if passed else
        f"{len(offenders)} job(s) load an ML model with trust_remote_code "
        f"enabled, executing the model repo's own Python at load time: "
        f"{', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
