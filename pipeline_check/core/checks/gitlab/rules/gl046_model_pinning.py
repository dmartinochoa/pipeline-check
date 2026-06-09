"""GL-046. AI model pulled from a mutable (unpinned) registry ref.

A GitLab CI job ``script`` fetches a model from a model registry (Hugging
Face Hub and friends) by a *mutable* reference: ``from_pretrained(
"org/model")``, ``hf_hub_download`` / ``snapshot_download`` with a bare
``repo_id``, or ``huggingface-cli download org/model`` with no
``--revision``. Without a pinned revision the registry serves whatever the
repo's default branch points at *now*, so the model owner (or anyone who
compromises the account or the upstream repo) can swap the weights, the
tokenizer, or the custom loader code under a green build, with no diff in
your repo. It is the model-registry analog of pinning an include to a SHA
(GL-005) or a dependency to a lockfile, and it is the prerequisite for the
``trust_remote_code`` execution path GL-045 flags: pinning the revision is
the one control that makes a poisoned-model swap detectable.

The GitLab analog of GHA-121. Scoped to org-namespaced ids
(``org/model``) so it targets third-party models, not the canonical
first-party hub names (``bert-base-uncased``).
"""
from __future__ import annotations

from typing import Any

from ..._primitives.model_ref import unpinned_model_id
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, job_scripts

RULE = Rule(
    id="GL-046",
    title="AI model pulled without a pinned revision",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-494", "CWE-829"),
    recommendation=(
        "Pin the model to an immutable revision. Pass an exact commit "
        "``revision=`` to ``from_pretrained`` / ``hf_hub_download`` / "
        "``snapshot_download`` (a 40-char commit SHA, not a branch or a "
        "tag, both of which the owner can move), or ``--revision <sha>`` "
        "to ``huggingface-cli download``. A pinned revision is what makes "
        "a swapped-weights or swapped-loader-code attack show up as a diff "
        "in your repo instead of silently landing on the next build. Pair "
        "with ``trust_remote_code=False`` (GL-045) and prefer safetensors "
        "weights over pickle."
    ),
    docs_note=(
        "Fires on a job ``script`` / ``before_script`` / ``after_script`` "
        "that fetches a model by a mutable registry reference and supplies "
        "no revision pin. Detected fetch forms: "
        "``from_pretrained(\"org/model\")``, ``hf_hub_download`` / "
        "``snapshot_download`` with a ``org/model`` repo id, and "
        "``huggingface-cli download org/model`` / ``hf download "
        "org/model``.\n\n"
        "Does NOT fire when a revision is pinned in the same command "
        "(``revision='<sha>'`` / ``--revision <sha>``), when the reference "
        "is a local path (``./model``, ``/models/x``) or a variable / "
        "``${{ }}`` interpolation (the value can't be judged statically), "
        "or on a bare single-segment canonical hub name "
        "(``bert-base-uncased``) that has no ``org/`` namespace, since "
        "those are first-party and the org-scoped third-party models are "
        "the higher-risk surface."
    ),
    known_fp=(
        "A team that re-pulls its own group's model on every pipeline may "
        "treat the latest revision as intentional. The right fix is still "
        "to pin the revision (it makes an upstream compromise visible); if "
        "a rolling pull is genuinely wanted, suppress on the specific job "
        "with a rationale naming the model and who controls it.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for job_id, job in iter_jobs(doc):
        body = "\n".join(job_scripts(job))
        repo = unpinned_model_id(body)
        if repo is not None:
            offenders.append(f"{job_id}: {repo}")
            line = _line_of(job)
            locations.append(Location(path=path, start_line=line, end_line=line))
    passed = not offenders
    desc = (
        "No job pulls a model from a registry without a pinned revision."
        if passed else
        f"{len(offenders)} job(s) fetch a model by a mutable registry "
        f"reference with no revision pin, so the registry can serve "
        f"swapped weights or loader code on the next pipeline: "
        f"{', '.join(offenders[:5])}{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
