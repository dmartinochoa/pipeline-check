"""GHA-121. AI model pulled from a mutable (unpinned) registry ref.

A ``run:`` step fetches a model from a model registry (Hugging Face Hub
and friends) by a *mutable* reference: ``from_pretrained("org/model")``,
``hf_hub_download`` / ``snapshot_download`` with a bare ``repo_id``, or
``huggingface-cli download org/model`` with no ``--revision``. Without a
pinned revision the registry serves whatever the repo's default branch
points at *now*, so the model owner (or anyone who compromises the
account or the upstream repo) can swap the weights, the tokenizer, or the
custom loader code under a green build, with no diff in your repo. It is
the model-registry analog of pinning an action to a SHA (GHA-001) or a
dependency to a lockfile, and it is the prerequisite for the
``trust_remote_code`` execution path GHA-120 flags: pinning the revision
is the one control that makes a poisoned-model swap detectable.

Scoped to org-namespaced ids (``org/model``) so it targets third-party
models, not the canonical first-party hub names (``bert-base-uncased``).
"""
from __future__ import annotations

from typing import Any

from ..._primitives.model_ref import unpinned_model_id as _unpinned_model_id
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-121",
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
        "with ``trust_remote_code=False`` (GHA-120) and prefer safetensors "
        "weights over pickle."
    ),
    docs_note=(
        "Fires on a ``run:`` step that fetches a model by a mutable "
        "registry reference and supplies no revision pin. Detected fetch "
        "forms: ``from_pretrained(\"org/model\")``, ``hf_hub_download`` / "
        "``snapshot_download`` with a ``org/model`` repo id, and "
        "``huggingface-cli download org/model`` / ``hf download "
        "org/model``. A finding requires the fetch call and the repo id to "
        "sit in the same step (a two-line window absorbs shell "
        "continuations).\n\n"
        "Does NOT fire when a revision is pinned in the same step "
        "(``revision='<sha>'`` / ``--revision <sha>``), when the reference "
        "is a local path (``./model``, ``/models/x``) or a variable / "
        "``${{ }}`` interpolation (the value can't be judged statically), "
        "or on a bare single-segment canonical hub name "
        "(``bert-base-uncased``) that has no ``org/`` namespace, since "
        "those are first-party and the org-scoped third-party models are "
        "the higher-risk surface."
    ),
    known_fp=(
        "A team that re-pulls its own org's model on every run may treat "
        "the latest revision as intentional. The right fix is still to "
        "pin the revision (it makes an upstream compromise visible); if a "
        "rolling pull is genuinely wanted, suppress on the specific step "
        "with a rationale naming the model and who controls it.",
    ),
)

# Registry-fetch + unpinned-revision detection is shared with GL-046; it
# lives in ``_primitives/model_ref`` and is imported as
# ``_unpinned_model_id`` above.


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    anchor_jobs: dict[str, None] = {}
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            repo = _unpinned_model_id(run)
            if repo is not None:
                offenders.append(f"{job_id}[{idx}]: {repo}")
                locations.append(step_location(path, step))
                anchor_jobs[job_id] = None
    passed = not offenders
    desc = (
        "No step pulls a model from a registry without a pinned revision."
        if passed else
        f"{len(offenders)} step(s) fetch a model by a mutable registry "
        f"reference with no revision pin, so the registry can serve "
        f"swapped weights or loader code on the next build: "
        f"{', '.join(offenders[:5])}{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        job_anchors=tuple(anchor_jobs),
    )
