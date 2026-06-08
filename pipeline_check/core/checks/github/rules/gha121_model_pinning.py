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

import re
from typing import Any

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

# Calls / commands that fetch an artifact from a model registry.
_FETCH_ANCHOR_RE = re.compile(
    r"\b(?:from_pretrained|hf_hub_download|snapshot_download)\b"
    r"|\bhuggingface-cli\s+download\b"
    r"|\bhf\s+download\b",
    re.IGNORECASE,
)

# An ``org/model`` (optionally ``org/model/subpath``) hub id. The
# lookbehind stops the match inside a longer path or URL segment
# (``/models/x``, ``a/b/c/d``); the lookahead stops it on a docker tag
# (``org/img:tag``), a git pin (``org/repo@sha``), or a deeper path so
# we capture the whole id, not a prefix. ``$`` / ``{`` are outside the
# charset, so ``${{ env.MODEL }}`` never matches.
_REPO_ID_RE = re.compile(
    r"(?<![\w./@$~-])"
    r"([A-Za-z0-9_][\w.-]*/[\w.-]+(?:/[\w.-]+)?)"
    r"(?![\w/@:-])"
)

# A pinned revision anywhere in the window: the ``revision`` kwarg, the
# ``--revision`` flag, or an ``@<commit-ish>`` suffix.
_REVISION_RE = re.compile(
    r"\brevision\s*[=:]\s*['\"]?[\w.\-]+"
    r"|--revision[=\s]"
    r"|@[0-9a-fA-F]{7,40}\b",
    re.IGNORECASE,
)


def _logical_lines(body: str) -> list[str]:
    r"""Join shell line-continuations (a trailing ``\``) into one logical
    line, so a ``--revision`` / ``revision=`` pin wrapped onto the next
    line still counts as belonging to the same call."""
    out: list[str] = []
    buf = ""
    for raw in body.splitlines():
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        buf += stripped
        out.append(buf)
        buf = ""
    if buf:
        out.append(buf)
    return out


def _line_windows(body: str) -> list[str]:
    """Each logical line plus each adjacent two-line pair (the pair
    absorbs a call wrapped across lines without a backslash)."""
    lines = _logical_lines(body)
    out: list[str] = list(lines)
    for i in range(len(lines) - 1):
        out.append(lines[i] + " " + lines[i + 1])
    return out


def _unpinned_model_id(body: str) -> str | None:
    """Return the offending repo id in *body*, or ``None``.

    Fires when a single step-window holds a registry-fetch call and an
    ``org/model`` id with no revision pin alongside it.
    """
    for window in _line_windows(body):
        if not _FETCH_ANCHOR_RE.search(window):
            continue
        if _REVISION_RE.search(window):
            continue
        repo = _REPO_ID_RE.search(window)
        if repo:
            return repo.group(1)
    return None


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
