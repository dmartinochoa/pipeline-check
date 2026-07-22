"""Shared regexes and helpers for GL rules."""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.deploy_names import DEPLOY_RE as DEPLOY_RE
from ..._primitives.image_pinning import DIGEST_RE as DIGEST_RE
from ..._primitives.image_pinning import VERSION_TAG_RE as VERSION_TAG_RE
from ..._primitives.secret_shapes import AWS_KEY_RE as AWS_KEY_RE
from ..._primitives.secret_shapes import SECRETISH_KEY_RE as SECRETISH_KEY_RE
from ..._primitives.secret_shapes import aws_key_in as aws_key_in
from ..._primitives.secret_shapes import is_placeholder_value as is_placeholder_value

# Attacker-controllable GitLab CI predefined variables.
UNTRUSTED_VAR_RE = re.compile(
    r"\$\{?(?:"
    r"CI_COMMIT_MESSAGE|CI_COMMIT_DESCRIPTION|CI_COMMIT_TITLE"
    r"|CI_COMMIT_REF_NAME|CI_COMMIT_BRANCH|CI_COMMIT_TAG"
    r"|CI_COMMIT_TAG_MESSAGE"
    r"|CI_COMMIT_AUTHOR"
    r"|CI_MERGE_REQUEST_TITLE|CI_MERGE_REQUEST_DESCRIPTION"
    r"|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"
    r"|CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME"
    r"|CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_SHA"
    r")\}?"
)

# Cache-key taint regex used by GL-012.
CACHE_TAINT_RE = re.compile(
    r"\$\{?(?:"
    r"CI_MERGE_REQUEST_[A-Z_]+"
    r"|CI_COMMIT_(?:BRANCH|REF_NAME|REF_SLUG|MESSAGE|TITLE|DESCRIPTION|TAG_MESSAGE)"
    r"|CI_COMMIT_AUTHOR"
    r"|CI_EXTERNAL_PULL_REQUEST_[A-Z_]+"
    r")\}?"
)


def image_ref(v: Any) -> str | None:
    """GitLab image: can be a string or a dict with name: …"""
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        n = v.get("name")
        return n if isinstance(n, str) else None
    return None


def rules_manual(rules: Any) -> bool:
    """True when any ``rules:`` entry declares ``when: manual``."""
    if not isinstance(rules, list):
        return False
    return any(
        isinstance(r, dict) and r.get("when") == "manual"
        for r in rules
    )


def rules_fully_manual(rules: Any) -> bool:
    """True when *every* reachable ``rules:`` entry is ``when: manual``.

    A job is only fully gated when there's no reachable rules entry that
    auto-runs: a job that is manual on one branch but auto-runs via a
    later catch-all entry is not gated. ``when: never`` entries exclude
    their pipelines, so they don't count as reachable.
    """
    if not isinstance(rules, list) or not rules:
        return False
    reachable = [
        r for r in rules
        if isinstance(r, dict) and r.get("when") != "never"
    ]
    if not reachable:
        return False
    return all(r.get("when") == "manual" for r in reachable)


def _rules_opt_into_mr(rules: Any) -> bool:
    """True when a ``rules:`` list has an entry whose ``if:`` admits MR pipelines.

    An entry with ``when: never`` EXCLUDES the matched pipelines (the
    documented "branch pipelines only" snippet is ``if:
    $CI_PIPELINE_SOURCE == "merge_request_event"`` + ``when: never``), so
    it opts *out*, not in, and must not count.
    """
    if not isinstance(rules, list):
        return False
    return any(
        isinstance(r, dict)
        and "merge_request_event" in str(r.get("if", ""))
        and r.get("when") != "never"
        for r in rules
    )


def _only_opts_into_mr(only: Any) -> bool:
    """True when a legacy ``only:`` clause includes ``merge_requests``."""
    if isinstance(only, str):
        return only == "merge_requests"
    if isinstance(only, list):
        return "merge_requests" in only
    if isinstance(only, dict):  # only: { refs: [...] }
        refs = only.get("refs")
        return isinstance(refs, list) and "merge_requests" in refs
    return False


def workflow_opts_into_mr(doc: dict[str, Any]) -> bool:
    """True when the top-level ``workflow: rules:`` admit merge-request pipelines."""
    wf = doc.get("workflow")
    return isinstance(wf, dict) and _rules_opt_into_mr(wf.get("rules"))


def pipeline_runs_on_mr(doc: dict[str, Any], jobs: Any) -> bool:
    """Heuristic: the pipeline (or any job) opts into ``merge_request_event``."""
    from ..base import iter_jobs
    if workflow_opts_into_mr(doc):
        return True
    return any(_rules_opt_into_mr(job.get("rules")) for _, job in iter_jobs(doc))


def job_runs_on_mr(doc: dict[str, Any], job: dict[str, Any]) -> bool:
    """True when *job* is reachable on a merge-request pipeline.

    Checked in GitLab's precedence order: a job's own ``rules:``
    supersede its legacy ``only:``, and both supersede the pipeline
    default. A job opts into MR pipelines when

    - its own ``rules:`` has an ``if:`` admitting ``merge_request_event``,
    - its legacy ``only:`` includes ``merge_requests``, or
    - it declares neither, so it inherits the pipeline default and runs
      whenever the top-level ``workflow: rules:`` admit MR pipelines.
    """
    rules = job.get("rules")
    if rules is not None:
        return _rules_opt_into_mr(rules)
    only = job.get("only")
    if only is not None:
        return _only_opts_into_mr(only)
    return workflow_opts_into_mr(doc)
