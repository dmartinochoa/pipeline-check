"""Shared regexes and helpers for GL rules."""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.deploy_names import DEPLOY_RE as DEPLOY_RE
from ..._primitives.secret_shapes import AWS_KEY_RE as AWS_KEY_RE
from ..._primitives.secret_shapes import SECRETISH_KEY_RE as SECRETISH_KEY_RE

DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
VERSION_TAG_RE = re.compile(r":[^:]*\d[^:]*$")

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


def pipeline_runs_on_mr(doc: dict[str, Any], jobs: Any) -> bool:
    """Heuristic: the pipeline (or any job) opts into ``merge_request_event``."""
    from ..base import iter_jobs
    wf = doc.get("workflow")
    if isinstance(wf, dict):
        rules = wf.get("rules")
        if isinstance(rules, list):
            for r in rules:
                if isinstance(r, dict) and "merge_request_event" in str(r.get("if", "")):
                    return True
    for _, job in iter_jobs(doc):
        rules = job.get("rules")
        if isinstance(rules, list):
            for r in rules:
                if isinstance(r, dict) and "merge_request_event" in str(r.get("if", "")):
                    return True
    return False
