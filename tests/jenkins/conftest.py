"""Shared helpers for Jenkins (Groovy) per-rule tests.

Mirrors ``tests/azure/conftest.py`` and ``tests/circleci/conftest.py``:
parse a Groovy snippet into a ``JenkinsContext``, run the orchestrator,
return the Finding for the requested check_id. Jenkins differs from
the YAML providers in that the source is Groovy text, not a parsed
dict, so the Jenkinsfile dataclass is built manually with the same
fields ``JenkinsContext.from_path`` would compute.
"""
from __future__ import annotations

import re
import textwrap

from pipeline_check.core.checks.jenkins.base import (
    JenkinsContext,
    Jenkinsfile,
    _extract_stages,
)
from pipeline_check.core.checks.jenkins.jenkinsfile import JenkinsfileChecks
from pipeline_check.core.checks.jenkins.rules._helpers import (
    strip_groovy_comments,
)


_LIBRARY_RE = re.compile(r"@Library\(\s*['\"]([^'\"]+)['\"]\s*\)")


def jenkins_ctx(groovy_text: str, path: str = "Jenkinsfile") -> JenkinsContext:
    """Parse a Groovy snippet into a JenkinsContext with one Jenkinsfile."""
    text = textwrap.dedent(groovy_text)
    return JenkinsContext([Jenkinsfile(
        path=path,
        text=text,
        library_refs=_LIBRARY_RE.findall(text),
        stages=_extract_stages(text),
        text_no_comments=strip_groovy_comments(text),
    )])


def run_check(groovy_text: str, check_id: str):
    """Run every Jenkins check; return the Finding with the given id."""
    ctx = jenkins_ctx(groovy_text)
    for f in JenkinsfileChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not found in Jenkins orchestrator output"
    )
