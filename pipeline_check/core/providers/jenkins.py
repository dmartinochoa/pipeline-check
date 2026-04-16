"""Jenkins provider — scans ``Jenkinsfile`` (declarative + scripted).

    pipeline_check --pipeline jenkins --jenkinsfile-path Jenkinsfile

Only text parsing is required — no Jenkins controller access, no
Groovy interpreter, no plugin install. Works on detached repos.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.jenkins.base import JenkinsContext
from ..checks.jenkins.jenkinsfile import JenkinsfileChecks
from .base import BaseProvider


class JenkinsProvider(BaseProvider):
    """Jenkins provider — parses Jenkinsfile text from disk."""

    NAME = "jenkins"

    def build_context(self, jenkinsfile_path: str | None = None, **_: Any) -> JenkinsContext:
        if not jenkinsfile_path:
            raise ValueError(
                "The jenkins provider requires --jenkinsfile-path "
                "<file-or-dir> pointing at a Jenkinsfile or a directory "
                "containing one."
            )
        return JenkinsContext.from_path(jenkinsfile_path)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [JenkinsfileChecks]
