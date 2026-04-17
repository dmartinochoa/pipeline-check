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
from ..inventory import Component
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

    def inventory(self, context: JenkinsContext) -> list[Component]:
        import re
        out: list[Component] = []
        for jf in context.files:
            metadata: dict = {}
            stages = [name for name, _body in jf.stages]
            if stages:
                metadata["stages"] = stages
            if jf.library_refs:
                metadata["library_refs"] = list(jf.library_refs)
            # Agent declaration — ``any``, a label, a docker image, or
            # a Kubernetes pod. Surfaced so an asset register can
            # distinguish "runs on a shared pool" from "runs in an
            # ephemeral container".
            text = getattr(jf, "text_no_comments", None) or jf.text
            if re.search(r"\bagent\s+any\b", text):
                metadata["agent"] = "any"
            elif re.search(r"\bkubernetes\s*\{", text):
                metadata["agent"] = "kubernetes"
            elif m := re.search(r"docker\s*\{\s*image\s+['\"]([^'\"]+)['\"]", text):
                metadata["agent"] = f"docker:{m.group(1)}"
            elif m := re.search(r"\bagent\s*\{\s*label\s+['\"]([^'\"]+)['\"]", text):
                metadata["agent"] = f"label:{m.group(1)}"
            # Guard presence — shows which pipelines already have the
            # bounded-runtime protections JF-011/015 check for.
            metadata["has_timeout"] = bool(re.search(r"\btimeout\s*\(", text))
            metadata["has_build_discarder"] = bool(
                re.search(r"\b(?:buildDiscarder|logRotator)\s*\(", text)
            )
            out.append(Component(
                provider=self.NAME,
                type="jenkinsfile",
                identifier=jf.path,
                source=jf.path,
                metadata=metadata,
            ))
        return out
