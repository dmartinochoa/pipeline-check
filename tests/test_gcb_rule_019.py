"""Unit tests for GCB-019 — shell entrypoint inlines a user substitution."""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.cloudbuild.rules import (
    gcb019_shell_entrypoint_user_sub as r19,
)


def _doc(**fields: Any) -> dict[str, Any]:
    return dict(fields)


class TestGCB019ShellEntrypointUserSub:
    def test_fails_when_bash_dash_c_inlines_user_sub(self):
        f = r19.check("cb.yaml", _doc(steps=[{
            "name": "gcr.io/cloud-builders/gcloud@sha256:" + "a" * 64,
            "entrypoint": "bash",
            "args": ["-c", "echo deploying $_TARGET_ENV"],
            "id": "deploy",
        }]))
        assert not f.passed
        assert "$_TARGET_ENV" in f.description or "_TARGET_ENV" in f.description

    def test_fails_with_braced_user_sub(self):
        f = r19.check("cb.yaml", _doc(steps=[{
            "entrypoint": "/bin/sh",
            "args": ["-c", "echo ${_BUILD_TAG}"],
            "id": "tag",
        }]))
        assert not f.passed

    def test_passes_when_entrypoint_is_not_a_shell(self):
        # Plain ``docker`` entrypoint sees the substitution as a literal
        # argument; it's not shell-evaluated, so no injection surface.
        f = r19.check("cb.yaml", _doc(steps=[{
            "name": "gcr.io/cloud-builders/docker@sha256:" + "a" * 64,
            "entrypoint": "docker",
            "args": ["build", "-t", "$_IMAGE_TAG", "."],
            "id": "build",
        }]))
        assert f.passed

    def test_passes_when_shell_entrypoint_has_no_user_sub(self):
        f = r19.check("cb.yaml", _doc(steps=[{
            "entrypoint": "bash",
            "args": ["-c", "echo $PROJECT_ID && echo $COMMIT_SHA"],
            "id": "ids",
        }]))
        assert f.passed

    def test_passes_when_no_steps(self):
        f = r19.check("cb.yaml", _doc())
        assert f.passed
