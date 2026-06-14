"""Unit tests for GCB-028 (secret echoed to the build log)."""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.cloudbuild.rules import (
    gcb028_log_leak as r28,
)


def _doc(**fields: Any) -> dict[str, Any]:
    return dict(fields)


class TestGCB028LogLeak:
    def test_metadata(self):
        f = r28.check("cloudbuild.yaml", _doc(steps=[
            {"name": "gcr.io/cloud-builders/docker", "args": ["build", "."]},
        ]))
        assert f.check_id == "GCB-028"
        assert f.severity is Severity.HIGH

    def test_fails_on_echo_secret_named_var(self):
        doc = _doc(steps=[
            {"name": "gcr.io/cloud-builders/bash", "entrypoint": "bash",
             "args": ["-c", 'echo "deploying with $AWS_SECRET_ACCESS_KEY"']},
        ])
        assert not r28.check("cloudbuild.yaml", doc).passed

    def test_fails_on_dollar_dollar_escaped_secret(self):
        # Cloud Build escapes a literal ``$`` as ``$$``; normalize so it
        # is still caught.
        doc = _doc(steps=[
            {"name": "bash", "entrypoint": "bash",
             "args": ["-c", 'echo "$$DEPLOY_TOKEN"']},
        ])
        assert not r28.check("cloudbuild.yaml", doc).passed

    def test_fails_on_printenv_dump(self):
        doc = _doc(steps=[
            {"name": "bash", "entrypoint": "bash", "args": ["-c", "printenv"]},
        ])
        assert not r28.check("cloudbuild.yaml", doc).passed

    def test_passes_on_clean_build(self):
        doc = _doc(steps=[
            {"name": "gcr.io/cloud-builders/docker", "args": [
                "build", "-t", "gcr.io/$PROJECT_ID/app", "."]},
        ])
        assert r28.check("cloudbuild.yaml", doc).passed

    def test_passes_on_safe_existence_check(self):
        doc = _doc(steps=[
            {"name": "bash", "entrypoint": "bash",
             "args": ["-c", '[ -n "$$TOKEN" ] && echo set || echo unset']},
        ])
        assert r28.check("cloudbuild.yaml", doc).passed
