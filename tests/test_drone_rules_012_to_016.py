"""Per-rule tests for the Drone extended pack (DR-012..016)."""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.drone.base import Pipeline
from pipeline_check.core.checks.drone.rules import (
    dr012_service_image_pinning as r12,
)
from pipeline_check.core.checks.drone.rules import (
    dr013_pipeline_no_trigger as r13,
)
from pipeline_check.core.checks.drone.rules import (
    dr014_pipe_to_shell as r14,
)
from pipeline_check.core.checks.drone.rules import (
    dr015_clone_recursive_submodules as r15,
)
from pipeline_check.core.checks.drone.rules import (
    dr016_image_field_interpolation as r16,
)

_DIGEST = "@sha256:" + "0" * 64


def _pipeline(**data: Any) -> Pipeline:
    body: dict[str, Any] = {
        "kind": "pipeline",
        "type": "docker",
        "name": "default",
    }
    body.update(data)
    return Pipeline(path=".drone.yml", doc_index=0, data=body)


# ── DR-012 ──────────────────────────────────────────────────────


class TestDR012ServiceImagePinning:
    def test_passes_on_digest_pinned_service(self):
        p = _pipeline(services=[{"name": "db", "image": f"postgres:15{_DIGEST}"}])
        assert r12.check(p).passed

    def test_fires_on_tag_only_service(self):
        p = _pipeline(services=[{"name": "db", "image": "postgres:15"}])
        f = r12.check(p)
        assert not f.passed
        assert "postgres:15" in f.description

    def test_passes_with_no_services(self):
        p = _pipeline()
        assert r12.check(p).passed

    def test_skips_non_container_pipelines(self):
        p = Pipeline(
            path=".drone.yml", doc_index=0,
            data={"kind": "pipeline", "type": "ssh", "name": "x"},
        )
        assert r12.check(p).passed


# ── DR-013 ──────────────────────────────────────────────────────


class TestDR013PipelineNoTrigger:
    def test_fires_when_trigger_absent(self):
        p = _pipeline(steps=[{"name": "build", "image": f"alpine:3{_DIGEST}"}])
        f = r13.check(p)
        assert not f.passed
        assert "no trigger" in f.description.lower()

    def test_passes_when_trigger_excludes_pr(self):
        p = _pipeline(
            trigger={"event": {"exclude": ["pull_request"]}},
            steps=[{"name": "build", "image": f"alpine:3{_DIGEST}"}],
        )
        assert r13.check(p).passed

    def test_passes_on_explicit_event_list_without_pr(self):
        p = _pipeline(
            trigger={"event": ["push", "tag"]},
            steps=[{"name": "build", "image": f"alpine:3{_DIGEST}"}],
        )
        assert r13.check(p).passed

    def test_fires_when_pr_included_without_offset(self):
        p = _pipeline(
            trigger={"event": ["push", "pull_request"]},
            steps=[{"name": "build", "image": f"alpine:3{_DIGEST}"}],
        )
        f = r13.check(p)
        assert not f.passed


# ── DR-014 ──────────────────────────────────────────────────────


class TestDR014PipeToShell:
    def test_fires_on_curl_pipe_sh(self):
        p = _pipeline(steps=[{
            "name": "install",
            "image": f"alpine:3{_DIGEST}",
            "commands": ["curl -fsSL https://example.com/install.sh | sh"],
        }])
        f = r14.check(p)
        assert not f.passed

    def test_fires_on_wget_pipe_bash(self):
        p = _pipeline(steps=[{
            "name": "install",
            "image": f"alpine:3{_DIGEST}",
            "commands": ["wget -qO - https://example.com/x | bash"],
        }])
        f = r14.check(p)
        assert not f.passed

    def test_passes_on_download_then_verify(self):
        p = _pipeline(steps=[{
            "name": "install",
            "image": f"alpine:3{_DIGEST}",
            "commands": [
                "curl -fsSL -o installer.sh https://example.com/install.sh",
                "sha256sum -c expected.sha256",
                "sh installer.sh",
            ],
        }])
        assert r14.check(p).passed

    def test_passes_with_no_commands(self):
        p = _pipeline(steps=[{
            "name": "x", "image": f"alpine:3{_DIGEST}",
        }])
        assert r14.check(p).passed


# ── DR-015 ──────────────────────────────────────────────────────


class TestDR015CloneRecursive:
    def test_passes_on_default_clone(self):
        p = _pipeline(steps=[{"name": "x", "image": f"alpine:3{_DIGEST}"}])
        assert r15.check(p).passed

    def test_fires_on_recursive_true(self):
        p = _pipeline(
            clone={"recursive": True},
            steps=[{"name": "x", "image": f"alpine:3{_DIGEST}"}],
        )
        f = r15.check(p)
        assert not f.passed
        assert "recursive=true" in f.description

    def test_passes_on_explicit_recursive_false(self):
        p = _pipeline(
            clone={"recursive": False},
            steps=[{"name": "x", "image": f"alpine:3{_DIGEST}"}],
        )
        assert r15.check(p).passed


# ── DR-016 ──────────────────────────────────────────────────────


class TestDR016ImageInterpolation:
    def test_fires_on_template_in_step_image(self):
        p = _pipeline(steps=[{
            "name": "deploy",
            "image": "${DRONE_DEPLOY_TO}-runner:latest",
            "commands": ["./deploy.sh"],
        }])
        f = r16.check(p)
        assert not f.passed

    def test_fires_on_template_in_service_image(self):
        p = _pipeline(services=[{
            "name": "db",
            "image": "${DB_REGISTRY}/postgres:15",
        }])
        f = r16.check(p)
        assert not f.passed

    def test_passes_on_literal_image(self):
        p = _pipeline(steps=[{
            "name": "deploy",
            "image": f"myregistry/deploy:1.2.3{_DIGEST}",
        }])
        assert r16.check(p).passed

    def test_passes_with_no_images(self):
        p = _pipeline()
        assert r16.check(p).passed
