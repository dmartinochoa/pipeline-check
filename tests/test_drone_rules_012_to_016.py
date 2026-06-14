"""Per-rule tests for the Drone extended pack (DR-012..016)."""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.base import Severity
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
from pipeline_check.core.checks.drone.rules import (
    dr017_shell_eval as r17,
)
from pipeline_check.core.checks.drone.rules import (
    dr018_log_leak as r18,
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


# ── DR-017 ──────────────────────────────────────────────────────


class TestDR017ShellEval:
    def test_fails_on_eval_of_variable(self):
        p = _pipeline(steps=[
            {"name": "build", "image": f"alpine:3.19{_DIGEST}",
             "commands": ['eval "$BUILD_CMD"']},
        ])
        f = r17.check(p)
        assert not f.passed
        assert "idiom" in f.description.lower()

    def test_fails_on_sh_c_unquoted_variable(self):
        p = _pipeline(steps=[
            {"name": "run", "image": f"alpine:3.19{_DIGEST}",
             "commands": ["sh -c $RAW_HOOK"]},
        ])
        assert not r17.check(p).passed

    def test_passes_on_direct_command(self):
        p = _pipeline(steps=[
            {"name": "build", "image": f"alpine:3.19{_DIGEST}",
             "commands": ['./scripts/dispatch.sh "$BUILD_CMD"']},
        ])
        assert r17.check(p).passed

    def test_passes_on_ssh_agent_bootstrap_idiom(self):
        # ``eval "$(ssh-agent -s)"`` substitutes a literal command; only
        # its output is eval'd, so it is intentionally not flagged.
        p = _pipeline(steps=[
            {"name": "agent", "image": f"alpine:3.19{_DIGEST}",
             "commands": ['eval "$(ssh-agent -s)"']},
        ])
        assert r17.check(p).passed

    def test_passes_on_non_container_pipeline(self):
        p = _pipeline(type="exec", steps=[
            {"name": "x", "commands": ['eval "$CMD"']},
        ])
        assert r17.check(p).passed


# ── DR-018 ──────────────────────────────────────────────────────


class TestDR018LogLeak:
    def test_fails_on_echo_secret_named_var(self):
        p = _pipeline(steps=[
            {"name": "deploy", "image": f"alpine:3.19{_DIGEST}",
             "commands": ['echo "token is $DEPLOY_TOKEN"']},
        ])
        f = r18.check(p)
        assert not f.passed
        assert f.severity is Severity.HIGH
        assert "deploy" in f.description

    def test_fails_on_printenv_dump(self):
        p = _pipeline(steps=[
            {"name": "debug", "image": f"alpine:3.19{_DIGEST}",
             "commands": ["printenv"]},
        ])
        assert not r18.check(p).passed

    def test_passes_on_safe_existence_check(self):
        p = _pipeline(steps=[
            {"name": "deploy", "image": f"alpine:3.19{_DIGEST}",
             "commands": ['[ -n "$TOKEN" ] && echo set || echo unset']},
        ])
        assert r18.check(p).passed

    def test_passes_on_non_container_pipeline(self):
        p = _pipeline(type="exec", steps=[
            {"name": "x", "commands": ['echo "$AWS_SECRET_ACCESS_KEY"']},
        ])
        assert r18.check(p).passed
