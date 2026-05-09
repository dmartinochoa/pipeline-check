"""End-to-end tests for the Drone provider plumbing.

Covers ``DroneContext.from_path`` (file + directory loading,
multi-doc YAML, parse-error handling, non-pipeline skipping),
``DronePipelineChecks`` orchestrator, ``DroneProvider`` adapter,
and the Scanner round-trip through ``--pipeline drone``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_check.core.checks.drone.base import DroneContext
from pipeline_check.core.checks.drone.pipelines import DronePipelineChecks
from pipeline_check.core.providers.drone import DroneProvider
from pipeline_check.core.scanner import Scanner

_DIGEST = "@sha256:" + "0" * 64


def _write(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")


_HARDENED = f"""\
kind: pipeline
type: docker
name: default

steps:
  - name: build
    image: golang:1.21{_DIGEST}
    commands:
      - go build
      - echo "${{DRONE_PULL_REQUEST_TITLE}}"
    environment:
      API_TOKEN:
        from_secret: api_token
"""

_VULNERABLE = """\
kind: pipeline
type: docker
name: default

steps:
  - name: build
    image: golang:latest
    commands:
      - go build
      - echo ${DRONE_PULL_REQUEST_TITLE}
      - curl -k https://example.com
    environment:
      API_TOKEN: literal-secret-1234567890
    privileged: true
"""


class TestDroneContextLoading:
    def test_loads_single_file(self, tmp_path: Path) -> None:
        f = tmp_path / ".drone.yml"
        _write(f, _HARDENED)
        ctx = DroneContext.from_path(f)
        assert ctx.files_scanned == 1
        assert len(ctx.pipelines) == 1
        assert ctx.pipelines[0].data["name"] == "default"

    def test_loads_directory_recursively(self, tmp_path: Path) -> None:
        # Two services, each with its own pipeline file.
        (tmp_path / "svc-a").mkdir()
        (tmp_path / "svc-b").mkdir()
        _write(tmp_path / "svc-a" / ".drone.yml", _HARDENED)
        _write(tmp_path / "svc-b" / ".drone.yml", _HARDENED)
        ctx = DroneContext.from_path(tmp_path)
        assert ctx.files_scanned == 2
        assert len(ctx.pipelines) == 2

    def test_multi_doc_yaml(self, tmp_path: Path) -> None:
        # Drone supports stacking pipelines via YAML doc separators.
        body = _HARDENED + "\n---\n" + _HARDENED.replace(
            "name: default", "name: deploy"
        )
        f = tmp_path / ".drone.yml"
        _write(f, body)
        ctx = DroneContext.from_path(f)
        assert len(ctx.pipelines) == 2
        assert {p.data["name"] for p in ctx.pipelines} == {
            "default", "deploy",
        }

    def test_skips_non_pipeline_yaml(self, tmp_path: Path) -> None:
        # A YAML doc without ``kind: pipeline`` is silently skipped.
        f = tmp_path / ".drone.yml"
        _write(f, "kind: secret\nname: api_token\nget:\n  path: secret\n")
        ctx = DroneContext.from_path(f)
        assert ctx.pipelines == []

    def test_warns_on_yaml_parse_error(self, tmp_path: Path) -> None:
        f = tmp_path / ".drone.yml"
        _write(f, "kind: pipeline\nsteps: [invalid yaml")
        ctx = DroneContext.from_path(f)
        assert ctx.pipelines == []
        assert any("YAML parse error" in w for w in ctx.warnings)

    def test_raises_when_path_missing(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="does not exist"):
            DroneContext.from_path(tmp_path / "missing.yml")


class TestDronePipelineChecksOrchestrator:
    def test_runs_every_rule_on_hardened_pipeline(
        self, tmp_path: Path,
    ) -> None:
        f = tmp_path / ".drone.yml"
        _write(f, _HARDENED)
        ctx = DroneContext.from_path(f)
        findings = DronePipelineChecks(ctx).run()
        ids = sorted(f.check_id for f in findings)
        assert ids == [
            "DR-001", "DR-002", "DR-003",
            "DR-004", "DR-005", "DR-006", "DR-007",
        ]
        # Every rule passes on the hardened fixture.
        assert all(f.passed for f in findings), [
            (f.check_id, f.description) for f in findings if not f.passed
        ]

    def test_runs_every_rule_on_vulnerable_pipeline(
        self, tmp_path: Path,
    ) -> None:
        f = tmp_path / ".drone.yml"
        _write(f, _VULNERABLE)
        ctx = DroneContext.from_path(f)
        findings = DronePipelineChecks(ctx).run()
        # DR-005 only fires on plugin steps and DR-007 only fires on
        # sensitive host-path mounts; the vulnerable fixture has
        # neither, so every other rule fires.
        failed_ids = sorted(f.check_id for f in findings if not f.passed)
        assert failed_ids == [
            "DR-001", "DR-002", "DR-003", "DR-004", "DR-006",
        ]


class TestDroneProvider:
    def test_build_context_requires_path(self) -> None:
        with pytest.raises(ValueError, match="--drone-path"):
            DroneProvider().build_context()

    def test_inventory_records_pipeline_metadata(
        self, tmp_path: Path,
    ) -> None:
        f = tmp_path / ".drone.yml"
        _write(f, _HARDENED + """
trigger:
  event:
    - push
    - tag
  branch:
    - main
""")
        ctx = DroneProvider().build_context(drone_path=str(f))
        components = DroneProvider().inventory(ctx)
        assert len(components) == 1
        c = components[0]
        assert c.type == "pipeline"
        assert c.metadata["name"] == "default"
        assert c.metadata["step_count"] == 1
        assert c.metadata["trigger_event"] == ["push", "tag"]
        assert c.metadata["trigger_branch"] == ["main"]


class TestScannerWiring:
    def test_scanner_runs_drone_pipeline(self, tmp_path: Path) -> None:
        f = tmp_path / ".drone.yml"
        _write(f, _VULNERABLE)
        scanner = Scanner(pipeline="drone", drone_path=str(f))
        findings = scanner.run()
        ids = sorted(f.check_id for f in findings)
        assert ids == [
            "DR-001", "DR-002", "DR-003",
            "DR-004", "DR-005", "DR-006", "DR-007",
        ]
        # Vulnerable fixture trips 5 of 7 (DR-005 needs a plugin,
        # DR-007 needs a host-path volume).
        failed_ids = sorted(f.check_id for f in findings if not f.passed)
        assert failed_ids == [
            "DR-001", "DR-002", "DR-003", "DR-004", "DR-006",
        ]
