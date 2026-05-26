"""End-to-end SBOM integration tests.

Construct scanners with known fixture content and verify
build_dependencies() returns the expected components.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from pipeline_check.core.scanner import Scanner


def _write_workflow(tmp_path: Path) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf = wf_dir / "ci.yml"
    wf.write_text(
        "name: CI\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8\n"
        "      - uses: docker://python:3.12-slim\n"
        "      - run: echo hello\n",
        encoding="utf-8",
    )
    return wf_dir


def _write_dockerfile(tmp_path: Path) -> Path:
    df = tmp_path / "Dockerfile"
    df.write_text(
        "FROM python:3.12-slim AS builder\n"
        "RUN pip install flask\n"
        "FROM nginx:1.25-alpine\n"
        "COPY --from=builder /app /app\n",
        encoding="utf-8",
    )
    return df


def _write_package_json(tmp_path: Path) -> Path:
    pj = tmp_path / "package.json"
    pj.write_text(
        '{\n'
        '  "name": "my-app",\n'
        '  "version": "1.0.0",\n'
        '  "dependencies": {\n'
        '    "express": "^4.18.2",\n'
        '    "lodash": "4.17.21"\n'
        '  },\n'
        '  "devDependencies": {\n'
        '    "jest": "^29.0.0"\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    return pj


def _write_requirements(tmp_path: Path) -> Path:
    rf = tmp_path / "requirements.txt"
    rf.write_text(
        "flask==2.3.3\n"
        "requests>=2.31.0\n"
        "# comment\n"
        "gunicorn==21.2.0\n",
        encoding="utf-8",
    )
    return rf


class TestGitHubSBOM:
    def test_extracts_action_refs(self, tmp_path: Path) -> None:
        wf_dir = _write_workflow(tmp_path)
        scanner = Scanner(pipeline="github", gha_path=str(wf_dir))
        deps = scanner.sbom()
        names = {d.name for d in deps}
        assert "actions/checkout" in names
        assert "actions/setup-node" in names

    def test_pinned_sha_detected(self, tmp_path: Path) -> None:
        wf_dir = _write_workflow(tmp_path)
        scanner = Scanner(pipeline="github", gha_path=str(wf_dir))
        deps = scanner.sbom()
        setup_node = [d for d in deps if d.name == "actions/setup-node"]
        assert len(setup_node) == 1
        assert setup_node[0].pinned is True

    def test_docker_step_extracted(self, tmp_path: Path) -> None:
        wf_dir = _write_workflow(tmp_path)
        scanner = Scanner(pipeline="github", gha_path=str(wf_dir))
        deps = scanner.sbom()
        docker_deps = [d for d in deps if d.dep_type == "container"]
        assert len(docker_deps) == 1
        assert docker_deps[0].name == "python"
        assert docker_deps[0].version == "3.12-slim"

    def test_purl_format(self, tmp_path: Path) -> None:
        wf_dir = _write_workflow(tmp_path)
        scanner = Scanner(pipeline="github", gha_path=str(wf_dir))
        deps = scanner.sbom()
        for d in deps:
            assert d.purl.startswith("pkg:")


class TestDockerfileSBOM:
    def test_extracts_from_refs(self, tmp_path: Path) -> None:
        df = _write_dockerfile(tmp_path)
        scanner = Scanner(
            pipeline="dockerfile", dockerfile_path=str(df),
        )
        deps = scanner.sbom()
        names = {d.name for d in deps}
        assert "python" in names
        assert "nginx" in names
        assert len(deps) == 2

    def test_all_are_containers(self, tmp_path: Path) -> None:
        df = _write_dockerfile(tmp_path)
        scanner = Scanner(
            pipeline="dockerfile", dockerfile_path=str(df),
        )
        deps = scanner.sbom()
        assert all(d.dep_type == "container" for d in deps)


class TestNpmSBOM:
    def test_extracts_dependencies(self, tmp_path: Path) -> None:
        pj = _write_package_json(tmp_path)
        scanner = Scanner(pipeline="npm", npm_path=str(pj))
        deps = scanner.sbom()
        names = {d.name for d in deps}
        assert "express" in names
        assert "lodash" in names
        assert "jest" in names
        assert len(deps) == 3

    def test_purl_format(self, tmp_path: Path) -> None:
        pj = _write_package_json(tmp_path)
        scanner = Scanner(pipeline="npm", npm_path=str(pj))
        deps = scanner.sbom()
        for d in deps:
            assert d.purl.startswith("pkg:npm/")


class TestPypiSBOM:
    def test_extracts_pinned_requirements(self, tmp_path: Path) -> None:
        rf = _write_requirements(tmp_path)
        scanner = Scanner(pipeline="pypi", pypi_path=str(rf))
        deps = scanner.sbom()
        names = {d.name for d in deps}
        assert "flask" in names
        assert "requests" in names
        assert "gunicorn" in names

    def test_pinned_detection(self, tmp_path: Path) -> None:
        rf = _write_requirements(tmp_path)
        scanner = Scanner(pipeline="pypi", pypi_path=str(rf))
        deps = scanner.sbom()
        flask = [d for d in deps if d.name == "flask"]
        assert flask[0].pinned is True
        requests_dep = [d for d in deps if d.name == "requests"]
        assert requests_dep[0].pinned is False


class TestNoSBOM:
    def test_provider_without_override_returns_empty(
        self, tmp_path: Path,
    ) -> None:
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        wf = wf_dir / "ci.yml"
        wf.write_text(
            "name: CI\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo hi\n",
            encoding="utf-8",
        )
        scanner = Scanner(pipeline="github", gha_path=str(wf_dir))
        deps = scanner.sbom()
        action_deps = [d for d in deps if d.dep_type == "action"]
        assert len(action_deps) == 0
