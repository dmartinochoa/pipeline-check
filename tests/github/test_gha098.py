"""Tests for GHA-098: deploy without security scan gate."""
from __future__ import annotations

from .conftest import run_check


class TestGHA098:
    def test_fires_on_deploy_without_scan(self) -> None:
        wf = """
        name: deploy
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            environment: production
            steps:
              - run: kubectl apply -f k8s/
        """
        f = run_check(wf, "GHA-098")
        assert not f.passed
        assert "security scan" in f.description.lower()

    def test_passes_with_scan_in_same_job(self) -> None:
        wf = """
        name: deploy
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            environment: production
            steps:
              - run: trivy fs .
              - run: kubectl apply -f k8s/
        """
        f = run_check(wf, "GHA-098")
        assert f.passed

    def test_passes_with_scan_in_upstream_job(self) -> None:
        wf = """
        name: deploy
        on: push
        jobs:
          scan:
            runs-on: ubuntu-latest
            steps:
              - uses: aquasecurity/trivy-action@abc123
          deploy:
            needs: scan
            runs-on: ubuntu-latest
            environment: production
            steps:
              - run: kubectl apply -f k8s/
        """
        f = run_check(wf, "GHA-098")
        assert f.passed

    def test_passes_when_no_deploy_job(self) -> None:
        wf = """
        name: ci
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: make test
        """
        f = run_check(wf, "GHA-098")
        assert f.passed

    def test_fires_on_deploy_named_job(self) -> None:
        wf = """
        name: release
        on: push
        jobs:
          deploy-prod:
            runs-on: ubuntu-latest
            steps:
              - run: echo deploying
        """
        f = run_check(wf, "GHA-098")
        assert not f.passed


def test_gha098_transitive_scan_ancestor_passes():
    # Regression (2026-07 audit): a scan that gates an intermediate job
    # (scan -> build -> deploy) is a valid upstream gate.
    wf = """
    on: push
    jobs:
      scan:
        runs-on: ubuntu-latest
        steps:
          - uses: aquasecurity/trivy-action@master
      build:
        needs: scan
        runs-on: ubuntu-latest
        steps:
          - run: make build
      deploy:
        needs: build
        runs-on: ubuntu-latest
        steps:
          - run: kubectl apply -f .
    """
    assert run_check(wf, "GHA-098").passed
