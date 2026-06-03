"""Tests for GL-039 (dind service with TLS disabled / daemon exposed)."""
from __future__ import annotations

from .conftest import run_check


class TestGL039DindInsecureDaemon:
    def test_fails_on_dind_with_empty_certdir(self) -> None:
        f = run_check("""
        build-image:
          services:
            - docker:27-dind
          variables:
            DOCKER_TLS_CERTDIR: ""
          script: [docker build -t app .]
        """, "GL-039")
        assert not f.passed
        assert "dind" in f.description

    def test_fails_on_daemon_exposed_on_2375(self) -> None:
        f = run_check("""
        build-image:
          services:
            - name: docker:27-dind
              command: ["--host=tcp://0.0.0.0:2375"]
          script: [docker build -t app .]
        """, "GL-039")
        assert not f.passed

    def test_fails_on_global_dind_and_vars(self) -> None:
        # Global services + variables merged into the job.
        f = run_check("""
        services:
          - docker:24-dind
        variables:
          DOCKER_TLS_CERTDIR: ""
        build:
          script: [docker build -t app .]
        """, "GL-039")
        assert not f.passed

    def test_passes_with_tls_on(self) -> None:
        f = run_check("""
        build-image:
          services:
            - docker:27-dind
          variables:
            DOCKER_TLS_CERTDIR: "/certs"
          script: [docker build -t app .]
        """, "GL-039")
        assert f.passed

    def test_passes_without_dind(self) -> None:
        f = run_check("""
        build:
          services:
            - postgres:16
          variables:
            DOCKER_TLS_CERTDIR: ""
          script: [make]
        """, "GL-039")
        assert f.passed
