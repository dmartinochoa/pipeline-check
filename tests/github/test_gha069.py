"""Per-rule tests for GHA-069 (orphan id-token: write scope)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA069OrphanIdToken:
    def test_fails_when_workflow_grants_id_token_but_no_consumer(self):
        wf = """
        permissions:
          contents: read
          id-token: write
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: ./build.sh
        """
        f = run_check(wf, "GHA-069")
        assert not f.passed
        assert "build" in f.description

    def test_fails_when_job_grants_id_token_but_no_consumer(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              id-token: write
            steps:
              - run: ./build.sh
        """
        assert not run_check(wf, "GHA-069").passed

    def test_passes_when_aws_consumer_present(self):
        wf = """
        permissions:
          contents: read
          id-token: write
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: aws-actions/configure-aws-credentials@v4
                with:
                  role-to-assume: arn:aws:iam::123:role/x
              - run: ./build.sh
        """
        assert run_check(wf, "GHA-069").passed

    def test_passes_when_pypi_publish_present(self):
        wf = """
        permissions:
          id-token: write
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - uses: pypa/gh-action-pypi-publish@release/v1
        """
        assert run_check(wf, "GHA-069").passed

    def test_passes_when_docker_build_with_provenance(self):
        wf = """
        permissions:
          id-token: write
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: docker/build-push-action@v5
                with:
                  provenance: true
        """
        assert run_check(wf, "GHA-069").passed

    def test_fails_when_docker_build_explicitly_disables_provenance(self):
        wf = """
        permissions:
          id-token: write
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: docker/build-push-action@v5
                with:
                  provenance: false
                  sbom: false
                  attestations: false
        """
        assert not run_check(wf, "GHA-069").passed

    def test_passes_when_no_id_token_scope(self):
        wf = """
        permissions:
          contents: read
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: ./build.sh
        """
        assert run_check(wf, "GHA-069").passed

    def test_passes_on_write_all_with_consumer(self):
        wf = """
        permissions: write-all
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - uses: pypa/gh-action-pypi-publish@release/v1
        """
        assert run_check(wf, "GHA-069").passed

    def test_fails_on_write_all_without_consumer(self):
        wf = """
        permissions: write-all
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: ./build.sh
        """
        assert not run_check(wf, "GHA-069").passed

    def test_job_permissions_override_workflow(self):
        # Workflow grants id-token: write; job replaces with read-only
        # set. Job has no id-token, so rule passes for that job.
        wf = """
        permissions:
          id-token: write
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions:
              contents: read
            steps:
              - run: ./build.sh
        """
        assert run_check(wf, "GHA-069").passed

    def test_passes_on_sigstore_cosign(self):
        wf = """
        permissions:
          id-token: write
        jobs:
          sign:
            runs-on: ubuntu-latest
            steps:
              - uses: sigstore/cosign-installer@v3
              - run: cosign sign --yes ghcr.io/x/y@sha256:abc
        """
        assert run_check(wf, "GHA-069").passed
