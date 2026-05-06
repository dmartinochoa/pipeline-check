"""Per-rule tests for the GitHub Actions supply-chain rules:
GHA-006 (signing), GHA-007 (SBOM), GHA-017 (docker insecure flags),
GHA-018 (insecure package source), GHA-021 (lockfile enforcement),
GHA-022 (dependency-update commands).

Each rule guards a different leg of the build-to-deploy chain. The
tests cover positive (compliant) and negative (triggers finding)
cases, plus the silent-pass branches where the rule shouldn't fire
because the precondition isn't met (no artifacts produced, no
package install, etc.).
"""
from __future__ import annotations

from .conftest import run_check

# ── GHA-006 signing ─────────────────────────────────────────────────


class TestGHA006Signing:
    def test_fails_when_artifacts_produced_without_signing(self):
        # Workflow uploads a build artifact but never signs it.
        wf = """
        name: release
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
              - run: make build
              - uses: actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882
                with:
                  name: dist
                  path: dist/
        """
        f = run_check(wf, "GHA-006")
        assert not f.passed

    def test_passes_with_cosign_signing(self):
        wf = """
        name: release
        on: push
        permissions:
          contents: read
          id-token: write
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
              - run: make build
              - uses: sigstore/cosign-installer@d7d6e1ce392b96c3e5ec33567f23c7c93c4c0e95
              - run: cosign sign --yes ghcr.io/example/app@sha256:abc
              - uses: actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882
                with:
                  name: dist
                  path: dist/
        """
        f = run_check(wf, "GHA-006")
        assert f.passed

    def test_silent_pass_when_no_artifacts_produced(self):
        # Lint-only workflow, no artifact production -> rule
        # short-circuits with passed=True.
        wf = """
        name: lint
        on: push
        permissions: { contents: read }
        jobs:
          lint:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
              - run: ruff check .
        """
        f = run_check(wf, "GHA-006")
        assert f.passed


# ── GHA-007 SBOM ────────────────────────────────────────────────────


class TestGHA007SBOM:
    def test_fails_when_artifacts_produced_without_sbom(self):
        wf = """
        name: release
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
              - run: docker build -t ghcr.io/example/app:v1 .
              - run: docker push ghcr.io/example/app:v1
        """
        f = run_check(wf, "GHA-007")
        assert not f.passed

    def test_passes_with_syft_sbom(self):
        wf = """
        name: release
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
              - run: docker build -t ghcr.io/example/app:v1 .
              - run: syft ghcr.io/example/app:v1 -o cyclonedx-json > sbom.json
              - run: docker push ghcr.io/example/app:v1
        """
        f = run_check(wf, "GHA-007")
        assert f.passed


# ── GHA-017 docker insecure flags ───────────────────────────────────


class TestGHA017DockerInsecure:
    def test_fails_on_privileged_flag(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: docker run --privileged builder make all
        """
        f = run_check(wf, "GHA-017")
        assert not f.passed

    def test_fails_on_cap_add_sys_admin(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: docker run --cap-add=SYS_ADMIN builder make all
        """
        f = run_check(wf, "GHA-017")
        assert not f.passed

    def test_passes_when_docker_run_uses_minimal_flags(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: docker run --rm -v ${{ github.workspace }}:/work builder make all
        """
        f = run_check(wf, "GHA-017")
        assert f.passed


# ── GHA-018 insecure package source ─────────────────────────────────


class TestGHA018PackageInsecure:
    def test_fails_on_pip_index_url_http(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: pip install --index-url http://example.com/simple/ requests
        """
        f = run_check(wf, "GHA-018")
        assert not f.passed

    def test_fails_on_npm_registry_http(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: npm install --registry http://internal.example.com/
        """
        f = run_check(wf, "GHA-018")
        assert not f.passed

    def test_passes_with_default_https_sources(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: pip install --require-hashes -r requirements.txt
        """
        f = run_check(wf, "GHA-018")
        assert f.passed


# ── GHA-021 lockfile enforcement ────────────────────────────────────


class TestGHA021Lockfile:
    def test_fails_on_npm_install(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: npm install
        """
        f = run_check(wf, "GHA-021")
        assert not f.passed

    def test_passes_on_npm_ci(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: npm ci
        """
        f = run_check(wf, "GHA-021")
        assert f.passed

    def test_passes_on_pip_require_hashes(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: pip install --require-hashes -r requirements.txt
        """
        f = run_check(wf, "GHA-021")
        assert f.passed


# ── GHA-022 dependency-update commands ──────────────────────────────


class TestGHA022DepUpdate:
    def test_fails_on_npm_update(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: npm update
        """
        f = run_check(wf, "GHA-022")
        assert not f.passed

    def test_fails_on_pip_install_upgrade(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: pip install --upgrade requests
        """
        f = run_check(wf, "GHA-022")
        assert not f.passed

    def test_passes_when_no_update_command(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: pip install --require-hashes -r requirements.txt
        """
        f = run_check(wf, "GHA-022")
        assert f.passed
