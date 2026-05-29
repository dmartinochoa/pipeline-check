"""Per-rule tests for the egress-control pack:
GHA-107 (harden-runner in audit mode, egress not blocked) and
GHA-108 (sensitive workflow with no runtime egress control).
"""
from __future__ import annotations

from .conftest import run_check

# ── GHA-107 harden-runner audit mode ─────────────────────────────────


class TestGHA107HardenRunnerEgressAudit:
    def test_fails_on_egress_policy_audit(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: step-security/harden-runner@v2
                with:
                  egress-policy: audit
              - run: npm ci
        """
        f = run_check(wf, "GHA-107")
        assert not f.passed
        assert "audit" in f.description.lower()

    def test_fails_when_egress_policy_unset(self):
        # harden-runner with no `with:` defaults to audit.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: step-security/harden-runner@v2
              - run: npm ci
        """
        f = run_check(wf, "GHA-107")
        assert not f.passed
        assert "unset" in f.description.lower()

    def test_fails_when_with_block_omits_egress_policy(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: step-security/harden-runner@v2
                with:
                  disable-sudo: true
              - run: npm ci
        """
        f = run_check(wf, "GHA-107")
        assert not f.passed

    def test_passes_on_egress_policy_block(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: step-security/harden-runner@v2
                with:
                  egress-policy: block
                  allowed-endpoints: >
                    github.com:443
              - run: npm ci
        """
        f = run_check(wf, "GHA-107")
        assert f.passed

    def test_passes_when_no_harden_runner(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: npm ci
        """
        f = run_check(wf, "GHA-107")
        assert f.passed

    def test_passes_on_expression_valued_policy(self):
        # A ${{ }} expression can't be resolved statically; don't flag.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: step-security/harden-runner@v2
                with:
                  egress-policy: ${{ inputs.policy }}
              - run: npm ci
        """
        f = run_check(wf, "GHA-107")
        assert f.passed

    def test_fails_on_one_of_several_jobs(self):
        wf = """
        name: ci
        on: push
        jobs:
          good:
            runs-on: ubuntu-latest
            steps:
              - uses: step-security/harden-runner@v2
                with:
                  egress-policy: block
              - run: make build
          bad:
            runs-on: ubuntu-latest
            steps:
              - uses: step-security/harden-runner@v2
                with:
                  egress-policy: audit
              - run: make test
        """
        f = run_check(wf, "GHA-107")
        assert not f.passed
        assert "bad" in f.description
        assert "good" not in f.description


# ── GHA-108 no runtime egress control ────────────────────────────────


class TestGHA108NoEgressControl:
    def test_fails_on_oidc_workflow_without_harden_runner(self):
        wf = """
        name: deploy
        on: push
        permissions:
          id-token: write
          contents: read
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
              - run: ./deploy.sh
        """
        f = run_check(wf, "GHA-108")
        assert not f.passed
        assert "deploy" in f.description

    def test_fails_on_job_level_oidc(self):
        wf = """
        name: deploy
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            permissions:
              id-token: write
            steps:
              - run: ./deploy.sh
        """
        f = run_check(wf, "GHA-108")
        assert not f.passed

    def test_fails_on_environment_gated_job(self):
        wf = """
        name: release
        on: push
        jobs:
          publish:
            runs-on: ubuntu-latest
            environment: production
            steps:
              - run: ./publish.sh
        """
        f = run_check(wf, "GHA-108")
        assert not f.passed

    def test_fails_on_write_all_permissions(self):
        # write-all subsumes id-token: write.
        wf = """
        name: deploy
        on: push
        permissions: write-all
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: ./deploy.sh
        """
        f = run_check(wf, "GHA-108")
        assert not f.passed

    def test_passes_when_harden_runner_present(self):
        # Even audit-mode harden-runner means an egress agent exists;
        # GHA-107 owns the audit-vs-block call, GHA-108 only the absence.
        wf = """
        name: deploy
        on: push
        permissions:
          id-token: write
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - uses: step-security/harden-runner@v2
                with:
                  egress-policy: audit
              - run: ./deploy.sh
        """
        f = run_check(wf, "GHA-108")
        assert f.passed

    def test_passes_when_no_oidc_or_environment(self):
        wf = """
        name: ci
        on: push
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: npm test
        """
        f = run_check(wf, "GHA-108")
        assert f.passed

    def test_passes_when_job_overrides_oidc_away(self):
        # Top-level grants id-token: write, but the job narrows its own
        # permissions and drops it — that job is not OIDC-sensitive.
        wf = """
        name: ci
        on: push
        permissions:
          id-token: write
        jobs:
          test:
            runs-on: ubuntu-latest
            permissions:
              contents: read
            steps:
              - run: npm test
        """
        f = run_check(wf, "GHA-108")
        assert f.passed
