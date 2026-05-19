"""Per-rule tests for GHA-059 (npm install without `npm audit signatures`)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA059NpmAuditSignatures:
    def test_fails_when_npm_ci_without_audit_signatures(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: actions/setup-node@v4
                with: { node-version: 20 }
              - run: npm ci
              - run: npm run build
        """
        f = run_check(wf, "GHA-059")
        assert not f.passed
        assert "audit signatures" in f.description.lower() or "signature" in f.description.lower()

    def test_fails_when_npm_install_without_audit_signatures(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: npm install
        """
        f = run_check(wf, "GHA-059")
        assert not f.passed

    def test_fails_when_npm_i_shorthand_without_audit_signatures(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: npm i
        """
        f = run_check(wf, "GHA-059")
        assert not f.passed

    def test_fails_when_pnpm_install_without_audit_signatures(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: pnpm install
        """
        f = run_check(wf, "GHA-059")
        assert not f.passed

    def test_fails_when_pnpm_i_without_audit_signatures(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: pnpm i
        """
        f = run_check(wf, "GHA-059")
        assert not f.passed

    def test_fails_when_pnpm_ci_without_audit_signatures(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: pnpm ci
        """
        f = run_check(wf, "GHA-059")
        assert not f.passed

    def test_passes_when_npm_ci_followed_by_audit_signatures(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: npm ci
              - run: npm audit signatures
        """
        f = run_check(wf, "GHA-059")
        assert f.passed

    def test_passes_when_pnpm_audit_signatures_present(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: pnpm install
              - run: pnpm audit signatures
        """
        f = run_check(wf, "GHA-059")
        assert f.passed

    def test_passes_when_audit_signatures_runs_in_separate_job(self):
        # Audit verification doesn't have to share a job with the
        # install; as long as some job in the workflow runs it, the
        # workflow's posture is sound. Cross-job verification is a
        # common shape for monorepos that fan out the install across
        # multiple jobs.
        wf = """
        name: ci
        on: push
        jobs:
          install:
            runs-on: ubuntu-latest
            steps:
              - run: npm ci
          verify:
            runs-on: ubuntu-latest
            needs: install
            steps:
              - run: npm audit signatures
        """
        f = run_check(wf, "GHA-059")
        assert f.passed

    def test_passes_silently_when_workflow_has_no_install_step(self):
        wf = """
        name: lint-only
        on: push
        jobs:
          lint:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: pre-commit run --all-files
        """
        f = run_check(wf, "GHA-059")
        assert f.passed

    def test_passes_silently_on_yarn_only_workflow(self):
        # Yarn doesn't have a meaningful ``yarn audit signatures``
        # primitive; the rule scopes to npm / pnpm to avoid a
        # false-positive on yarn-only repos.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: yarn install
              - run: yarn build
        """
        f = run_check(wf, "GHA-059")
        assert f.passed

    def test_does_not_match_npm_pack_or_npm_test(self):
        # Regression: the install regex anchors on the install verbs;
        # ``npm pack`` / ``npm test`` / ``npm publish`` / ``pnpm exec``
        # must not trip the rule.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: npm pack
              - run: npm test
              - run: pnpm exec something
        """
        f = run_check(wf, "GHA-059")
        assert f.passed

    def test_offender_description_lists_job_step_label(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - name: Install
                run: npm ci
        """
        f = run_check(wf, "GHA-059")
        assert not f.passed
        assert "build.Install" in f.description
