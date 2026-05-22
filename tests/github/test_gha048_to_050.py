"""Per-rule tests for the GHA-04x worm-mitigation pack:
GHA-048 (workflow self-mutation),
GHA-049 (cross-repo push from CI),
GHA-050 (publish without OIDC trusted-publisher gating).
"""
from __future__ import annotations

from .conftest import run_check

# ── GHA-048 workflow self-mutation ───────────────────────────────────


class TestGHA048SelfMutation:
    def test_fails_on_heredoc_write_to_workflows_dir(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions: { contents: write }
            steps:
              - run: |
                  cat > .github/workflows/shai-hulud.yml <<'EOF'
                  name: shai
                  on: push
                  jobs: { x: { runs-on: ubuntu-latest, steps: [{run: 'echo hi'}] } }
                  EOF
        """
        f = run_check(wf, "GHA-048")
        assert not f.passed
        assert "workflows" in f.description.lower()

    def test_fails_on_cp_into_workflows_dir(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions: { contents: write }
            steps:
              - run: cp payload.yml .github/workflows/lint.yml
        """
        f = run_check(wf, "GHA-048")
        assert not f.passed

    def test_fails_on_redirect_to_workflows_dir(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions: { contents: write }
            steps:
              - run: 'echo "name: spread" > .github/workflows/spread.yml'
        """
        f = run_check(wf, "GHA-048")
        assert not f.passed

    def test_passes_when_workflow_path_only_in_log_message(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions: { contents: read }
            steps:
              - run: echo "Workflows live under .github/workflows" > /tmp/log
        """
        f = run_check(wf, "GHA-048")
        assert f.passed

    def test_passes_on_clean_workflow(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions: { contents: read }
            steps:
              - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
              - run: npm test
        """
        f = run_check(wf, "GHA-048")
        assert f.passed


# ── GHA-049 cross-repo push ──────────────────────────────────────────


class TestGHA049CrossRepoPush:
    def test_fails_on_git_push_with_env_var_url(self):
        wf = """
        name: spread
        on: push
        jobs:
          mirror:
            runs-on: ubuntu-latest
            permissions: { contents: write }
            steps:
              - run: git push $TARGET_URL main
        """
        f = run_check(wf, "GHA-049")
        assert not f.passed

    def test_fails_on_git_push_with_expression_url(self):
        wf = """
        name: spread
        on: push
        jobs:
          mirror:
            runs-on: ubuntu-latest
            permissions: { contents: write }
            steps:
              - run: git push ${{ inputs.target_url }} main
        """
        f = run_check(wf, "GHA-049")
        assert not f.passed

    def test_fails_on_gh_repo_create_parameterized(self):
        wf = """
        name: bootstrap
        on: workflow_dispatch
        jobs:
          create:
            runs-on: ubuntu-latest
            permissions: { contents: write, administration: write }
            steps:
              - run: gh repo create ${{ inputs.new_repo }} --public
        """
        f = run_check(wf, "GHA-049")
        assert not f.passed

    def test_fails_on_gh_api_post_parameterized(self):
        wf = """
        name: bootstrap
        on: workflow_dispatch
        jobs:
          poke:
            runs-on: ubuntu-latest
            permissions: { contents: write }
            steps:
              - run: gh api -X POST /repos/$OWNER/$REPO/issues -f title=hi
        """
        f = run_check(wf, "GHA-049")
        assert not f.passed

    def test_passes_on_git_push_origin(self):
        wf = """
        name: ci
        on: push
        jobs:
          mirror:
            runs-on: ubuntu-latest
            permissions: { contents: write }
            steps:
              - run: git push origin main
        """
        f = run_check(wf, "GHA-049")
        assert f.passed

    def test_passes_on_clean_workflow(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions: { contents: read }
            steps:
              - run: npm test
        """
        f = run_check(wf, "GHA-049")
        assert f.passed

    def test_fails_on_cicd_goat_scenario_23_actions_bot_bypass(self):
        # Body lifted from cicd-goat scenario 23. The combination
        # of ``git config user.name "github-actions[bot]"`` + ``git
        # push origin HEAD:main`` is the branch-protection
        # bypass-allowance abuse shape, even though origin is the
        # canonical remote.
        wf = """
        name: scenario-23-actions-bot-branch-protection-bypass
        on:
          push:
            branches: [main]
        permissions:
          contents: write
        jobs:
          auto-format:
            if: false
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: |
                  set -euo pipefail
                  npm install
                  npm run format
                  git config user.name "github-actions[bot]"
                  git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
                  git add -A
                  if ! git diff --cached --quiet; then
                    git commit -m "chore: auto-format"
                    git push origin HEAD:main
                  fi
        """
        f = run_check(wf, "GHA-049")
        assert not f.passed
        assert "github-actions[bot]" in f.description

    def test_passes_on_actions_bot_identity_without_push(self):
        # Bot identity is sometimes set just for the commit message
        # ledger; without a push, no bypass-abuse shape exists.
        wf = """
        name: ci
        on: push
        jobs:
          tag:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: |
                  git config user.name "github-actions[bot]"
                  git tag v1.0.0
        """
        f = run_check(wf, "GHA-049")
        assert f.passed

    def test_passes_on_push_without_bot_identity(self):
        # Plain ``git push origin`` without assuming the bot identity
        # stays in the existing carve-out (release jobs, mirror
        # syncs, etc. that run as the workflow's default actor).
        wf = """
        name: ci
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: |
                  git tag v1.0.0
                  git push origin v1.0.0
        """
        f = run_check(wf, "GHA-049")
        assert f.passed


# ── GHA-050 publish without OIDC / environment gate ──────────────────


class TestGHA050PublishWithoutOIDC:
    def test_fails_on_npm_publish_with_node_auth_token(self):
        wf = """
        name: release
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            permissions: { contents: read }
            steps:
              - run: npm publish
                env:
                  NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
        """
        f = run_check(wf, "GHA-050")
        assert not f.passed
        assert "npm publish" in f.description.lower() or "long-lived" in f.description.lower()

    def test_fails_on_twine_upload_with_pypi_token(self):
        wf = """
        name: release
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            permissions: { contents: read }
            steps:
              - run: twine upload dist/*
                env:
                  TWINE_PASSWORD: ${{ secrets.PYPI_TOKEN }}
        """
        f = run_check(wf, "GHA-050")
        assert not f.passed

    def test_fails_on_pypa_publish_action_with_password(self):
        wf = """
        name: release
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            permissions: { contents: read }
            steps:
              - uses: pypa/gh-action-pypi-publish@release/v1
                with:
                  password: ${{ secrets.PYPI_TOKEN }}
        """
        f = run_check(wf, "GHA-050")
        assert not f.passed

    def test_passes_when_environment_gated(self):
        # Protected environment compensates for a static token.
        wf = """
        name: release
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            environment: npm-publish
            permissions: { contents: read }
            steps:
              - run: npm publish
                env:
                  NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
        """
        f = run_check(wf, "GHA-050")
        assert f.passed

    def test_passes_on_trusted_publisher_oidc_flow(self):
        # No long-lived secret; ``pypa/gh-action-pypi-publish`` without
        # a ``password`` input rides the OIDC trusted-publisher path.
        wf = """
        name: release
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              id-token: write
            steps:
              - uses: pypa/gh-action-pypi-publish@release/v1
        """
        f = run_check(wf, "GHA-050")
        assert f.passed

    def test_passes_when_no_publish_step(self):
        wf = """
        name: ci
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            permissions: { contents: read }
            steps: [{run: 'npm test'}]
        """
        f = run_check(wf, "GHA-050")
        assert f.passed


class TestGHA050AttestationExplicitlyDisabled:
    """Widening: zizmor proposal #938. ``pypa/gh-action-pypi-publish``
    with ``attestations: false`` and ``docker/build-push-action`` with
    ``provenance: false`` / ``sbom: false`` / ``attestations: false``
    turn off trusted-publishing's attestation surface while staying
    under the long-lived-secret check's radar."""

    def test_fails_on_pypi_publish_attestations_false(self):
        wf = """
        name: release
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            permissions:
              id-token: write
            steps:
              - uses: pypa/gh-action-pypi-publish@release/v1
                with:
                  attestations: false
        """
        f = run_check(wf, "GHA-050")
        assert not f.passed
        assert "attestations" in f.description.lower()
        assert "false" in f.description.lower()

    def test_fails_on_docker_build_push_provenance_false(self):
        wf = """
        name: build
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions:
              packages: write
              id-token: write
            steps:
              - uses: docker/build-push-action@v6
                with:
                  push: true
                  provenance: false
                  tags: ghcr.io/example/image:latest
        """
        f = run_check(wf, "GHA-050")
        assert not f.passed
        assert "provenance" in f.description.lower()

    def test_fails_on_docker_build_push_sbom_false(self):
        wf = """
        name: build
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions:
              packages: write
              id-token: write
            steps:
              - uses: docker/build-push-action@v6
                with:
                  push: true
                  sbom: false
                  tags: ghcr.io/example/image:latest
        """
        f = run_check(wf, "GHA-050")
        assert not f.passed
        assert "sbom" in f.description.lower()

    def test_passes_when_docker_push_false(self):
        # No publish at all - the disable doesn't matter.
        wf = """
        name: build
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: docker/build-push-action@v6
                with:
                  push: false
                  provenance: false
                  sbom: false
        """
        f = run_check(wf, "GHA-050")
        assert f.passed

    def test_passes_when_pypi_publish_defaults(self):
        # No explicit attestations field - defaults to true (PEP 740).
        wf = """
        name: release
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            permissions:
              id-token: write
            steps:
              - uses: pypa/gh-action-pypi-publish@release/v1
        """
        f = run_check(wf, "GHA-050")
        assert f.passed

    def test_passes_when_environment_gated(self):
        # Environment carve-out applies to the new disable shape too.
        wf = """
        name: release
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            environment: pypi-publish
            permissions:
              id-token: write
            steps:
              - uses: pypa/gh-action-pypi-publish@release/v1
                with:
                  attestations: false
        """
        f = run_check(wf, "GHA-050")
        assert f.passed

    def test_docker_build_push_attestations_false(self):
        wf = """
        name: build
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions:
              packages: write
              id-token: write
            steps:
              - uses: docker/build-push-action@v6
                with:
                  push: true
                  attestations: false
        """
        f = run_check(wf, "GHA-050")
        assert not f.passed
        assert "attestations" in f.description.lower()
