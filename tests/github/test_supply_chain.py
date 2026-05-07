"""Per-rule tests for the GitHub Actions supply-chain rules:
GHA-006 (signing), GHA-007 (SBOM), GHA-017 (docker insecure flags),
GHA-018 (insecure package source), GHA-020 (vulnerability scanning),
GHA-021 (lockfile enforcement), GHA-022 (dependency-update commands),
GHA-024 (SLSA provenance), GHA-029 (package source integrity).

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


# ── GHA-020 vulnerability scanning ──────────────────────────────────


class TestGHA020VulnScanning:
    def test_fails_when_artifact_built_without_scan(self):
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
        f = run_check(wf, "GHA-020")
        assert not f.passed

    def test_passes_with_trivy_step(self):
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
              - run: trivy image --severity HIGH,CRITICAL ghcr.io/example/app:v1
              - run: docker push ghcr.io/example/app:v1
        """
        f = run_check(wf, "GHA-020")
        assert f.passed


# ── GHA-024 SLSA provenance ─────────────────────────────────────────


class TestGHA024SLSAProvenance:
    def test_fails_when_artifact_built_without_provenance(self):
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
        f = run_check(wf, "GHA-024")
        assert not f.passed

    def test_passes_with_slsa_generator(self):
        wf = """
        name: release
        on: push
        permissions:
          contents: read
          id-token: write
        jobs:
          build:
            uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.10.0
            with:
              image: ghcr.io/example/app
              digest: sha256:abc
        """
        f = run_check(wf, "GHA-024")
        assert f.passed


# ── GHA-029 package source integrity ────────────────────────────────


class TestGHA029PackageSourceIntegrity:
    def test_fails_on_pip_install_git_url(self):
        # Installing from a git URL without a commit SHA pin lets the
        # upstream repo silently swap the installed code at run time.
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: pip install git+https://github.com/example/tool.git
        """
        f = run_check(wf, "GHA-029")
        assert not f.passed

    def test_passes_with_lockfile_install(self):
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
        f = run_check(wf, "GHA-029")
        assert f.passed


class TestGHA034ReusableSecretsInherit:
    def test_fails_on_secrets_inherit(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            uses: octo/repo/.github/workflows/build.yml@v2
            secrets: inherit
        """
        f = run_check(wf, "GHA-034")
        assert not f.passed
        assert "build" in f.description

    def test_fails_case_insensitive(self):
        # GitHub Actions accepts the lowercase form only, but we
        # match case-insensitively to catch the obvious variation.
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            uses: octo/repo/.github/workflows/build.yml@v2
            secrets: INHERIT
        """
        f = run_check(wf, "GHA-034")
        assert not f.passed

    def test_passes_with_explicit_secrets_mapping(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            uses: octo/repo/.github/workflows/build.yml@v2
            secrets:
              NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        """
        f = run_check(wf, "GHA-034")
        assert f.passed

    def test_passes_with_no_secrets_key(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            uses: octo/repo/.github/workflows/build.yml@v2
        """
        f = run_check(wf, "GHA-034")
        assert f.passed

    def test_passes_on_regular_job(self):
        # Regular jobs (no ``uses:`` at the job level) are out of
        # scope — this rule only applies to reusable-workflow calls.
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo hi
        """
        f = run_check(wf, "GHA-034")
        assert f.passed


class TestGHA035GitHubScriptInjection:
    def test_fails_on_pr_title_in_script(self):
        wf = """
        name: ci
        on: pull_request_target
        permissions: { contents: read }
        jobs:
          comment:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@v7
                with:
                  script: |
                    console.log("PR: ${{ github.event.pull_request.title }}");
        """
        f = run_check(wf, "GHA-035")
        assert not f.passed
        assert "comment[0]" in f.description

    def test_fails_on_head_ref_interpolation(self):
        wf = """
        name: ci
        on: pull_request_target
        permissions: { contents: read }
        jobs:
          act:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@v7
                with:
                  script: |
                    await github.rest.git.createRef({ ref: "${{ github.head_ref }}" });
        """
        f = run_check(wf, "GHA-035")
        assert not f.passed

    def test_passes_with_env_var_pattern(self):
        # The recommended shape: pass via env, read via process.env.X.
        wf = """
        name: ci
        on: pull_request_target
        permissions: { contents: read }
        jobs:
          comment:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@v7
                env:
                  PR_TITLE: ${{ github.event.pull_request.title }}
                with:
                  script: |
                    console.log("PR:", process.env.PR_TITLE);
        """
        f = run_check(wf, "GHA-035")
        assert f.passed

    def test_passes_for_trusted_step_outputs(self):
        # ``steps.<id>.outputs.<name>`` is curated as trusted — the
        # rule's regex only flags untrusted-context fields.
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          act:
            runs-on: ubuntu-latest
            steps:
              - id: build
                run: echo "id=abc" >> $GITHUB_OUTPUT
              - uses: actions/github-script@v7
                with:
                  script: |
                    console.log("${{ steps.build.outputs.id }}");
        """
        f = run_check(wf, "GHA-035")
        assert f.passed

    def test_passes_when_no_with_script(self):
        # ``actions/github-script`` invoked without ``with.script:``
        # has no JS body to inject into.
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          act:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@v7
        """
        f = run_check(wf, "GHA-035")
        assert f.passed

    def test_passes_for_non_github_script_action(self):
        # An unrelated action whose ``with.script`` happens to carry
        # an untrusted reference is out of scope — only
        # ``actions/github-script`` runs the value as JS.
        wf = """
        name: ci
        on: pull_request_target
        permissions: { contents: read }
        jobs:
          act:
            runs-on: ubuntu-latest
            steps:
              - uses: my-org/some-other-action@v1
                with:
                  script: ${{ github.event.pull_request.title }}
        """
        f = run_check(wf, "GHA-035")
        assert f.passed

    def test_fails_when_pinned_to_sha(self):
        # Pinning closes GHA-001 / GHA-025 but doesn't change the
        # injection surface — the script still runs the interpolated
        # value as JS.
        sha = "0" * 40
        wf = f"""
        name: ci
        on: pull_request_target
        permissions: {{ contents: read }}
        jobs:
          act:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@{sha}
                with:
                  script: |
                    console.log("${{{{ github.event.head_commit.message }}}}");
        """
        f = run_check(wf, "GHA-035")
        assert not f.passed
