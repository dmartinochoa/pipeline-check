"""Detection quality tests — edge cases for cross-provider regex patterns.

Each test documents a concrete real-world input that previously caused a
false positive or false negative, preventing regression.
"""
from __future__ import annotations

import pytest

from pipeline_check.core.checks.base import (
    CURL_PIPE_RE,
    DOCKER_INSECURE_RE,
    PKG_NO_LOCKFILE_RE,
    TLS_BYPASS_RE,
)

# ────────────────────────────────────────────────────────────────────────
# TLS_BYPASS_RE — MITM injection via disabled certificate verification
# ────────────────────────────────────────────────────────────────────────


class TestTLSBypassRE:
    """Every TLS bypass pattern must be caught regardless of position."""

    @pytest.mark.parametrize("cmd", [
        "curl -k https://example.com",
        "curl --insecure https://example.com",
        "curl -v -k https://example.com",
        "curl -sS -k https://registry.local/pkg.tar.gz",
        "curl -o out.tar.gz -k https://mirror.io/file",
    ])
    def test_curl_insecure_flag(self, cmd):
        assert TLS_BYPASS_RE.search(cmd.lower()), f"missed: {cmd}"

    @pytest.mark.parametrize("cmd", [
        "curl https://example.com",
        "curl -v -o file https://safe.io/archive.tar.gz",
    ])
    def test_curl_safe_not_flagged(self, cmd):
        assert not TLS_BYPASS_RE.search(cmd.lower()), f"false positive: {cmd}"

    @pytest.mark.parametrize("cmd", [
        "git config http.sslVerify false",
        "git config --global http.sslverify false",
    ])
    def test_git_ssl_verify(self, cmd):
        assert TLS_BYPASS_RE.search(cmd.lower()), f"missed: {cmd}"

    @pytest.mark.parametrize("cmd", [
        "NODE_TLS_REJECT_UNAUTHORIZED=0",
        "export NODE_TLS_REJECT_UNAUTHORIZED=0",
        "PYTHONHTTPSVERIFY=0",
        "export PYTHONHTTPSVERIFY=0",
        "GIT_SSL_NO_VERIFY=true",
        "export GIT_SSL_NO_VERIFY=true",
        "GOINSECURE=example.com",
    ])
    def test_env_var_bypass(self, cmd):
        assert TLS_BYPASS_RE.search(cmd.lower()), f"missed: {cmd}"


# ────────────────────────────────────────────────────────────────────────
# CURL_PIPE_RE — remote code execution via pipe to interpreter
# ────────────────────────────────────────────────────────────────────────


class TestCurlPipeRE:

    @pytest.mark.parametrize("cmd", [
        "curl https://example.com | bash",
        "curl https://example.com | sh",
        "curl https://example.com | sudo bash",
        "wget https://example.com | bash",
        "curl https://example.com | python",
        "curl https://example.com | python3",
        "wget https://example.com | python3",
        "curl https://example.com | perl",
        "curl https://example.com | ruby",
        "irm https://example.com | iex",
    ])
    def test_pipe_to_interpreter(self, cmd):
        assert CURL_PIPE_RE.search(cmd.lower()), f"missed: {cmd}"

    @pytest.mark.parametrize("cmd", [
        "curl https://example.com -o file.tar.gz",
        "wget https://example.com -O file.zip",
        "python3 -m pytest",
    ])
    def test_safe_not_flagged(self, cmd):
        assert not CURL_PIPE_RE.search(cmd.lower()), f"false positive: {cmd}"


# ────────────────────────────────────────────────────────────────────────
# DOCKER_INSECURE_RE — container escape via privileged/host mount
# ────────────────────────────────────────────────────────────────────────


class TestDockerInsecureRE:

    @pytest.mark.parametrize("cmd", [
        "docker run --privileged ubuntu",
        "docker run --cap-add SYS_ADMIN ubuntu",
        "docker run --net=host ubuntu",
        "docker run --pid=host ubuntu",
        "docker run --userns=host ubuntu",
        "docker run -v /var/run/docker.sock:/var/run/docker.sock ubuntu",
        "docker run -v /:/host ubuntu",
    ])
    def test_insecure_flags_caught(self, cmd):
        assert DOCKER_INSECURE_RE.search(cmd.lower()), f"missed: {cmd}"

    @pytest.mark.parametrize("cmd", [
        "docker run -v /app:/app ubuntu",
        "docker run -v /src:/src ubuntu",
        "docker run -v /home/user/code:/workspace ubuntu",
        "docker run -v /tmp/build:/build ubuntu",
        "docker run ubuntu echo hello",
    ])
    def test_benign_mounts_not_flagged(self, cmd):
        assert not DOCKER_INSECURE_RE.search(cmd.lower()), f"false positive: {cmd}"


# ────────────────────────────────────────────────────────────────────────
# PKG_NO_LOCKFILE_RE — go install version pinning
# ────────────────────────────────────────────────────────────────────────


class TestPkgNoLockfilePipInstall:
    """pip install with version pins should not be flagged."""

    @pytest.mark.parametrize("cmd", [
        "pip install boto3==1.34.0",
        "pip install boto3>=1.34",
        "pip install boto3~=1.34.0",
        "pip install pip-tools==7.3.0",
        "pip install .[dev]",
        "pip install .[test,lint]",
        "pip install .",
        "pip install -e .",
        "pip install -r requirements.txt",
        "pip install --require-hashes -r requirements.txt",
    ])
    def test_safe_pip_not_flagged(self, cmd):
        assert not PKG_NO_LOCKFILE_RE.search(cmd.lower()), f"false positive: {cmd}"

    @pytest.mark.parametrize("cmd", [
        "pip install boto3",
        "pip install requests",
        "pip3 install awscli",
        "pip install coverage pytest",
    ])
    def test_bare_pip_flagged(self, cmd):
        assert PKG_NO_LOCKFILE_RE.search(cmd.lower()), f"missed: {cmd}"


class TestPkgNoLockfileNpmGlobal:
    """npm install -g should not be flagged (npm ci doesn't support -g)."""

    @pytest.mark.parametrize("cmd", [
        "npm install -g typescript",
        "npm install --global @angular/cli",
        "npm install -g @angular/cli@17.0.0",
    ])
    def test_npm_global_not_flagged(self, cmd):
        assert not PKG_NO_LOCKFILE_RE.search(cmd.lower()), f"false positive: {cmd}"


class TestPkgNoLockfileGoInstall:

    @pytest.mark.parametrize("cmd", [
        "go install example.com/tool@v1.2.3",
        "go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.54.2",
        "go install golang.org/x/tools/gopls@v0.14.1",
    ])
    def test_pinned_versions_not_flagged(self, cmd):
        assert not PKG_NO_LOCKFILE_RE.search(cmd.lower()), f"false positive: {cmd}"

    @pytest.mark.parametrize("cmd", [
        "go install example.com/tool",
        "go install example.com/tool@latest",
    ])
    def test_unpinned_flagged(self, cmd):
        assert PKG_NO_LOCKFILE_RE.search(cmd.lower()), f"missed: {cmd}"


# ────────────────────────────────────────────────────────────────────────
# UNTRUSTED_CONTEXT_RE — GitHub Actions script injection
# ────────────────────────────────────────────────────────────────────────


class TestUntrustedContextRE:

    @pytest.fixture(autouse=True)
    def _load_re(self):
        from pipeline_check.core.checks.github.rules._helpers import UNTRUSTED_CONTEXT_RE
        self.re = UNTRUSTED_CONTEXT_RE

    @pytest.mark.parametrize("expr", [
        "${{ github.event.pull_request.title }}",
        "${{ github.event.pull_request.body }}",
        "${{ github.event.comment.body }}",
        "${{ github.event.review.body }}",
        "${{ github.event.issue.title }}",
        "${{ github.event.issue.body }}",
        "${{ github.event.head_commit.message }}",
        "${{ github.event.release.tag_name }}",
        "${{ github.event.release.name }}",
        "${{ github.event.release.body }}",
        "${{ github.event.discussion.title }}",
        "${{ github.event.discussion.body }}",
        "${{ github.head_ref }}",
        "${{ github.ref_name }}",
        "${{ github.actor }}",
        "${{ inputs.user_name }}",
        "${{ github.event.pages[0].page_name }}",
        "${{ github.event.pages.page_name }}",
        "${{ github.event.workflow_run.head_branch }}",
        "${{ github.event.client_payload.data }}",
    ])
    def test_untrusted_contexts_caught(self, expr):
        assert self.re.search(expr), f"missed: {expr}"

    @pytest.mark.parametrize("expr", [
        "${{ github.sha }}",
        "${{ github.run_id }}",
        "${{ github.repository }}",
        "${{ github.event.number }}",
        "${{ runner.os }}",
        "${{ env.MY_VAR }}",
    ])
    def test_safe_contexts_not_flagged(self, expr):
        assert not self.re.search(expr), f"false positive: {expr}"


# ────────────────────────────────────────────────────────────────────────
# Deploy name regex — word boundaries prevent substring matches
# ────────────────────────────────────────────────────────────────────────


class TestDeployNameRE:

    @pytest.fixture(autouse=True)
    def _load_re(self):
        from pipeline_check.core.checks.github.rules.gha014_deploy_environment import _DEPLOY_RE
        self.re = _DEPLOY_RE

    @pytest.mark.parametrize("name", [
        "deploy", "Deploy", "release", "publish", "promote",
        "deploy-prod", "release-v2", "publish-npm",
    ])
    def test_deploy_names_caught(self, name):
        assert self.re.search(name), f"missed: {name}"

    @pytest.mark.parametrize("name", [
        "deployment-config",  # "deployment" != "deploy"
        "deployed",           # past tense, not a verb stem
        "publisher",          # agent noun, not the verb
        "released",           # past tense
    ])
    def test_non_deploy_word_forms_not_flagged(self, name):
        assert not self.re.search(name), f"false positive: {name}"

    @pytest.mark.parametrize("name", [
        "release-notes",   # "release" is the standalone word — correctly flagged
        "publish-docs",    # "publish" is the standalone word — correctly flagged
    ])
    def test_compound_deploy_names_still_caught(self, name):
        """Hyphenated compounds where the first word IS deploy-related
        should still match — the operator can suppress with an ignore rule."""
        assert self.re.search(name), f"missed: {name}"


# ────────────────────────────────────────────────────────────────────────
# Deploy command RE — expanded coverage
# ────────────────────────────────────────────────────────────────────────


class TestDeployCommandRE:

    @pytest.fixture(autouse=True)
    def _load_re(self):
        from pipeline_check.core.checks.github.rules.gha014_deploy_environment import _DEPLOY_CMD_RE
        self.re = _DEPLOY_CMD_RE

    @pytest.mark.parametrize("cmd", [
        "kubectl apply -f manifest.yml",
        "kubectl create -f manifest.yml",
        "kubectl set image deployment/app app=img:v2",
        "kubectl rollout restart deployment/app",
        "terraform apply -auto-approve",
        "terraform destroy -auto-approve",
        "aws s3 cp build/ s3://bucket/",
        "aws s3 sync dist/ s3://bucket/",
        "aws cloudformation deploy --stack-name mystack",
        "aws ecs update-service --cluster prod --service app",
        "docker push myregistry/myimage:latest",
        "helm upgrade myrelease ./chart",
        "helm install myrelease ./chart",
        "gcloud app deploy",
        "gcloud run deploy myservice",
        "gcloud functions deploy myfunction",
        "ansible-playbook deploy.yml",
        "serverless deploy -r us-east-1",
        "az webapp deploy --name myapp",
        "az functionapp deploy --name func",
        "az containerapp update --name app",
    ])
    def test_deploy_commands_caught(self, cmd):
        assert self.re.search(cmd), f"missed: {cmd}"

    @pytest.mark.parametrize("cmd", [
        "npm ci",
        "npm test",
        "pytest tests/",
        "make build",
        "echo deploying...",
    ])
    def test_non_deploy_commands_not_flagged(self, cmd):
        assert not self.re.search(cmd), f"false positive: {cmd}"


# ────────────────────────────────────────────────────────────────────────
# Context-aware signing/SBOM/vuln-scan — no FP on test-only workflows
# ────────────────────────────────────────────────────────────────────────


class TestArtifactContextAwareness:
    """Signing, SBOM, and vuln-scan checks should pass on workflows
    that don't produce deployable artifacts."""

    def _scan_gha(self, doc):
        from pipeline_check.core.checks.base import clear_blob_cache
        from pipeline_check.core.checks.github.base import GitHubContext, Workflow
        from pipeline_check.core.checks.github.workflows import WorkflowChecks
        clear_blob_cache()
        ctx = GitHubContext([Workflow(path="test.yml", data=doc)])
        return {f.check_id: f.passed for f in WorkflowChecks(ctx).run()}

    def test_test_only_workflow_passes_artifact_checks(self):
        """A workflow that only runs tests should not be flagged for
        missing signing, SBOM, or vulnerability scanning."""
        import yaml
        doc = yaml.safe_load("""
name: test
on: push
permissions: {contents: read}
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: npm ci
      - run: npm test
""")
        results = self._scan_gha(doc)
        assert results["GHA-006"] is True, "signing check should pass on test-only workflow"
        assert results["GHA-007"] is True, "SBOM check should pass on test-only workflow"
        assert results["GHA-020"] is True, "vuln-scan check should pass on test-only workflow"

    def test_deploy_workflow_fails_artifact_checks(self):
        """A workflow that deploys should be flagged for missing signing."""
        import yaml
        doc = yaml.safe_load("""
name: deploy
on: push
permissions: {contents: read}
jobs:
  deploy:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: docker build -t app .
      - run: docker push app:latest
""")
        results = self._scan_gha(doc)
        assert results["GHA-006"] is False, "signing check should fail when artifacts are produced"
        assert results["GHA-007"] is False, "SBOM check should fail when artifacts are produced"

    def test_publish_workflow_fails_artifact_checks(self):
        """npm publish is artifact production — should trigger checks."""
        import yaml
        doc = yaml.safe_load("""
name: publish
on: push
permissions: {contents: read}
jobs:
  publish:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: npm ci
      - run: npm publish
""")
        results = self._scan_gha(doc)
        assert results["GHA-006"] is False, "signing check should fail on npm publish workflow"
