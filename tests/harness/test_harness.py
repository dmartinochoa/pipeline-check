"""Tests for the Harness CI/CD provider (HARNESS-*)."""
from __future__ import annotations

from pathlib import Path

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.harness.base import HarnessContext
from pipeline_check.core.checks.harness.pipelines import HarnessPipelineChecks

_DA = "a" * 64
_DB = "b" * 64

# A pipeline exercising nested steps (parallel + stepGroup), an unpinned
# image, a digest-pinned image, and an untrusted-expression command.
_PIPELINE = f"""\
pipeline:
  identifier: build
  name: build
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: test
                  spec:
                    image: node:18
                    shell: Sh
                    command: echo "building <+codebase.prTitle>"
              - parallel:
                  - step:
                      type: Run
                      identifier: lint
                      spec:
                        image: golang@sha256:{_DA}
                        command: go vet ./...
                  - stepGroup:
                      identifier: grp
                      steps:
                        - step:
                            type: Plugin
                            identifier: publish
                            spec:
                              image: plugins/docker:latest
                              settings:
                                repo: my/app
"""

# A clean pipeline: digest-pinned image, command bound via env var.
_CLEAN = f"""\
pipeline:
  identifier: clean
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: test
                  spec:
                    image: node@sha256:{_DB}
                    envVariables:
                      PR_TITLE: <+codebase.prTitle>
                    command: echo "$PR_TITLE"
"""

# A realistically-shaped (fake) leaked GitHub PAT: ghp_ + 36 chars.
_LEAKED_TOKEN = "ghp_016d8d1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b"

# A pipeline with a privileged step and a literal-secret String variable
# alongside a properly-referenced Secret variable.
_RISKY = f"""\
pipeline:
  identifier: risky
  variables:
    - name: GH_TOKEN
      type: String
      value: {_LEAKED_TOKEN}
    - name: SAFE_TOKEN
      type: Secret
      value: <+secrets.getValue("gh_token")>
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: dind
                  spec:
                    image: docker@sha256:{_DA}
                    privileged: true
                    command: docker build .
"""

# Not a Harness pipeline (no top-level ``pipeline:`` key): must be skipped.
_NOT_HARNESS = """\
template:
  identifier: t
  type: Step
"""


def _ctx(tmp_path: Path, text: str, name: str = "pipeline.yaml") -> HarnessContext:
    f = tmp_path / name
    f.write_text(text, encoding="utf-8")
    return HarnessContext.from_path(f)


def _findings(ctx: HarnessContext) -> list:
    return HarnessPipelineChecks(ctx).run()


def _for(findings: list, check_id: str) -> list:
    return [f for f in findings if f.check_id == check_id]


class TestContextLoad:
    def test_keeps_only_pipeline_documents(self, tmp_path):
        ctx = _ctx(tmp_path, _NOT_HARNESS)
        assert ctx.pipelines == []

    def test_missing_path_raises(self):
        import pytest
        with pytest.raises(ValueError):
            HarnessContext.from_path("/no/such/harness/dir")

    def test_directory_scan_picks_up_yaml(self, tmp_path):
        (tmp_path / ".harness").mkdir()
        (tmp_path / ".harness" / "p.yaml").write_text(_CLEAN, encoding="utf-8")
        ctx = HarnessContext.from_path(tmp_path / ".harness")
        assert len(ctx.pipelines) == 1
        assert ctx.pipelines[0].identifier == "clean"


class TestHarness001ImagePinning:
    def test_flags_unpinned_step_and_plugin_images(self, tmp_path):
        out = [f for f in _for(_findings(_ctx(tmp_path, _PIPELINE)), "HARNESS-001")
               if not f.passed]
        assert len(out) == 1
        f = out[0]
        assert f.severity is Severity.HIGH
        # node:18 (Run) and plugins/docker:latest (Plugin, in a stepGroup)
        # are flagged; the digest-pinned golang is not.
        assert "ci/test=node:18" in f.description
        assert "ci/publish=plugins/docker:latest" in f.description
        assert "golang" not in f.description

    def test_passes_when_all_digest_pinned(self, tmp_path):
        out = _for(_findings(_ctx(tmp_path, _CLEAN)), "HARNESS-001")
        assert out and all(f.passed for f in out)


class TestHarness002ExpressionInjection:
    def test_flags_untrusted_expression_in_command(self, tmp_path):
        out = [f for f in _for(_findings(_ctx(tmp_path, _PIPELINE)), "HARNESS-002")
               if not f.passed]
        assert len(out) == 1
        f = out[0]
        assert f.severity is Severity.HIGH
        assert "ci/test" in f.description
        assert "codebase.prTitle" in f.description

    def test_env_var_binding_is_safe(self, tmp_path):
        # The clean pipeline binds <+codebase.prTitle> to an env var and
        # uses $PR_TITLE in the command; the command text has no expression.
        out = _for(_findings(_ctx(tmp_path, _CLEAN)), "HARNESS-002")
        assert out and all(f.passed for f in out)

    def test_commit_sha_not_flagged(self, tmp_path):
        text = _CLEAN.replace(
            'command: echo "$PR_TITLE"',
            'command: echo "<+codebase.commitSha>"',
        )
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-002")
               if not f.passed]
        assert out == []


class TestHarness003PrivilegedStep:
    def test_flags_privileged_step(self, tmp_path):
        out = [f for f in _for(_findings(_ctx(tmp_path, _RISKY)), "HARNESS-003")
               if not f.passed]
        assert len(out) == 1
        f = out[0]
        assert f.severity is Severity.HIGH
        assert "ci/dind" in f.description

    def test_passes_without_privileged(self, tmp_path):
        out = _for(_findings(_ctx(tmp_path, _CLEAN)), "HARNESS-003")
        assert out and all(f.passed for f in out)

    def test_privileged_false_not_flagged(self, tmp_path):
        text = _RISKY.replace("privileged: true", "privileged: false")
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-003")
               if not f.passed]
        assert out == []

    def test_quoted_true_string_is_flagged(self, tmp_path):
        # YAML ``privileged: "true"`` parses to the string "true", which is
        # still privileged; the docs_note promises "truthy", so the quoted
        # form must fire too (a strict ``is True`` check would miss it).
        text = _RISKY.replace("privileged: true", 'privileged: "true"')
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-003")
               if not f.passed]
        assert len(out) == 1


class TestHarness004LiteralSecret:
    def test_flags_literal_secret_string_variable(self, tmp_path):
        out = [f for f in _for(_findings(_ctx(tmp_path, _RISKY)), "HARNESS-004")
               if not f.passed]
        assert len(out) == 1
        f = out[0]
        assert f.severity is Severity.CRITICAL
        assert "pipeline.GH_TOKEN" in f.description
        # The Secret-typed reference variable is not flagged, and the raw
        # token value is redacted out of the finding.
        assert "SAFE_TOKEN" not in f.description
        assert _LEAKED_TOKEN not in f.description

    def test_secret_reference_is_safe(self, tmp_path):
        out = _for(_findings(_ctx(tmp_path, _CLEAN)), "HARNESS-004")
        assert out and all(f.passed for f in out)

    def test_non_secret_string_not_flagged(self, tmp_path):
        text = _RISKY.replace(_LEAKED_TOKEN, "production")
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-004")
               if not f.passed]
        assert out == []

    def test_flags_literal_secret_in_step_env_variables(self, tmp_path):
        # A token pasted into a step's ``spec.envVariables`` (the most
        # common placement) must fire — no pipeline/stage variable
        # needed. Regression for the A6 false negative.
        text = f"""\
pipeline:
  identifier: build
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: publish
                  spec:
                    image: node@sha256:{_DB}
                    envVariables:
                      GH_TOKEN: {_LEAKED_TOKEN}
                    command: npm publish
"""
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-004")
               if not f.passed]
        assert len(out) == 1
        assert "ci.publish.env.GH_TOKEN" in out[0].description
        assert _LEAKED_TOKEN not in out[0].description


_PIPE = """\
pipeline:
  identifier: build
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: install
                  spec:
                    image: alpine
                    command: |
                      curl -fsSL https://example.com/install.sh | sh
"""


class TestHarness005PipeToShell:
    def test_flags_pipe_to_shell(self, tmp_path):
        out = [f for f in _for(_findings(_ctx(tmp_path, _PIPE)), "HARNESS-005")
               if not f.passed]
        assert len(out) == 1
        assert out[0].severity is Severity.HIGH
        assert "ci/install" in out[0].description

    def test_download_then_execute_is_safe(self, tmp_path):
        text = _PIPE.replace(
            "curl -fsSL https://example.com/install.sh | sh",
            "curl -fsSL -o i.sh https://example.com/install.sh && sh i.sh",
        )
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-005")
               if not f.passed]
        assert out == []

    def test_clean_pipeline_passes(self, tmp_path):
        out = _for(_findings(_ctx(tmp_path, _CLEAN)), "HARNESS-005")
        assert out and all(f.passed for f in out)


_TLS = """\
pipeline:
  identifier: build
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: install
                  spec:
                    image: node
                    command: |
                      npm config set strict-ssl false
                      npm install
"""


class TestHarness006TlsBypass:
    def test_flags_tls_bypass(self, tmp_path):
        out = [f for f in _for(_findings(_ctx(tmp_path, _TLS)), "HARNESS-006")
               if not f.passed]
        assert len(out) == 1
        assert out[0].severity is Severity.HIGH
        assert "ci/install" in out[0].description

    def test_clean_pipeline_passes(self, tmp_path):
        out = _for(_findings(_ctx(tmp_path, _CLEAN)), "HARNESS-006")
        assert out and all(f.passed for f in out)


_HOSTPATH = """\
pipeline:
  identifier: build
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          infrastructure:
            type: KubernetesDirect
            spec:
              connectorRef: k8s
              namespace: harness
              volumes:
                - mountPath: /var/run
                  type: HostPath
                  spec:
                    path: /var/run/docker.sock
                - mountPath: /cache
                  type: EmptyDir
          execution:
            steps:
              - step:
                  type: Run
                  identifier: t
                  spec:
                    image: docker
                    command: docker build .
"""


class TestHarness007HostPathMount:
    def test_flags_sensitive_hostpath(self, tmp_path):
        out = [f for f in _for(_findings(_ctx(tmp_path, _HOSTPATH)), "HARNESS-007")
               if not f.passed]
        assert len(out) == 1
        f = out[0]
        assert f.severity is Severity.HIGH
        assert "/var/run/docker.sock" in f.description

    def test_emptydir_only_is_safe(self, tmp_path):
        text = _HOSTPATH.replace("type: HostPath", "type: EmptyDir")
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-007")
               if not f.passed]
        assert out == []

    def test_non_sensitive_hostpath_not_flagged(self, tmp_path):
        text = _HOSTPATH.replace("/var/run/docker.sock", "/opt/build-cache")
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-007")
               if not f.passed]
        assert out == []

    def test_etc_certs_subpath_is_exempt(self, tmp_path):
        # A narrow read-only cert subpath under /etc is a benign
        # CA-injection pattern, not a host-config escape (2026-07 audit).
        text = _HOSTPATH.replace("/var/run/docker.sock", "/etc/ssl/certs")
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-007")
               if not f.passed]
        assert out == []
        # mounting /etc itself still fires
        broad = _HOSTPATH.replace("/var/run/docker.sock", "/etc")
        out2 = [f for f in _for(_findings(_ctx(tmp_path, broad)), "HARNESS-007")
                if not f.passed]
        assert len(out2) == 1


_AI = """\
pipeline:
  identifier: build
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: review
                  spec:
                    image: node
                    command: claude -p "Review PR titled <+codebase.prTitle>"
"""


class TestHarness008AiPromptInjection:
    def test_flags_untrusted_context_into_agentic_cli(self, tmp_path):
        out = [f for f in _for(_findings(_ctx(tmp_path, _AI)), "HARNESS-008")
               if not f.passed]
        assert len(out) == 1
        f = out[0]
        assert f.severity is Severity.HIGH
        assert "ci/review" in f.description
        assert "claude" in f.description

    def test_agentic_cli_without_untrusted_context_is_safe(self, tmp_path):
        text = _AI.replace("<+codebase.prTitle>", "the staged diff")
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-008")
               if not f.passed]
        assert out == []

    def test_untrusted_context_without_agentic_cli_not_flagged(self, tmp_path):
        # HARNESS-002 catches this shell-injection case; HARNESS-008 only
        # fires when an agentic CLI is the sink.
        text = _AI.replace("claude -p ", "echo ")
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-008")
               if not f.passed]
        assert out == []


_AUTOLAND = """\
pipeline:
  identifier: build
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: edit
                  spec:
                    image: node
                    command: |
                      aider --yes --message apply
                      git add -A && git commit -m auto && git push origin HEAD
"""


class TestHarness009AiAutoland:
    def test_flags_agent_plus_push(self, tmp_path):
        out = [f for f in _for(_findings(_ctx(tmp_path, _AUTOLAND)), "HARNESS-009")
               if not f.passed]
        assert len(out) == 1
        f = out[0]
        assert f.severity is Severity.HIGH
        assert "aider" in f.description

    def test_dry_run_push_is_ignored(self, tmp_path):
        text = _AUTOLAND.replace("git push origin HEAD", "git push --dry-run origin HEAD")
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-009")
               if not f.passed]
        assert out == []

    def test_agent_without_push_is_safe(self, tmp_path):
        out = _for(_findings(_ctx(tmp_path, _AI)), "HARNESS-009")
        assert out and all(f.passed for f in out)

    def test_push_without_agent_is_safe(self, tmp_path):
        text = _AUTOLAND.replace("aider --yes --message apply", "echo building")
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-009")
               if not f.passed]
        assert out == []


def _model_pipeline(cmd: str) -> str:
    return f"""\
pipeline:
  identifier: build
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: load
                  spec:
                    image: python
                    command: |
                      {cmd}
"""


class TestHarness010TrustRemoteCode:
    def test_flags_trust_remote_code(self, tmp_path):
        text = _model_pipeline(
            "python -c 'AutoModel.from_pretrained(\"x\", trust_remote_code=True)'"
        )
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-010")
               if not f.passed]
        assert len(out) == 1
        assert out[0].severity is Severity.HIGH
        assert "ci/load" in out[0].description

    def test_passes_without_trust_remote_code(self, tmp_path):
        out = _for(_findings(_ctx(tmp_path, _CLEAN)), "HARNESS-010")
        assert out and all(f.passed for f in out)


class TestHarness011UnsafeDeser:
    def test_flags_fetch_plus_unpickle(self, tmp_path):
        text = _model_pipeline(
            "curl -fsSL -o m.pt https://x/m.pt && "
            "python -c 'import torch; torch.load(\"m.pt\")'"
        )
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-011")
               if not f.passed]
        assert len(out) == 1
        assert out[0].severity is Severity.HIGH
        assert "ci/load" in out[0].description

    def test_local_unpickle_without_fetch_is_safe(self, tmp_path):
        text = _model_pipeline("python -c 'import torch; torch.load(\"local.pt\")'")
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-011")
               if not f.passed]
        assert out == []


class TestHarness012ModelPinning:
    _PIN = "0123456789abcdef0123456789abcdef01234567"

    def test_flags_unpinned_org_model(self, tmp_path):
        text = _model_pipeline(
            "python -c 'AutoModel.from_pretrained(\"acme/llm\")'"
        )
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-012")
               if not f.passed]
        assert len(out) == 1
        assert out[0].severity is Severity.MEDIUM
        assert "ci/load" in out[0].description
        assert "acme/llm" in out[0].description

    def test_flags_unpinned_cli_download(self, tmp_path):
        text = _model_pipeline("huggingface-cli download acme/llm")
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-012")
               if not f.passed]
        assert len(out) == 1

    def test_passes_when_revision_pinned(self, tmp_path):
        text = _model_pipeline(
            f"python -c 'AutoModel.from_pretrained(\"acme/llm\", "
            f"revision=\"{self._PIN}\")'"
        )
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-012")
               if not f.passed]
        assert out == []

    def test_passes_on_first_party_hub_name(self, tmp_path):
        # No org/ namespace -> canonical first-party model, not flagged.
        text = _model_pipeline(
            "python -c 'AutoModel.from_pretrained(\"bert-base-uncased\")'"
        )
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-012")
               if not f.passed]
        assert out == []

    def test_passes_clean_pipeline(self, tmp_path):
        out = _for(_findings(_ctx(tmp_path, _CLEAN)), "HARNESS-012")
        assert out and all(f.passed for f in out)


class TestHarness013LogLeak:
    def test_flags_echo_secret_named_var(self, tmp_path):
        text = _model_pipeline('echo "key is $AWS_SECRET_ACCESS_KEY"')
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-013")
               if not f.passed]
        assert len(out) == 1
        assert out[0].severity is Severity.HIGH
        assert "ci/load" in out[0].description

    def test_flags_printenv_dump(self, tmp_path):
        text = _model_pipeline("printenv")
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-013")
               if not f.passed]
        assert len(out) == 1

    def test_passes_on_safe_existence_check(self, tmp_path):
        text = _model_pipeline('[ -n "$TOKEN" ] && echo set || echo unset')
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-013")
               if not f.passed]
        assert out == []

    def test_passes_clean_pipeline(self, tmp_path):
        out = _for(_findings(_ctx(tmp_path, _CLEAN)), "HARNESS-013")
        assert out and all(f.passed for f in out)


class TestHarness014ShellEval:
    def test_flags_eval_variable(self, tmp_path):
        text = _model_pipeline('eval "$BUILD_CMD"')
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-014")
               if not f.passed]
        assert len(out) == 1
        assert out[0].severity is Severity.HIGH
        assert "ci/load" in out[0].description

    def test_passes_on_ssh_agent_bootstrap(self, tmp_path):
        text = _model_pipeline('eval "$(ssh-agent -s)"')
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-014")
               if not f.passed]
        assert out == []

    def test_passes_clean_pipeline(self, tmp_path):
        out = _for(_findings(_ctx(tmp_path, _CLEAN)), "HARNESS-014")
        assert out and all(f.passed for f in out)


# A pipeline whose only build step is Harness's native CIE build step
# (``type: BuildAndPushDockerRegistry``) with no ``docker build`` /
# ``docker push`` command text, plus an optional STO scanner step.
_NATIVE_BUILD = """\
pipeline:
  identifier: build
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: BuildAndPushDockerRegistry
                  identifier: build
                  spec:
                    repo: my/app
                    tags: [latest]
"""

_NATIVE_BUILD_WITH_GRYPE = _NATIVE_BUILD + """\
              - step:
                  type: Grype
                  identifier: scan
                  spec:
                    mode: orchestration
"""


class TestHarness015to018SupplyChainGates:
    def _build(self, *extra: str) -> str:
        cmd = "docker build -t app . && docker push app"
        for e in extra:
            cmd += " && " + e
        return _model_pipeline(cmd)

    def _failing(self, tmp_path, text, rule_id):
        return [f for f in _for(_findings(_ctx(tmp_path, text)), rule_id)
                if not f.passed]

    def test_sbom_fires_on_native_build_step(self, tmp_path):
        # ``BuildAndPushDockerRegistry`` produces an image; a build with
        # no SBOM must fire (B4 FN: native build step was invisible to
        # the artifact heuristic).
        assert self._failing(tmp_path, _NATIVE_BUILD, "HARNESS-016")

    def test_provenance_fires_on_native_build_step(self, tmp_path):
        assert self._failing(tmp_path, _NATIVE_BUILD, "HARNESS-017")

    def test_vuln_fires_on_native_build_without_scanner(self, tmp_path):
        assert self._failing(tmp_path, _NATIVE_BUILD, "HARNESS-018")

    def test_vuln_passes_with_native_sto_scanner_step(self, tmp_path):
        # A native STO ``type: Grype`` step names the scanner as a bare
        # scalar (no command text); it must count as scanning (B4 FN:
        # only AquaTrivy was recognized before).
        assert self._failing(tmp_path, _NATIVE_BUILD_WITH_GRYPE,
                             "HARNESS-018") == []

    def test_signing_fails_on_unsigned_build(self, tmp_path):
        out = self._failing(tmp_path, self._build(), "HARNESS-015")
        assert len(out) == 1
        assert out[0].severity is Severity.MEDIUM

    def test_signing_passes_with_cosign(self, tmp_path):
        text = self._build("cosign sign --yes app")
        assert self._failing(tmp_path, text, "HARNESS-015") == []

    def test_signing_not_applicable_on_lint_only(self, tmp_path):
        # _CLEAN produces no artifacts -> signing gate is not applicable.
        out = _for(_findings(_ctx(tmp_path, _CLEAN)), "HARNESS-015")
        assert out and all(f.passed for f in out)

    def test_sbom_fails_then_passes(self, tmp_path):
        assert self._failing(tmp_path, self._build(), "HARNESS-016")
        text = self._build("syft app -o cyclonedx-json")
        assert self._failing(tmp_path, text, "HARNESS-016") == []

    def test_provenance_fails_then_passes(self, tmp_path):
        assert self._failing(tmp_path, self._build(), "HARNESS-017")
        text = self._build("cosign attest --predicate slsa.json app")
        assert self._failing(tmp_path, text, "HARNESS-017") == []

    def test_vuln_fails_then_passes(self, tmp_path):
        assert self._failing(tmp_path, self._build(), "HARNESS-018")
        text = self._build("trivy image app")
        assert self._failing(tmp_path, text, "HARNESS-018") == []


class TestHarness019NoTimeout:
    _UNBOUNDED = """\
pipeline:
  identifier: build
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: test
                  spec:
                    command: make test
"""
    _STEP_BOUNDED = """\
pipeline:
  identifier: build
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: test
                  timeout: 10m
                  spec:
                    command: make test
"""
    _STAGE_BOUNDED = """\
pipeline:
  identifier: build
  stages:
    - stage:
        identifier: ci
        type: CI
        timeout: 1h
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: test
                  spec:
                    command: make test
"""
    _EMPTY_TIMEOUT = """\
pipeline:
  identifier: build
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: test
                  timeout: ""
                  spec:
                    command: make test
"""

    def _failing(self, tmp_path, text):
        return [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-019")
                if not f.passed]

    def test_flags_step_without_timeout(self, tmp_path):
        out = self._failing(tmp_path, self._UNBOUNDED)
        assert len(out) == 1
        assert out[0].severity is Severity.LOW
        assert "ci/test" in out[0].description

    def test_passes_with_step_timeout(self, tmp_path):
        assert self._failing(tmp_path, self._STEP_BOUNDED) == []

    def test_stage_timeout_bounds_all_steps(self, tmp_path):
        assert self._failing(tmp_path, self._STAGE_BOUNDED) == []

    def test_empty_timeout_string_still_flags(self, tmp_path):
        # timeout: "" is the key present but value unset -> Harness default.
        assert self._failing(tmp_path, self._EMPTY_TIMEOUT)

    _TWO_IDLESS_STAGES = """\
pipeline:
  identifier: build
  stages:
    - stage:
        type: CI
        timeout: 1h
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: bounded
                  spec:
                    command: make a
    - stage:
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: unbounded
                  spec:
                    command: make b
"""

    def test_idless_stage_timeout_not_misattributed(self, tmp_path):
        # Two id-less stages both fall back to the label "stage"; a
        # stage_id-keyed map used to let the second stage's missing
        # timeout overwrite the first's 1h bound, flagging the bounded
        # step (2026-07 audit LOW FP).
        out = self._failing(tmp_path, self._TWO_IDLESS_STAGES)
        assert len(out) == 1
        # Only the truly-unbounded step is flagged; the 1h-bounded one is
        # not ("stage/bounded" is not a substring of "stage/unbounded").
        assert "stage/unbounded" in out[0].description
        assert "stage/bounded" not in out[0].description
