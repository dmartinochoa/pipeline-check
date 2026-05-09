"""Per-rule tests for GitHub Actions cache, log-channel, and secret-echo rules:
GHA-011 (cache key derives from attacker-controllable input),
GHA-031 (workflow uses retired ``::set-output``/``::save-state``),
GHA-033 (secret value echoed / printed in a run: block).

GHA-011 closes the cache-poisoning gap that PR-controlled inputs
in the key namespace open. GHA-031 catches the retired stdout
control channel that any tool's diagnostic line can inject into.
GHA-033 covers both the obvious and indirect forms of secret
leakage to the build log.
"""
from __future__ import annotations

from .conftest import run_check

# ── GHA-011 cache key from attacker-controlled input ────────────────


class TestGHA011CacheKey:
    def test_fails_when_cache_key_uses_pr_head_ref(self):
        wf = """
        name: ci
        on: pull_request
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/cache@1bd1e32a3bdc45362d1e726936510720a7c30a57
                with:
                  path: ~/.cache/pip
                  key: pip-${{ github.head_ref }}
        """
        f = run_check(wf, "GHA-011")
        assert not f.passed

    def test_fails_when_cache_key_uses_event_pull_request_title(self):
        wf = """
        name: ci
        on: pull_request_target
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/cache@1bd1e32a3bdc45362d1e726936510720a7c30a57
                with:
                  path: ~/.cache/pip
                  key: pip-${{ github.event.pull_request.title }}
        """
        f = run_check(wf, "GHA-011")
        assert not f.passed

    def test_passes_with_runner_os_and_lockfile_hash(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/cache@1bd1e32a3bdc45362d1e726936510720a7c30a57
                with:
                  path: ~/.cache/pip
                  key: pip-${{ runner.os }}-${{ hashFiles('**/requirements.txt') }}
        """
        f = run_check(wf, "GHA-011")
        assert f.passed

    def test_passes_when_no_cache_step(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: make test
        """
        f = run_check(wf, "GHA-011")
        assert f.passed


# ── GHA-031 retired set-output / save-state ────────────────────────


class TestGHA031DeprecatedCommands:
    def test_fails_on_set_output_command(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - id: meta
                run: echo "::set-output name=version::1.0"
        """
        f = run_check(wf, "GHA-031")
        assert not f.passed

    def test_fails_on_save_state_command(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: echo "::save-state name=cache_hit::true"
        """
        f = run_check(wf, "GHA-031")
        assert not f.passed

    def test_passes_with_github_output_redirect(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - id: meta
                run: echo "version=1.0" >> "$GITHUB_OUTPUT"
        """
        f = run_check(wf, "GHA-031")
        assert f.passed


# ── GHA-033 secret echoed in run: block ─────────────────────────────


class TestGHA033SecretEchoed:
    def test_fails_when_secret_context_is_echoed(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: echo "${{ secrets.API_TOKEN }}"
        """
        f = run_check(wf, "GHA-033")
        assert not f.passed

    def test_fails_on_secret_env_var_echoed_at_step_scope(self):
        # The indirect form: a step ``env:`` block resolves a secret
        # into the env, then the same step's ``run:`` echoes the env
        # var. GHA-033 traces this taint through the step boundary.
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - env:
                  API_TOKEN: ${{ secrets.API_TOKEN }}
                run: echo "$API_TOKEN"
        """
        f = run_check(wf, "GHA-033")
        assert not f.passed

    def test_passes_when_secret_used_inline_only(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: 'curl --header "Authorization: Bearer ${{ secrets.API_TOKEN }}" https://api.example.com/'
        """
        f = run_check(wf, "GHA-033")
        assert f.passed

    def test_passes_when_no_secret_referenced(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: make test
        """
        f = run_check(wf, "GHA-033")
        assert f.passed


# ── GHA-037 actions/checkout persist-credentials ────────────────────


class TestGHA037PersistCredentials:
    def test_fails_on_default_v4_checkout(self):
        # No ``with:`` block at all means the default
        # ``persist-credentials: true`` applies.
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/checkout@v4
              - run: make test
        """
        f = run_check(wf, "GHA-037")
        assert not f.passed
        assert "default" in f.description.lower()

    def test_fails_on_explicit_persist_true(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/checkout@v4
                with:
                  persist-credentials: true
              - run: make test
        """
        f = run_check(wf, "GHA-037")
        assert not f.passed
        assert "persist-credentials: true" in f.description

    def test_passes_when_persist_credentials_false(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/checkout@v4
                with:
                  persist-credentials: false
              - run: make test
        """
        f = run_check(wf, "GHA-037")
        assert f.passed

    def test_passes_when_no_checkout_step(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: echo hello
        """
        f = run_check(wf, "GHA-037")
        assert f.passed

    def test_fires_per_unsafe_step_on_multi_job_workflow(self):
        # Two jobs, each with an unsafe checkout. Both surface in
        # the description (or at least the count is 2).
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          a:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/checkout@v4
              - run: make a
          b:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/checkout@v4
                with:
                  persist-credentials: true
              - run: make b
        """
        f = run_check(wf, "GHA-037")
        assert not f.passed
        assert "2 actions/checkout step(s)" in f.description


# ── GHA-038 ACTIONS_ALLOW_UNSECURE_COMMANDS ─────────────────────────


class TestGHA038AllowUnsecureCommands:
    def test_passes_when_flag_absent(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: make test
        """
        f = run_check(wf, "GHA-038")
        assert f.passed

    def test_fails_at_workflow_env(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        env:
          ACTIONS_ALLOW_UNSECURE_COMMANDS: "true"
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: make test
        """
        f = run_check(wf, "GHA-038")
        assert not f.passed
        assert "workflow.env" in f.description

    def test_fails_at_job_env(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            env:
              ACTIONS_ALLOW_UNSECURE_COMMANDS: "true"
            steps:
              - run: make test
        """
        f = run_check(wf, "GHA-038")
        assert not f.passed
        assert "jobs.build.env" in f.description

    def test_fails_at_step_env(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - name: legacy install
                env:
                  ACTIONS_ALLOW_UNSECURE_COMMANDS: "true"
                run: legacy-installer.sh
        """
        f = run_check(wf, "GHA-038")
        assert not f.passed
        assert "legacy install" in f.description

    def test_fails_on_native_yaml_true(self):
        # YAML loaders sometimes preserve ``true`` as a real bool;
        # the rule normalises both forms.
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        env:
          ACTIONS_ALLOW_UNSECURE_COMMANDS: true
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-038")
        assert not f.passed

    def test_passes_when_flag_set_to_false_string(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        env:
          ACTIONS_ALLOW_UNSECURE_COMMANDS: "false"
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-038")
        assert f.passed
