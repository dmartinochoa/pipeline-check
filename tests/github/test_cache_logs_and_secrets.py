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


# ── GHA-039 services / container credentials literal ────────────────


class TestGHA039ContainerCredentials:
    def test_passes_with_secret_reference(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            container:
              image: internal/build:1.2.3
              credentials:
                username: ${{ secrets.REGISTRY_USERNAME }}
                password: ${{ secrets.REGISTRY_PASSWORD }}
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-039")
        assert f.passed

    def test_fails_on_literal_container_password(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            container:
              image: internal/build:1.2.3
              credentials:
                username: ci-bot
                password: hunter2-rotate-me
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-039")
        assert not f.passed
        assert "container.credentials.username" in f.description
        assert "container.credentials.password" in f.description

    def test_fails_on_literal_service_password(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            services:
              postgres:
                image: postgres:14
                credentials:
                  username: postgres
                  password: literal-postgres-pw
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-039")
        assert not f.passed
        assert "services.postgres.credentials.password" in f.description

    def test_passes_on_anonymous_username(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            container:
              image: public.ecr.aws/x/y:1.0
              credentials:
                username: anonymous
                password: ""
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-039")
        assert f.passed

    def test_passes_with_inline_secret_reference_template(self):
        # ``prefix-${{ secrets.X }}`` shape is occasionally used so
        # the runner can pull from a tenant-scoped registry path;
        # the secret bytes still resolve at runtime.
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            services:
              cache:
                image: internal/cache:7
                credentials:
                  username: tenant-${{ secrets.TENANT_USERNAME }}
                  password: ${{ secrets.TENANT_PASSWORD }}
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-039")
        assert f.passed

    def test_passes_when_no_credentials_block(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            container:
              image: alpine:3
            services:
              redis:
                image: redis:7
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-039")
        assert f.passed

    def test_fails_on_non_string_password(self):
        # YAML loaders sometimes yield ``true`` / numbers when the
        # field was ``password: true`` (config bug); rule treats
        # this as unsafe to force a fix.
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            container:
              image: x/y:1
              credentials:
                username: bot
                password: 12345
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-039")
        assert not f.passed
