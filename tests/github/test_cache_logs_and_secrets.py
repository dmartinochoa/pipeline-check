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

    def test_ecr_anchors_scoped_to_offending_job_only(self):
        # Job A has the poisonable cache step; Job B (unrelated)
        # pushes to a different ECR repo. ECR anchors must come
        # only from Job A's sub-tree so AC-017 doesn't compose the
        # cache primitive in A with a push from B that has no
        # dataflow relationship to it.
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
              - run: docker push 111111111111.dkr.ecr.us-east-1.amazonaws.com/build:latest
          deploy:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: docker push 222222222222.dkr.ecr.us-east-1.amazonaws.com/prod:latest
        """
        f = run_check(wf, "GHA-011")
        assert not f.passed
        identities = {a.identity for a in f.resource_anchors}
        # Build job's ECR repo is present (same job as the
        # offending cache step); deploy job's repo is excluded.
        assert "111111111111.dkr.ecr.us-east-1.amazonaws.com/build" in identities
        assert "222222222222.dkr.ecr.us-east-1.amazonaws.com/prod" not in identities


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

    def test_fails_on_secret_env_var_echoed_at_job_scope(self):
        # The secret is bound at JOB scope (the more common placement)
        # and echoed from a step. Job/workflow env inherits into the
        # step, so the leak must fire (A6 FN: only step env was scanned).
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            env:
              TOKEN: ${{ secrets.DEPLOY_KEY }}
            steps:
              - run: |
                  set -x
                  curl -H "Authorization: Bearer $TOKEN" https://api.example.com/
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

    def test_fails_on_set_x_with_secret_env_var(self):
        # Body lifted from cicd-goat scenario 27. ``set -x`` enables
        # shell trace, so any later line that expands $API_KEY (curl
        # URL, ${VAR:0:8} substring, $(... $VAR ...) command sub) ends
        # up in the build log with the secret value visible.
        wf = """
        name: scenario-27-secret-leak-in-logs
        on:
          push:
            branches: [main]
        permissions:
          contents: read
        jobs:
          deploy:
            if: false
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - name: Deploy
                env:
                  API_KEY: ${{ secrets.API_KEY }}
                run: |
                  set -x
                  curl -fsS "https://api.example.com/deploy?key=${API_KEY}"
                  partial="${API_KEY:0:8}"
                  echo "deploying with key prefix ${partial}..."
        """
        f = run_check(wf, "GHA-033")
        assert not f.passed
        assert "set -x" in f.description or "deploy" in f.description

    def test_fails_on_set_o_xtrace_long_form(self):
        wf = """
        name: ci
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TOKEN: ${{ secrets.TOKEN }}
                run: |
                  set -o xtrace
                  curl -H "Authorization: Bearer $TOKEN" https://api.example.com
        """
        f = run_check(wf, "GHA-033")
        assert not f.passed

    def test_fails_on_set_euxo_pipefail_bundle(self):
        # ``set -euxo pipefail`` is the idiomatic strict-mode prelude;
        # the embedded ``x`` flag still enables shell tracing.
        wf = """
        name: ci
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TOKEN: ${{ secrets.TOKEN }}
                run: |
                  set -euxo pipefail
                  curl -H "Authorization: Bearer $TOKEN" https://api.example.com
        """
        f = run_check(wf, "GHA-033")
        assert not f.passed

    def test_passes_on_set_x_without_secret_env_var(self):
        # set -x is fine if no secret-bound env is in scope. The
        # rule is about secret leakage, not shell hygiene.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  set -x
                  make test
        """
        f = run_check(wf, "GHA-033")
        assert f.passed

    def test_passes_on_curl_with_secret_header_no_shell_trace(self):
        # Carve-out: an inline ``secrets.*`` interpolation in a curl
        # ``-H`` header without ``set -x`` does NOT fire — curl
        # doesn't echo its arguments to stdout, so the value lands on
        # the network but not in the workflow log.
        wf = """
        name: ci
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TOKEN: ${{ secrets.TOKEN }}
                run: |
                  curl -H "Authorization: Bearer $TOKEN" https://api.example.com
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
