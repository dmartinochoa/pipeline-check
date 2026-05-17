"""Per-rule tests for GHA-051..055 — advanced PPE / credential-leak surface.

GHA-051 (services / container image unpinned),
GHA-052 (actions/cache key derived from untrusted PR input),
GHA-053 (if: predicate evaluates untrusted context),
GHA-054 (actions/checkout with ssh-key + persist-credentials),
GHA-055 (reusable workflow outputs reference a secret).
"""

from .conftest import run_check

# ── GHA-051: services / container image unpinned ────────────────────


class TestGHA051:
    def test_fails_on_tag_only_service(self):
        wf = """
        name: ci
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            services:
              db:
                image: postgres:16
            steps:
              - run: pg_isready
        """
        f = run_check(wf, "GHA-051")
        assert not f.passed
        assert "postgres:16" in f.description

    def test_fails_on_latest_service(self):
        wf = """
        name: ci
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            services:
              cache:
                image: redis:latest
            steps:
              - run: redis-cli ping
        """
        f = run_check(wf, "GHA-051")
        assert not f.passed

    def test_fails_on_unpinned_container(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            container:
              image: mcr.microsoft.com/dotnet/sdk:8.0
            steps:
              - run: dotnet --version
        """
        f = run_check(wf, "GHA-051")
        assert not f.passed
        assert "container" in f.description

    def test_passes_on_pinned_digest(self):
        # 64-hex sha256 digest.
        sha = "0" * 64
        wf = f"""
        name: ci
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            services:
              db:
                image: postgres:16@sha256:{sha}
            steps:
              - run: pg_isready
        """
        f = run_check(wf, "GHA-051")
        assert f.passed

    def test_passes_with_no_services(self):
        wf = """
        name: ci
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo hi
        """
        f = run_check(wf, "GHA-051")
        assert f.passed


# ── GHA-052: actions/cache key untrusted ────────────────────────────


class TestGHA052:
    def test_fails_on_head_ref_in_key(self):
        wf = """
        name: ci
        on: pull_request
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  path: ~/.cache/foo
                  key: ${{ github.head_ref }}-${{ hashFiles('**/Cargo.lock') }}
        """
        f = run_check(wf, "GHA-052")
        assert not f.passed
        assert "github.head_ref" in f.description

    def test_fails_on_pull_request_title(self):
        wf = """
        name: ci
        on: pull_request
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  path: ~/.cache/foo
                  key: ${{ github.event.pull_request.title }}
        """
        f = run_check(wf, "GHA-052")
        assert not f.passed

    def test_fails_on_restore_keys_with_head_ref(self):
        wf = """
        name: ci
        on: pull_request
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  path: ~/.cache/foo
                  key: safe-${{ hashFiles('**/Cargo.lock') }}
                  restore-keys: |
                    safe-${{ github.head_ref }}
                    safe-
        """
        f = run_check(wf, "GHA-052")
        assert not f.passed

    def test_passes_on_hashfiles_only(self):
        wf = """
        name: ci
        on: pull_request
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  path: ~/.cache/foo
                  key: ${{ runner.os }}-${{ hashFiles('**/Cargo.lock') }}
        """
        f = run_check(wf, "GHA-052")
        assert f.passed

    def test_passes_when_no_cache_step(self):
        wf = """
        name: ci
        on: pull_request
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """
        f = run_check(wf, "GHA-052")
        assert f.passed


# ── GHA-053: if predicate untrusted context ─────────────────────────


class TestGHA053:
    def test_fails_on_head_commit_message(self):
        wf = """
        name: ci
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            if: contains(github.event.head_commit.message, '[release]')
            steps:
              - run: echo releasing
        """
        f = run_check(wf, "GHA-053")
        assert not f.passed
        assert "head_commit.message" in f.description

    def test_fails_on_pr_title(self):
        wf = """
        name: ci
        on: pull_request
        jobs:
          gate:
            runs-on: ubuntu-latest
            steps:
              - if: contains(github.event.pull_request.title, 'feature')
                run: echo do feature thing
        """
        f = run_check(wf, "GHA-053")
        assert not f.passed
        assert "pull_request.title" in f.description

    def test_fails_on_issue_comment_body(self):
        wf = """
        name: ci
        on: issue_comment
        jobs:
          bot:
            runs-on: ubuntu-latest
            if: startsWith(github.event.comment.body, '/build')
            steps:
              - run: echo build
        """
        f = run_check(wf, "GHA-053")
        assert not f.passed

    def test_passes_on_safe_context(self):
        wf = """
        name: ci
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            if: github.ref == 'refs/heads/main' && github.actor != 'dependabot[bot]'
            steps:
              - run: echo go
        """
        f = run_check(wf, "GHA-053")
        assert f.passed

    def test_passes_when_no_if(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo build
        """
        f = run_check(wf, "GHA-053")
        assert f.passed


# ── GHA-054: checkout ssh-key persist-credentials ───────────────────


class TestGHA054:
    def test_fails_on_ssh_key_default_persist(self):
        wf = """
        name: ci
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ssh-key: ${{ secrets.DEPLOY_KEY }}
              - run: ./build.sh
        """
        f = run_check(wf, "GHA-054")
        assert not f.passed

    def test_passes_with_persist_false(self):
        wf = """
        name: ci
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ssh-key: ${{ secrets.DEPLOY_KEY }}
                  persist-credentials: false
              - run: ./build.sh
        """
        f = run_check(wf, "GHA-054")
        assert f.passed

    def test_passes_with_persist_false_string(self):
        # YAML loaders sometimes preserve string-valued false.
        wf = """
        name: ci
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ssh-key: ${{ secrets.DEPLOY_KEY }}
                  persist-credentials: 'false'
        """
        f = run_check(wf, "GHA-054")
        assert f.passed

    def test_passes_when_no_ssh_key(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: ./build.sh
        """
        f = run_check(wf, "GHA-054")
        assert f.passed

    def test_passes_on_non_checkout_action(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/setup-node@v4
                with:
                  ssh-key: ${{ secrets.X }}
        """
        f = run_check(wf, "GHA-054")
        assert f.passed


# ── GHA-055: reusable workflow outputs secret leak ──────────────────


class TestGHA055:
    def test_fails_on_direct_secret_in_output(self):
        wf = """
        name: reusable
        on:
          workflow_call:
            outputs:
              api_token:
                description: a token
                value: ${{ secrets.API_TOKEN }}
        jobs:
          dummy:
            runs-on: ubuntu-latest
            steps:
              - run: echo hi
        """
        f = run_check(wf, "GHA-055")
        assert not f.passed
        assert "secrets.API_TOKEN" in f.description

    def test_fails_on_concatenated_secret(self):
        wf = """
        name: reusable
        on:
          workflow_call:
            outputs:
              creds_blob:
                value: "prefix-${{ secrets.SECRET_VALUE }}-suffix"
        jobs:
          dummy:
            runs-on: ubuntu-latest
            steps:
              - run: echo hi
        """
        f = run_check(wf, "GHA-055")
        assert not f.passed

    def test_passes_on_safe_output(self):
        wf = """
        name: reusable
        on:
          workflow_call:
            outputs:
              build_id:
                value: ${{ jobs.build.outputs.id }}
        jobs:
          build:
            runs-on: ubuntu-latest
            outputs:
              id: 42
            steps:
              - id: gen
                run: echo "id=42" >> $GITHUB_OUTPUT
        """
        f = run_check(wf, "GHA-055")
        assert f.passed

    def test_passes_when_not_reusable(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo hi
        """
        f = run_check(wf, "GHA-055")
        assert f.passed
        assert (
            "not a reusable workflow" in f.description
            or "does not declare" in f.description
        )

    def test_passes_when_no_outputs_declared(self):
        wf = """
        name: reusable
        on:
          workflow_call: {}
        jobs:
          dummy:
            runs-on: ubuntu-latest
            steps:
              - run: echo hi
        """
        f = run_check(wf, "GHA-055")
        assert f.passed
