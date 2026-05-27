"""Per-rule tests for GitHub Actions runtime-hardening rules:
GHA-008 (literal secrets), GHA-012 (self-hosted ephemeral marker),
GHA-014 (deploy job environment), GHA-015 (timeout-minutes),
GHA-016 (curl-pipe), GHA-019 (token persistence), GHA-023 (TLS bypass).

Complements the existing ``test_workflows.py`` (GHA-001..GHA-005) by
covering the runtime-hardening half of the GitHub catalog. Each rule
gets a positive case (compliant), at least one negative case (triggers
finding), and an edge case where applicable.
"""
from __future__ import annotations

from .conftest import run_check

# ── GHA-008 literal secrets ─────────────────────────────────────────


class TestGHA008LiteralSecrets:
    def test_fails_on_aws_access_key_in_env(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            env:
              AWS_ACCESS_KEY_ID: AKIAZ3MHALF2TESTHIJK
            steps: [{run: 'aws s3 ls'}]
        """
        f = run_check(wf, "GHA-008")
        assert not f.passed

    def test_fails_on_github_token_literal(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            env:
              GH_TOKEN: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            steps: [{run: 'gh release view'}]
        """
        f = run_check(wf, "GHA-008")
        assert not f.passed

    def test_fails_on_cicd_goat_scenario_15_body(self):
        # 40-char lowercase-hex token in a credential-named env value.
        # The deterministic catalog had a gap on bare hex shapes
        # before the keyed-hex pass landed in ``_secrets.py``.
        wf = """
        name: scenario-15-hardcoded-secret-env
        on:
          push:
            branches: [main]
        permissions:
          contents: read
        env:
          LEGACY_API_TOKEN: "deadbeefcafef00dfeedfacebadc0ffee0ddf00d"
          DB_PASSWORD: "P@ssw0rd-do-not-actually-do-this"
        jobs:
          build:
            if: false
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: |
                  curl -H "Authorization: Bearer $LEGACY_API_TOKEN" https://api.example.com/build
        """
        f = run_check(wf, "GHA-008")
        assert not f.passed
        assert "hex40_keyed" in f.description

    def test_passes_when_secrets_referenced_via_secrets_context(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            env:
              AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
            steps: [{run: 'aws s3 ls'}]
        """
        f = run_check(wf, "GHA-008")
        assert f.passed


# ── GHA-015 timeout-minutes ─────────────────────────────────────────


class TestGHA015TimeoutMinutes:
    def test_fails_when_job_has_no_timeout(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps: [{run: './long-build.sh'}]
        """
        f = run_check(wf, "GHA-015")
        assert not f.passed

    def test_passes_with_explicit_timeout(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps: [{run: './long-build.sh'}]
        """
        f = run_check(wf, "GHA-015")
        assert f.passed

    def test_skips_reusable_workflow_caller(self):
        # GitHub Actions does not accept ``timeout-minutes:`` on jobs
        # that call a reusable workflow (``jobs.<id>.uses:``). The
        # called workflow's own jobs declare their timeouts. GHA-015
        # must skip the caller rather than fault it for missing an
        # attribute that's structurally invalid on this shape.
        wf = """
        name: ci
        on: push
        jobs:
          provenance:
            permissions:
              id-token: write
            uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0
            with:
              base64-subjects: deadbeef
        """
        f = run_check(wf, "GHA-015")
        assert f.passed


# ── GHA-016 curl-pipe ───────────────────────────────────────────────


class TestGHA016CurlPipe:
    def test_fails_on_curl_piped_to_bash(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: curl -fsSL https://example.com/install.sh | bash
        """
        f = run_check(wf, "GHA-016")
        assert not f.passed

    def test_fails_on_wget_piped_to_sh(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: wget -O - https://example.com/install.sh | sh
        """
        f = run_check(wf, "GHA-016")
        assert not f.passed

    def test_fails_on_codecov_style_sha_verified_third_party_install(self):
        # Post-2021 contract: sha256 verification alone isn't enough
        # for third-party installers. The Codecov compromise ships
        # malicious bytes signed by the publisher's own (compromised)
        # CI. Provenance attestation is the carve-out.
        wf = """
        name: scenario-19-codecov-style-installer
        on: push
        jobs:
          upload-coverage:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: |
                  set -euo pipefail
                  curl -fLso codecov "https://uploader.coverage-provider.example/latest/linux/codecov"
                  curl -fLso codecov.sha256sum "https://uploader.coverage-provider.example/latest/linux/codecov.SHA256SUM"
                  curl -fLso codecov.sig "https://uploader.coverage-provider.example/latest/linux/codecov.SHA256SUM.sig"
                  gpg --verify codecov.sig codecov.sha256sum
                  sha256sum --check codecov.sha256sum
                  chmod +x codecov
              - run: ./codecov -t $TOK
        """
        f = run_check(wf, "GHA-016")
        assert not f.passed
        assert "Codecov" in f.description or "trusted-installer" in f.description.lower() or "provenance" in f.description.lower()

    def test_passes_with_provenance_attested_install(self):
        # Same shape as the Codecov scenario but with a SLSA
        # verifier step. Provenance attestation defeats the
        # Codecov-2021 attack (verifier checks the upstream build
        # provenance, not just the publisher's static signature).
        wf = """
        name: ci
        on: push
        jobs:
          install:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  curl -fLso codecov "https://uploader.coverage-provider.example/latest/linux/codecov"
                  slsa-verifier verify-artifact codecov \\
                    --provenance-path codecov.intoto.jsonl \\
                    --source-uri github.com/codecov/codecov
                  chmod +x codecov
              - run: ./codecov
        """
        f = run_check(wf, "GHA-016")
        assert f.passed

    def test_trusted_installer_passes_on_vendor_host(self):
        # Vendor allowlist still applies: ``get.docker.com`` is the
        # canonical idiomatic install path.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  curl -fsSL https://get.docker.com -o get-docker.sh
                  sha256sum -c get-docker.sh.sha256
                  bash get-docker.sh
        """
        f = run_check(wf, "GHA-016")
        assert f.passed

# ── GHA-019 token persistence ───────────────────────────────────────


class TestGHA019TokenPersistence:
    def test_fails_when_token_redirected_to_file(self):
        # The rule fires on patterns where GITHUB_TOKEN is appended
        # to a file via ``>>``, piped through ``tee``, or written
        # into ``$GITHUB_ENV`` / ``$GITHUB_OUTPUT`` / ``$GITHUB_STATE``.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: echo $GITHUB_TOKEN >> /tmp/token.txt
        """
        f = run_check(wf, "GHA-019")
        assert not f.passed

    def test_fails_when_token_piped_to_tee(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: echo $GITHUB_TOKEN | tee creds.txt
        """
        f = run_check(wf, "GHA-019")
        assert not f.passed

    def test_fails_when_secret_written_to_github_output(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: echo "TOKEN=$GITHUB_TOKEN" >> $GITHUB_OUTPUT
        """
        f = run_check(wf, "GHA-019")
        assert not f.passed

    def test_passes_when_token_used_inline_only(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: gh release view --token $GITHUB_TOKEN
        """
        f = run_check(wf, "GHA-019")
        assert f.passed

    def test_fails_on_cicd_goat_scenario_17_artipacked_body(self):
        # Body lifted verbatim from cicd-goat scenario 17. The
        # default-on persist-credentials writes GITHUB_TOKEN into
        # .git/config; the upload-artifact step then bundles the
        # whole workspace including .git/.
        wf = """
        name: scenario-17-artipacked-git-dir
        on:
          push:
            branches: [main]
        permissions:
          contents: read
        jobs:
          build:
            if: false
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: make build
              - name: Upload artifact for downstream jobs
                uses: actions/upload-artifact@v4
                with:
                  name: workspace
                  path: .
        """
        f = run_check(wf, "GHA-019")
        assert not f.passed
        assert "ArtiPACKED" in f.description

    def test_artipacked_passes_when_persist_credentials_false(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  persist-credentials: false
              - uses: actions/upload-artifact@v4
                with:
                  name: workspace
                  path: .
        """
        f = run_check(wf, "GHA-019")
        assert f.passed

    def test_artipacked_passes_when_upload_path_excludes_dot_git(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: actions/upload-artifact@v4
                with:
                  name: build-output
                  path: dist/
        """
        f = run_check(wf, "GHA-019")
        assert f.passed

    def test_artipacked_fires_on_explicit_git_path(self):
        # Even when path is narrower than '.', an explicit .git/
        # reference is unambiguously sketchy.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: actions/upload-artifact@v4
                with:
                  name: gitstate
                  path: .git/
        """
        f = run_check(wf, "GHA-019")
        assert not f.passed

    def test_artipacked_passes_when_upload_precedes_checkout(self):
        # An upload before any checkout has no .git/config to leak.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/upload-artifact@v4
                with:
                  name: prepopulated
                  path: .
              - uses: actions/checkout@v4
        """
        f = run_check(wf, "GHA-019")
        assert f.passed

    def test_artipacked_fires_on_workspace_token_path(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: actions/upload-artifact@v4
                with:
                  name: bundle
                  path: ${{ github.workspace }}
        """
        f = run_check(wf, "GHA-019")
        assert not f.passed


# ── GHA-023 TLS bypass ──────────────────────────────────────────────


class TestGHA023TLSBypass:
    def test_fails_on_curl_insecure_flag(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: curl -k https://internal.example.com/secret
        """
        f = run_check(wf, "GHA-023")
        assert not f.passed

    def test_fails_on_npm_strict_ssl_false(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: npm config set strict-ssl false
        """
        f = run_check(wf, "GHA-023")
        assert not f.passed

    def test_passes_when_no_tls_bypass(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: curl -fsSL https://example.com/data
        """
        f = run_check(wf, "GHA-023")
        assert f.passed


# ── GHA-012 self-hosted runner ──────────────────────────────────────


class TestGHA012SelfHostedEphemeral:
    def test_fails_when_self_hosted_lacks_ephemeral(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: [self-hosted, linux, x64]
            timeout-minutes: 30
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-012")
        assert not f.passed

    def test_passes_with_ephemeral_label(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: [self-hosted, linux, ephemeral]
            timeout-minutes: 30
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-012")
        assert f.passed

    def test_passes_on_github_hosted_runner(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-012")
        assert f.passed


# ── GHA-014 deploy job environment ──────────────────────────────────


class TestGHA014DeployEnvironment:
    def test_fails_when_deploy_job_has_no_environment(self):
        wf = """
        name: release
        on: push
        permissions: { contents: read }
        jobs:
          deploy:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: deploy.sh production
        """
        f = run_check(wf, "GHA-014")
        assert not f.passed

    def test_passes_with_explicit_environment(self):
        wf = """
        name: release
        on: push
        permissions: { contents: read }
        jobs:
          deploy:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            environment: production
            steps:
              - run: deploy.sh production
        """
        f = run_check(wf, "GHA-014")
        assert f.passed

    def test_passes_for_non_deploy_job(self):
        # Lint-only job, no deploy keyword in name. Rule shouldn't fire.
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          lint:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: ruff check .
        """
        f = run_check(wf, "GHA-014")
        assert f.passed

    def test_passes_for_localstack_terraform_apply(self):
        # Integration-test job that runs ``terraform apply`` against
        # LocalStack (AWS_ENDPOINT_URL pointed at localhost). The rule
        # must not flag it as a deploy-without-environment.
        wf = """
        name: integration
        on: workflow_dispatch
        permissions: { contents: read }
        jobs:
          terraform-fixture:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - env:
                  AWS_ACCESS_KEY_ID: test
                  AWS_SECRET_ACCESS_KEY: test
                  AWS_ENDPOINT_URL: http://localhost:4566
                run: terraform apply -auto-approve
        """
        f = run_check(wf, "GHA-014")
        assert f.passed, "terraform apply against LocalStack should not need an environment gate"

    def test_real_terraform_apply_still_flags(self):
        # Same shape as above but no localhost endpoint -> real deploy.
        wf = """
        name: deploy
        on: push
        permissions: { contents: read }
        jobs:
          provision:
            runs-on: ubuntu-latest
            steps:
              - env:
                  AWS_REGION: us-east-1
                run: terraform apply -auto-approve
        """
        f = run_check(wf, "GHA-014")
        assert not f.passed


# ── GHA-036 runs-on injection ───────────────────────────────────────


class TestGHA036RunsOnInjection:
    def test_fails_on_inputs_runner(self):
        # Reusable workflow that lets the caller pick the runner is
        # the canonical attack shape — caller can route the job onto
        # any privileged self-hosted label the org owns.
        wf = """
        name: reusable
        on:
          workflow_call:
            inputs:
              runner:
                type: string
                required: true
        jobs:
          build:
            runs-on: ${{ inputs.runner }}
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-036")
        assert not f.passed
        assert "build" in f.description

    def test_fails_on_workflow_dispatch_input(self):
        wf = """
        name: ondemand
        on:
          workflow_dispatch:
            inputs:
              target:
                type: string
        jobs:
          deploy:
            runs-on: ${{ inputs.target }}
            steps:
              - run: deploy.sh
        """
        f = run_check(wf, "GHA-036")
        assert not f.passed

    def test_fails_when_dict_form_labels_interpolated(self):
        # Long-form runs-on: { group, labels: [...] } — labels are
        # also a vector. Dict form is documented in GHA's runner
        # group docs.
        wf = """
        name: ci
        on:
          workflow_call:
            inputs:
              label:
                type: string
        jobs:
          build:
            runs-on:
              group: prod-pool
              labels:
                - self-hosted
                - ${{ inputs.label }}
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-036")
        assert not f.passed

    def test_fails_when_dict_form_group_interpolated(self):
        wf = """
        name: ci
        on:
          workflow_call:
            inputs:
              pool:
                type: string
        jobs:
          build:
            runs-on:
              group: ${{ inputs.pool }}
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-036")
        assert not f.passed

    def test_fails_on_pr_head_ref_via_pull_request_target(self):
        # Less common but exploitable: a maintainer's runs-on tied
        # to the PR head ref hands attacker-controlled branch names
        # straight to the runner-selection step.
        wf = """
        name: ci
        on: pull_request_target
        jobs:
          build:
            runs-on: ${{ github.head_ref }}
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-036")
        assert not f.passed

    def test_passes_on_string_literal(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-036")
        assert f.passed

    def test_passes_on_list_literal(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: [self-hosted, linux, x64, ephemeral]
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-036")
        assert f.passed

    def test_passes_on_matrix_runner(self):
        # ``matrix.*`` is author-controlled, not caller-controlled —
        # the matrix values live in the same workflow file. The
        # untrusted-context regex deliberately excludes ``matrix.*``.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            strategy:
              matrix:
                os: [ubuntu-latest, macos-latest]
            runs-on: ${{ matrix.os }}
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-036")
        assert f.passed

    def test_passes_on_dict_form_with_literal_labels(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on:
              group: prod-pool
              labels: [self-hosted, ephemeral]
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-036")
        assert f.passed


# ── GHA-037 actions/checkout persist-credentials ────────────────────


class TestGHA037PersistCredentials:
    def test_fails_when_checkout_omits_persist_credentials(self):
        # The v3 / v4 default for persist-credentials is true. A
        # checkout with no with: block at all hits that default.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/checkout@v4
              - run: make
        """
        f = run_check(wf, "GHA-037")
        assert not f.passed
        assert "default" in f.description

    def test_fails_when_persist_credentials_explicitly_true(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/checkout@v4
                with:
                  persist-credentials: true
              - run: make
        """
        f = run_check(wf, "GHA-037")
        assert not f.passed
        assert "persist-credentials: true" in f.description

    def test_fails_when_persist_credentials_string_true(self):
        # YAML preserves quoted "true" as a string in some loaders;
        # the rule normalizes both forms.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/checkout@v4
                with:
                  persist-credentials: "true"
              - run: make
        """
        f = run_check(wf, "GHA-037")
        assert not f.passed

    def test_fails_with_block_omits_persist_credentials_key(self):
        # A with: block exists (other inputs set) but the flag itself
        # isn't named, so the unsafe default applies.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/checkout@v4
                with:
                  fetch-depth: 0
              - run: make
        """
        f = run_check(wf, "GHA-037")
        assert not f.passed

    def test_description_names_offending_job_and_step(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - name: pull source
                uses: actions/checkout@v4
              - run: make
        """
        f = run_check(wf, "GHA-037")
        assert not f.passed
        assert "build" in f.description
        assert "pull source" in f.description

    def test_passes_when_persist_credentials_false(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/checkout@v4
                with:
                  persist-credentials: false
              - run: make
        """
        f = run_check(wf, "GHA-037")
        assert f.passed

    def test_passes_when_no_checkout_step(self):
        # Rule scope is actions/checkout only. Workflows that build
        # without a checkout (cache-only jobs, dispatch entry points)
        # shouldn't trip.
        wf = """
        name: ci
        on: push
        jobs:
          ping:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: curl -fsS https://example.com/ping
        """
        f = run_check(wf, "GHA-037")
        assert f.passed

    def test_passes_when_unrelated_action_uses_persist_credentials(self):
        # Other actions may take a similarly-named input. The rule
        # is anchored to actions/checkout@ so unrelated actions must
        # not trigger it.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: some-org/some-action@v1
                with:
                  persist-credentials: true
              - run: make
        """
        f = run_check(wf, "GHA-037")
        assert f.passed

    def test_fails_only_on_unsafe_checkout_when_other_is_safe(self):
        # Two checkouts: one safe (false), one unsafe (default). Rule
        # must flag the unsafe one and ignore the safe one.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - name: pinned checkout
                uses: actions/checkout@v4
                with:
                  persist-credentials: false
              - name: leaky checkout
                uses: actions/checkout@v4
              - run: make
        """
        f = run_check(wf, "GHA-037")
        assert not f.passed
        assert "leaky checkout" in f.description
        assert "pinned checkout" not in f.description
        assert f.description.startswith("1 actions/checkout step(s)")


# ── GHA-038 ACTIONS_ALLOW_UNSECURE_COMMANDS ─────────────────────────


class TestGHA038AllowUnsecureCommands:
    def test_fails_at_workflow_env(self):
        wf = """
        name: ci
        on: push
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
        assert "workflow.env" in f.description

    def test_fails_at_job_env(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            env:
              ACTIONS_ALLOW_UNSECURE_COMMANDS: true
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-038")
        assert not f.passed
        assert "jobs.build.env" in f.description

    def test_fails_at_step_env(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - name: legacy step
                env:
                  ACTIONS_ALLOW_UNSECURE_COMMANDS: true
                run: ./legacy-tool.sh
        """
        f = run_check(wf, "GHA-038")
        assert not f.passed
        assert "legacy step" in f.description

    def test_fails_when_value_is_string_true(self):
        wf = """
        name: ci
        on: push
        env:
          ACTIONS_ALLOW_UNSECURE_COMMANDS: "true"
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-038")
        assert not f.passed

    def test_fails_when_value_is_uppercase_true(self):
        # YAML 1.1 boolean coercion gives ``True`` for unquoted true,
        # but quoted variants like "TRUE" or "True" stay strings; the
        # rule lower-cases before comparing.
        wf = """
        name: ci
        on: push
        env:
          ACTIONS_ALLOW_UNSECURE_COMMANDS: "TRUE"
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-038")
        assert not f.passed

    def test_fails_at_multiple_scopes(self):
        wf = """
        name: ci
        on: push
        env:
          ACTIONS_ALLOW_UNSECURE_COMMANDS: true
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            env:
              ACTIONS_ALLOW_UNSECURE_COMMANDS: true
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-038")
        assert not f.passed
        assert "workflow.env" in f.description
        assert "jobs.build.env" in f.description

    def test_passes_when_flag_unset(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-038")
        assert f.passed

    def test_passes_when_flag_explicitly_false(self):
        wf = """
        name: ci
        on: push
        env:
          ACTIONS_ALLOW_UNSECURE_COMMANDS: false
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-038")
        assert f.passed

    def test_passes_when_unrelated_env_set(self):
        # An env block with other variables but not the unsafe flag
        # must not fire the rule.
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            env:
              FOO: bar
              GO111MODULE: "on"
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-038")
        assert f.passed
