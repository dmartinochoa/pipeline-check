"""Regression tests from the rule audit (GitHub Actions example fixes).

The 2026-06-01 audit never covered the github pack; a follow-up parse
scan found github ``exploit_example`` snippets that no YAML loader
accepts. The breakages were all the same two shapes:

  * a GitHub ``${{ ... }}`` expression inside a YAML *flow* mapping
    (``with: { ref: ${{ ... }} }``) — the ``${{`` opens a nested flow
    context the parser can't close;
  * a ``run:`` plain scalar carrying a ``: `` (``curl -H
    "Authorization: Bearer ..."``) — the colon-space reads as a
    mapping indicator.

Both fixed by switching the offending line to block style. This module
pins two contracts:

1. **Every** github rule's ``exploit_example`` parses via the
   production loader (``test_every_example_parses``), so a future
   broken snippet trips here rather than silently skipping at scan
   time.
2. For the self-contained single-workflow rules whose fix could have
   changed detection, the Vulnerable half still fires and the Safe
   half still passes (the batch-3 "strong check" shape).

The TAINT rules (TAINT-002/003/009) are taint-engine rules that need a
multi-workflow context to fire, so they are covered by the parse
contract only.
"""
from __future__ import annotations

import warnings

import pytest
import yaml

from pipeline_check.core.checks._yaml_lines import (
    safe_load_all_with_lines,
    safe_load_yaml_lines,
)
from pipeline_check.core.checks.github.rules import gha055_reusable_outputs_secret as gha055
from pipeline_check.core.checks.github.rules import gha072_overprovisioned_secrets as gha072
from pipeline_check.core.checks.github.rules import gha111_ai_iac_apply as gha111
from pipeline_check.core.checks.rule import discover_rules

from .conftest import run_check

_GH_RULES = [
    (rule.id, rule)
    for rule, _check in discover_rules("pipeline_check.core.checks.github.rules")
    if getattr(rule, "exploit_example", None)
]


def _parse_half(half: str) -> None:
    """Parse one example half the way the production loader would.

    A half that carries a ``---`` document separator (an example that
    deliberately shows two workflow files, e.g. GHA-002's split-the-
    workflow fix) is parsed as a multi-document stream; everything else
    is a single document. Duplicate top-level keys only warn, matching
    the real loader.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        if "\n---\n" in half or half.lstrip().startswith("---"):
            list(safe_load_all_with_lines(half))
        else:
            safe_load_yaml_lines(half)


@pytest.mark.parametrize("rule_id,rule", _GH_RULES, ids=[r[0] for r in _GH_RULES])
def test_every_example_parses(rule_id: str, rule) -> None:
    """No github exploit_example may contain unparseable YAML.

    Splits on the first blank line into the Vulnerable / Safe halves
    (the documented convention) and parses each. Catches the
    flow-mapping ``${{ }}`` and ``run:`` colon-space breakages the
    audit found, plus any future regression.
    """
    parts = rule.exploit_example.split("\n\n", 1)
    for half in parts:
        if half.strip():
            _parse_half(half)


class TestGha111AiIacApply:
    def test_exploit_example_strong_check(self) -> None:
        # Vulnerable half previously used ``with: { ref: ${{ ... }} }``
        # (flow mapping) which no YAML loader accepts, so the snippet
        # was silently skipped. Block style fixes it; the agent + IaC
        # apply co-located in one job must still fire.
        vuln, safe = gha111.RULE.exploit_example.split("\n\n", 1)
        assert gha111.check("wf.yml", yaml.safe_load(vuln)).passed is False
        assert gha111.check("wf.yml", yaml.safe_load(safe)).passed is True


class TestGha072OverprovisionedSecrets:
    def test_exploit_example_strong_check(self) -> None:
        # Both halves' ``run: curl -H "Authorization: Bearer ..."``
        # plain scalar carried a colon-space and failed to parse;
        # block scalars fix it. Job-level env still fires, step-level
        # env still passes.
        vuln, safe = gha072.RULE.exploit_example.split("\n\n", 1)
        assert gha072.check("wf.yml", yaml.safe_load(vuln)).passed is False
        assert gha072.check("wf.yml", yaml.safe_load(safe)).passed is True


class TestGha055ReusableOutputsSecret:
    def test_exploit_example_strong_check(self) -> None:
        # Vulnerable half's flow-sequence step
        # (``steps: [{ run: ... ${{ }} ... }]``) failed to parse; block
        # style fixes it. A reusable workflow exposing a secret through
        # ``outputs:`` must still fire; a non-secret output passes.
        vuln, safe = gha055.RULE.exploit_example.split("\n\n", 1)
        assert gha055.check("wf.yml", yaml.safe_load(vuln)).passed is False
        assert gha055.check("wf.yml", yaml.safe_load(safe)).passed is True


class TestGHA022PipUpgradeShortForm:
    """A5: ``pip install -U`` was dead code. ``DEP_UPDATE_RE`` matched a
    case-sensitive ``-U`` but the rules scan a lowercased blob (``-u``), so
    the common short form of ``--upgrade`` was never flagged. Exemptions
    for build/lint tooling must still hold."""

    def test_pip_dash_u_fires(self):
        wf = (
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: pip install -U requests\n"
        )
        assert run_check(wf, "GHA-022").passed is False

    def test_exempt_tooling_upgrade_still_passes(self):
        wf = (
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: pip install -U pip setuptools\n"
        )
        assert run_check(wf, "GHA-022").passed is True


class TestAudit202607LowGitHub:
    """2026-07 audit LOW findings on the GitHub Actions rules."""

    def test_gha087_space_negative_suffix_slice_leaks(self):
        wf = (
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - env: { TOKEN: \"${{ secrets.K }}\" }\n"
            "        run: |\n"
            "          echo \"suffix ${TOKEN: -8}\"\n"
        )
        assert run_check(wf, "GHA-087").passed is False

    def test_gha087_default_value_expansion_not_a_slice(self):
        # ``${VAR:-8}`` (no space) is default-value, not truncation.
        wf = (
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - env: { TOKEN: \"${{ secrets.K }}\" }\n"
            "        run: |\n"
            "          echo \"${TOKEN:-fallback}\"\n"
        )
        assert run_check(wf, "GHA-087").passed is True

    def test_gha093_tee_into_step_summary_is_a_sink(self):
        wf = (
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - env: { TOKEN: \"${{ secrets.K }}\" }\n"
            "        run: |\n"
            "          echo \"token=$TOKEN\" | tee -a \"$GITHUB_STEP_SUMMARY\"\n"
        )
        assert run_check(wf, "GHA-093").passed is False

    def test_gha097_graphql_enable_automerge_fires(self):
        wf = (
            "on: pull_request\n"
            "jobs:\n"
            "  u:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: peter-evans/create-pull-request@abc\n"
            "      - run: |\n"
            "          gh api graphql -f query='mutation { enablePullRequestAutoMerge(input:{}) { x } }'\n"
        )
        assert run_check(wf, "GHA-097").passed is False

    def test_gha098_scan_after_deploy_does_not_gate(self):
        after = (
            "on: push\n"
            "jobs:\n"
            "  deploy:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: kubectl apply -f k8s/\n"
            "      - run: trivy image app:latest\n"
        )
        assert run_check(after, "GHA-098").passed is False
        before = (
            "on: push\n"
            "jobs:\n"
            "  deploy:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: trivy image app:latest\n"
            "      - run: kubectl apply -f k8s/\n"
        )
        assert run_check(before, "GHA-098").passed is True


class TestAudit202607LowGitHubC5:
    """2026-07 audit LOW findings (github_c5 chunk)."""

    def test_gha060_no_deps_local_editable_not_flagged(self):
        wf = (
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: pip install --no-deps -e .\n"
        )
        assert run_check(wf, "GHA-060").passed is True

    def test_gha063_non_bot_actor_gate_not_flagged(self):
        non_bot = (
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    if: contains(github.actor, 'preview')\n"
            "    runs-on: ubuntu-latest\n"
            "    steps: [{run: echo hi}]\n"
        )
        assert run_check(non_bot, "GHA-063").passed is True
        bot = (
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    if: contains(github.actor, 'dependabot[bot]')\n"
            "    runs-on: ubuntu-latest\n"
            "    steps: [{run: echo hi}]\n"
        )
        assert run_check(bot, "GHA-063").passed is False

    def test_gha065_zero_width_in_key_fires(self):
        zw_key = "PATH​EXTRA"
        wf = (
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    env:\n"
            f"      {zw_key}: /opt/bin\n"
            "    steps: [{run: echo hi}]\n"
        )
        assert run_check(wf, "GHA-065").passed is False

    def test_gha069_release_drafter_is_not_an_oidc_consumer(self):
        wf = (
            "on: push\n"
            "jobs:\n"
            "  d:\n"
            "    runs-on: ubuntu-latest\n"
            "    permissions: { id-token: write }\n"
            "    steps:\n"
            "      - uses: release-drafter/release-drafter@v6\n"
        )
        assert run_check(wf, "GHA-069").passed is False


class TestAudit202607Gha062Matches:
    """GHA-062 now reads the ``matches`` WIF predicate, not just startsWith."""

    def _labels(self, condition):
        import os
        import tempfile

        from pipeline_check.core.checks.github.rules.gha062_oidc_iac_subject import (  # noqa: E501
            _tf_wif_findings,
        )
        body = (
            'resource "google_iam_workload_identity_pool_provider" "p" {\n'
            f'  attribute_condition = "{condition}"\n'
            "}\n"
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".tf", delete=False, encoding="utf-8",
        ) as f:
            f.write(body)
            path = f.name
        try:
            return _tf_wif_findings(path)
        finally:
            os.unlink(path)

    def test_org_broad_matches_is_flagged(self):
        assert self._labels("attribute.repository.matches('myorg/.*')")

    def test_specific_repo_matches_not_flagged(self):
        assert not self._labels("attribute.repository.matches('myorg/myrepo$')")


class TestAudit202607LowGitHubC3:
    """2026-07 audit LOW findings (github_c3 chunk)."""

    def test_gha035_case_variant_github_script_fires(self):
        wf = (
            "on: pull_request\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: Actions/github-script@v7\n"
            "        with:\n"
            "          script: |\n"
            "            console.log(`${{ github.event.pull_request.title }}`)\n"
        )
        assert run_check(wf, "GHA-035").passed is False

    def test_gha044_yarn_named_scripts_not_flagged(self):
        def _run(cmd):
            wf = (
                "on: pull_request_target\n"
                "jobs:\n"
                "  b:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                f"      - run: {cmd}\n"
            )
            return run_check(wf, "GHA-044").passed
        assert _run("yarn lint") is True
        assert _run("yarn --version") is True
        assert _run("yarn install") is False
        assert _run("yarn") is False

    def test_gha031_retired_command_in_comment_not_flagged(self):
        commented = (
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: |\n"
            "          # migrated from: echo \"::set-output name=x::$v\"\n"
            "          echo \"x=$v\" >> \"$GITHUB_OUTPUT\"\n"
        )
        assert run_check(commented, "GHA-031").passed is True
        live = (
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo \"::set-output name=x::$v\"\n"
        )
        assert run_check(live, "GHA-031").passed is False


class TestAudit202607LowGitHubC1:
    """2026-07 audit LOW findings on the GitHub Actions rules (github_c1)."""

    def test_gha005_scalar_with_not_read_as_oidc(self):
        # A malformed string-scalar ``with:`` must not be substring-tested
        # into a spurious "OIDC configured" pass; the AWS credential step
        # with no valid OIDC config is treated as unconfigured, and the
        # long-lived static keys elsewhere still surface.
        wf = (
            "on: push\n"
            "jobs:\n"
            "  deploy:\n"
            "    runs-on: ubuntu-latest\n"
            "    env:\n"
            "      AWS_ACCESS_KEY_ID: \"${{ secrets.AWS_ACCESS_KEY_ID }}\"\n"
            "      AWS_SECRET_ACCESS_KEY: \"${{ secrets.AWS_SECRET_ACCESS_KEY }}\"\n"
            "    steps:\n"
            "      - uses: aws-actions/configure-aws-credentials@v4\n"
            "        with: role-to-assume\n"
            "      - run: aws s3 sync . s3://bucket\n"
        )
        # The scalar ``with`` must not flip the finding to a pass; the
        # job-level secrets-sourced long-lived keys must still fire.
        assert run_check(wf, "GHA-005").passed is False


class TestAudit202607LowGitHubC7:
    """2026-07 audit LOW findings on the GitHub Actions rules (github_c7)."""

    def test_gha114_branches_ignore_plus_tags_is_unrestricted(self):
        # branches-ignore is itself a branch filter: every non-ignored
        # branch push still reaches the publish path, so combining it with
        # tags is NOT restricted.
        wf = (
            "on:\n"
            "  push:\n"
            "    branches-ignore: [main]\n"
            "    tags: ['v*']\n"
            "permissions: { id-token: write }\n"
            "jobs:\n"
            "  publish:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: npm publish\n"
        )
        assert run_check(wf, "GHA-114").passed is False
        # tags-only (no branches / no branches-ignore) stays restricted.
        restricted = (
            "on:\n"
            "  push:\n"
            "    tags: ['v*']\n"
            "permissions: { id-token: write }\n"
            "jobs:\n"
            "  publish:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: npm publish\n"
        )
        assert run_check(restricted, "GHA-114").passed is True

    def test_gha116_tojson_secrets_in_reusable_call_with(self):
        # A reusable-workflow call job has no steps; toJSON(secrets) passed
        # through its job-level with:/secrets: must still be detected.
        wf_with = (
            "on: push\n"
            "jobs:\n"
            "  call:\n"
            "    uses: org/repo/.github/workflows/sync.yml@v1\n"
            "    with:\n"
            "      payload: \"${{ toJSON(secrets) }}\"\n"
        )
        assert run_check(wf_with, "GHA-116").passed is False
        wf_secrets = (
            "on: push\n"
            "jobs:\n"
            "  call:\n"
            "    uses: org/repo/.github/workflows/sync.yml@v1\n"
            "    secrets:\n"
            "      blob: \"${{ toJSON(secrets) }}\"\n"
        )
        assert run_check(wf_secrets, "GHA-116").passed is False


class TestAudit202607LowGitHubC8:
    """2026-07 audit LOW findings on the GitHub Actions rules (github_c8)."""

    def test_gha123_agent_name_in_echo_not_an_invocation(self):
        # An agent name echoed in output must not count as an invocation.
        wf = (
            "on: push\n"
            "jobs:\n"
            "  j:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: |\n"
            "          echo 'ask claude to review'\n"
            "          make build\n"
            "      - uses: ad-m/github-push-action@master\n"
        )
        assert run_check(wf, "GHA-123").passed is True
        # a real agentic-CLI invocation + autoland still fires.
        fires = (
            "on: push\n"
            "jobs:\n"
            "  j:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: claude -p 'fix the build'\n"
            "      - uses: ad-m/github-push-action@master\n"
        )
        assert run_check(fires, "GHA-123").passed is False

    def test_gha119_agent_name_in_echo_not_a_sink(self):
        # An agent name in an echoed string with an untrusted interpolation
        # is not a prompt-injection sink (no agent actually runs).
        wf = (
            "on: pull_request_target\n"
            "jobs:\n"
            "  j:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: |\n"
            "          echo 'The gemini model saw: "
            "${{ github.event.pull_request.title }}'\n"
        )
        assert run_check(wf, "GHA-119").passed is True
        # a real agent invocation ingesting untrusted context still fires.
        fires = (
            "on: pull_request_target\n"
            "jobs:\n"
            "  j:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: gemini -p "
            "'${{ github.event.pull_request.title }}'\n"
        )
        assert run_check(fires, "GHA-119").passed is False
