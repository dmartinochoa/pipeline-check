"""COMPOSER-006. ``scripts`` hook pipes a remote download to a shell."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ComposerFile

RULE = Rule(
    id="COMPOSER-006",
    title="composer.json scripts hook pipes a remote download to a shell",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-1"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-78", "CWE-829"),
    recommendation=(
        "Stop piping ``curl`` / ``wget`` / ``Invoke-WebRequest`` "
        "output directly into a shell from a Composer lifecycle "
        "hook. Download the artifact to a temp file, verify a "
        "pinned SHA-256 / signature, then execute. Better still, "
        "move the install step out of the manifest entirely — "
        "ship the dependency as a versioned Composer package, "
        "or fetch it in a Dockerfile / CI step where the "
        "verification chain is auditable per-build."
    ),
    docs_note=(
        "Fires when any ``scripts`` entry's command body contains "
        "``curl ... | sh`` / ``wget ... | bash`` / ``curl ... | "
        "php`` style patterns. The match is conservative: it "
        "requires both a download token (``curl`` / ``wget`` / "
        "``iwr`` / ``Invoke-WebRequest`` / ``fetch``) and a pipe "
        "to an interpreter (``sh`` / ``bash`` / ``zsh`` / "
        "``php`` / ``python`` / ``node``). Patterns that "
        "download then verify with ``sha256sum -c`` are "
        "explicitly allowed by checking for a ``sha256`` token "
        "in the same command line."
    ),
    known_fp=(
        "An install hook that downloads to a temp file and then "
        "verifies via ``sha256sum --check`` is treated as "
        "safe. If the verification step is in a *separate* "
        "script entry (different array element), the rule may "
        "still trip — combine them into one line so the "
        "verification is visible.",
    ),
    incident_refs=(
        "Standard supply-chain attack vector: install scripts "
        "that fetch and run upstream code at install time give "
        "the package author RCE on every consumer's CI runner.",
    ),
    exploit_example=(
        "// Vulnerable: curl-pipe-to-sh in a post-install hook.\n"
        "{\n"
        "  \"scripts\": {\n"
        "    \"post-install-cmd\": [\n"
        "      \"curl https://example.com/install.sh | bash\"\n"
        "    ]\n"
        "  }\n"
        "}\n"
        "\n"
        "// Safe: pinned download + verify, then run.\n"
        "{\n"
        "  \"scripts\": {\n"
        "    \"post-install-cmd\": [\n"
        "      \"curl -fsSL -o install.sh "
        "https://example.com/install.sh && echo "
        "'a1b2... install.sh' | sha256sum -c && bash install.sh\"\n"
        "    ]\n"
        "  }\n"
        "}"
    ),
)


_DOWNLOAD_RE = re.compile(
    r"\b(curl|wget|fetch|iwr|Invoke-WebRequest)\b",
    re.IGNORECASE,
)
_PIPE_TO_SHELL_RE = re.compile(
    r"\|\s*(sh|bash|zsh|ash|dash|php|python(?:3)?|node|iex)\b",
    re.IGNORECASE,
)


def _has_verification(cmd: str) -> bool:
    """Allowlist commands that download and then SHA-verify."""
    low = cmd.lower()
    return any(token in low for token in (
        "sha256sum", "sha256 -c", "shasum",
        "gpg --verify", "cosign verify", "minisign -v",
    ))


def check(pom: ComposerFile) -> Finding:
    offenders: list[tuple[str, str]] = []
    locations: list[Location] = []
    for script in pom.scripts:
        for cmd in script.commands:
            if not _DOWNLOAD_RE.search(cmd):
                continue
            if not _PIPE_TO_SHELL_RE.search(cmd):
                continue
            if _has_verification(cmd):
                continue
            display = cmd if len(cmd) < 80 else cmd[:77] + "…"
            offenders.append((script.event, display))
            locations.append(Location(
                path=pom.path,
                start_line=script.line_no, end_line=script.line_no,
            ))
    passed = not offenders
    if passed:
        desc = (
            "No scripts entry pipes a remote download into an "
            "interpreter without verification."
        )
    else:
        rendered = ", ".join(
            f"{event}: {body}" for event, body in offenders[:3]
        )
        suffix = "…" if len(offenders) > 3 else ""
        desc = (
            f"{len(offenders)} scripts hook(s) pipe a remote "
            f"download into a shell: {rendered}{suffix}. "
            f"Replace with a download-then-verify pattern or "
            f"move the install out of composer.json."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
