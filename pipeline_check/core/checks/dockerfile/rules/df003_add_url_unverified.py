"""DF-003 — ``ADD <url>`` pulls remote content without integrity verification."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, iter_instructions

RULE = Rule(
    id="DF-003",
    title="ADD pulls remote URL without integrity verification",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-9"),
    esf=("ESF-S-VERIFY-DEPS", "ESF-S-PIN-DEPS"),
    cwe=("CWE-494",),
    recommendation=(
        "Replace ``ADD https://...`` with a multi-step ``RUN``: "
        "download the file with ``curl -fsSLo``, verify a known-good "
        "checksum (``sha256sum -c``) or signature (``cosign verify-"
        "blob``), then extract / install. Better still: download the "
        "artifact in a builder stage and ``COPY`` it across — that "
        "way the verifier runs once at build time, not per-pull."
    ),
    docs_note=(
        "``ADD`` with a URL is the historical Dockerfile footgun: it "
        "fetches at *build* time over HTTP(S) with no checksum and no "
        "signature, and the registry tag does not pin the source. A "
        "tampered server or DNS hijack silently swaps the content. "
        "``COPY`` is for local files; ``RUN curl + verify`` is for "
        "remote ones."
    ),
)

_URL_RE = re.compile(r"\bhttps?://\S+", re.IGNORECASE)
# An ADD line that looks like ``ADD --checksum=sha256:<hex> URL DEST``
# is OK — the ``--checksum`` flag is BuildKit's native integrity check.
_CHECKSUM_FLAG_RE = re.compile(r"--checksum\s*=\s*sha256:[0-9a-f]{64}")


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    for ins in iter_instructions(df, directive="ADD"):
        urls = _URL_RE.findall(ins.args)
        if not urls:
            continue
        if _CHECKSUM_FLAG_RE.search(ins.args):
            continue
        offenders.append(f"L{ins.line_no}: {urls[0]}")
    passed = not offenders
    desc = (
        "No ``ADD <url>`` directives without a ``--checksum=sha256:...`` flag."
        if passed else
        f"{len(offenders)} ``ADD`` directive(s) pull remote URLs without "
        f"integrity verification: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
