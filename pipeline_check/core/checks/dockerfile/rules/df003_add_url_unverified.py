"""DF-003, ``ADD <url>`` pulls remote content without integrity verification."""
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
        "artifact in a builder stage and ``COPY`` it across. That "
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
    known_fp=(
        "``ADD`` of an internal URL served from an immutable, "
        "build-time-frozen object store (a private artifact "
        "registry under your control, GCS with object-versioning "
        "and uniform bucket-level access) is materially less "
        "risky than a public-internet fetch, but the rule still "
        "fires because no on-line check can distinguish trusted "
        "from untrusted hosts. Prefer the explicit "
        "``--checksum=sha256:<hex>`` form (BuildKit native, "
        "doesn't trigger) or move to a ``COPY`` from a builder "
        "stage; suppress per-Dockerfile if the deployment target "
        "guarantees the URL host can't be substituted.",
    ),
    exploit_example=(
        "# Vulnerable: ``ADD <url>`` pulls a remote blob into the\n"
        "# image at build time with no integrity check. A MITM\n"
        "# (compromised proxy, BGP hijack on the mirror) or a\n"
        "# host compromise substitutes the file; the build commits\n"
        "# the substituted bytes into a layer.\n"
        "FROM ubuntu@sha256:abc123...\n"
        "ADD https://internal-mirror.example.com/installer.tar.gz /tmp/\n"
        "RUN tar -xzf /tmp/installer.tar.gz && /tmp/install.sh\n"
        "\n"
        "# Safe: ``RUN curl`` to a tempfile, ``sha256sum -c`` against\n"
        "# a known-good digest, then extract / execute. The verify\n"
        "# step fails loud if the bytes don't match.\n"
        "FROM ubuntu@sha256:abc123...\n"
        "RUN curl -fsSL https://internal-mirror.example.com/installer.tar.gz \\\n"
        "      -o /tmp/installer.tar.gz \\\n"
        "    && echo 'a1b2c3d4...  /tmp/installer.tar.gz' | sha256sum -c - \\\n"
        "    && tar -xzf /tmp/installer.tar.gz \\\n"
        "    && /tmp/install.sh \\\n"
        "    && rm /tmp/installer.tar.gz"
    ),
)

_URL_RE = re.compile(r"\bhttps?://\S+", re.IGNORECASE)
# An ADD line that looks like ``ADD --checksum=sha256:<hex> URL DEST``
# is OK, the ``--checksum`` flag is BuildKit's native integrity check.
_CHECKSUM_FLAG_RE = re.compile(
    r"--checksum\s*=\s*sha256:[0-9a-f]{64}", re.IGNORECASE,
)


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
