"""DF-021, ``RUN pip install`` disables TLS / pulls from an HTTP index."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Dockerfile, run_bodies

RULE = Rule(
    id="DF-021",
    title="RUN pip install bypasses TLS or uses an HTTP index",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-319",),
    recommendation=(
        "Drop ``--trusted-host`` and switch any ``-i`` / ``--index-"
        "url`` / ``--extra-index-url`` to ``https://``. If the "
        "internal index has a self-signed certificate, install the "
        "CA into the image's truststore (``ca-certificates`` + "
        "``update-ca-certificates``) instead of telling pip to skip "
        "verification. ``--trusted-host`` whitelists the host across "
        "the entire pip invocation, so a single ``RUN`` line ends up "
        "fetching every dependency over an unverified connection."
    ),
    docs_note=(
        "Three shapes are detected: ``pip install --trusted-host "
        "<host>``, ``pip install -i http://...`` (or ``--index-url "
        "http://...``), and ``pip install --extra-index-url "
        "http://...``. All three tell pip to accept whatever the "
        "upstream returns without certificate verification. The "
        "result is a build-time supply-chain MITM surface: anyone "
        "able to inject responses on the network path between the "
        "build host and the index can ship arbitrary wheels into the "
        "image. Complements the generic TLS-bypass primitive (which "
        "catches ``pip config set global.trusted-host``) by covering "
        "the per-invocation flag form most teams actually reach for."
    ),
    known_fp=(
        "An internal index served over plain HTTP on a private "
        "network (no internet path) is the typical justification for "
        "the flag. Fix the index (terminate TLS at a reverse proxy, "
        "or install the internal CA into the image) rather than "
        "leaving the bypass in the Dockerfile.",
    ),
    exploit_example=(
        "# Vulnerable: pip resolves and downloads packages over\n"
        "# plaintext HTTP, so any network attacker between the\n"
        "# build and the registry can substitute a wheel. The\n"
        "# ``--trusted-host`` flag silences pip's hash\n"
        "# verification for the named host too.\n"
        "FROM python@sha256:abc123...\n"
        "RUN pip install \\\n"
        "      --index-url http://internal-pypi.example.com/simple \\\n"
        "      --trusted-host internal-pypi.example.com \\\n"
        "      -r requirements.txt\n"
        "\n"
        "# Safe: HTTPS with the index's certificate validated.\n"
        "# Internal CA installed into the image's trust store;\n"
        "# ``--require-hashes`` enforces hash pinning.\n"
        "FROM python@sha256:abc123...\n"
        "COPY ci/internal-ca.crt /usr/local/share/ca-certificates/\n"
        "RUN update-ca-certificates && \\\n"
        "    pip install \\\n"
        "      --index-url https://internal-pypi.example.com/simple \\\n"
        "      --require-hashes -r requirements.txt"
    ),
)

# ``pip install`` may be invoked as ``pip``, ``pip3``, ``python -m pip``, or
# ``python3 -m pip``. The detector is anchored on ``install`` to keep
# unrelated pip commands (``pip list``) from matching.
_PIP_INSTALL_RE = re.compile(
    r"\b(?:python\d*\s+-m\s+pip|pip\d*)\s+install\b",
    re.IGNORECASE,
)
_TRUSTED_HOST_RE = re.compile(r"--trusted-host\b", re.IGNORECASE)
_HTTP_INDEX_RE = re.compile(
    r"(?:-i|--index-url|--extra-index-url)(?:\s+|=)http://",
    re.IGNORECASE,
)


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for line_no, body in run_bodies(df):
        if not _PIP_INSTALL_RE.search(body):
            continue
        reasons: list[str] = []
        if _TRUSTED_HOST_RE.search(body):
            reasons.append("--trusted-host")
        if _HTTP_INDEX_RE.search(body):
            reasons.append("http:// index URL")
        if not reasons:
            continue
        offenders.append(f"L{line_no}: {', '.join(reasons)}")
        locations.append(Location(
            path=df.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "No ``RUN pip install`` invocation bypasses TLS verification."
        if passed else
        f"{len(offenders)} ``RUN pip install`` invocation(s) bypass "
        f"TLS: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. An attacker who can "
        f"inject responses on the build host's network path ships "
        f"wheels straight into the image."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
