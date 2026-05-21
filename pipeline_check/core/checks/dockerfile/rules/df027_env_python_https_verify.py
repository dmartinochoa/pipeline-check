"""DF-027, ``ENV PYTHONHTTPSVERIFY=0`` (Python TLS verify off)."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, env_pairs

RULE = Rule(
    id="DF-027",
    title="ENV disables Python HTTPS certificate verification",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-D-RUNTIME-HARDENING", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-295", "CWE-319"),
    recommendation=(
        "Remove the ``ENV PYTHONHTTPSVERIFY=0`` instruction. "
        "The variable tells Python's stdlib ``urllib`` and any "
        "library that delegates to it (most of them) to accept "
        "any TLS certificate. The bypass applies to every "
        "subsequent process — ``pip install``, runtime API "
        "calls, postinstall scripts — for the rest of the "
        "image's life. The same primitive in flag form (``pip "
        "install --trusted-host``) is DF-021's surface; "
        "DF-027 catches the env-var form that affects every "
        "Python invocation, not just pip.\n\n"
        "If the internal index has a self-signed cert, install "
        "the CA into the image's truststore (``REQUESTS_CA_BUNDLE`` "
        "pointing at a real CA bundle, or "
        "``update-ca-certificates`` for the system bundle) "
        "rather than blanket-disabling verification."
    ),
    docs_note=(
        "Fires on ``ENV PYTHONHTTPSVERIFY=0`` (also the "
        "stringy ``\"0\"``). The variable is the documented "
        "Python mechanism for disabling stdlib HTTPS "
        "verification; once set in the image ENV, every "
        "``urllib``-based TLS connection (and the libraries "
        "that delegate to it) accept any certificate.\n\n"
        "Complements DF-021 (``pip install`` TLS bypass via "
        "flags) and DF-026 (Node TLS bypass via env). "
        "Together the three cover the same primitive shape "
        "across pip-flag, Node-env, and Python-env surfaces."
    ),
    exploit_example=(
        "# Vulnerable: ``ENV PYTHONHTTPSVERIFY=0`` disables TLS\n"
        "# verification for every Python process in the\n"
        "# container. pip, requests-via-urllib3, every API call\n"
        "# now ignores certificate validity.\n"
        "FROM python@sha256:abc123...\n"
        "ENV PYTHONHTTPSVERIFY=0\n"
        "COPY . /app\n"
        "WORKDIR /app\n"
        "CMD [\"python\", \"main.py\"]\n"
        "\n"
        "# Safe: install the missing CA, keep PYTHONHTTPSVERIFY\n"
        "# at the safe default. Python's ``ssl`` module reads\n"
        "# from the system CA store.\n"
        "FROM python@sha256:abc123...\n"
        "COPY ci/internal-ca.crt /usr/local/share/ca-certificates/\n"
        "RUN update-ca-certificates\n"
        "COPY . /app\n"
        "WORKDIR /app\n"
        "CMD [\"python\", \"main.py\"]"
    ),
)


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    for line_no, key, value in env_pairs(df):
        if key != "PYTHONHTTPSVERIFY":
            continue
        stripped = value.strip() if isinstance(value, str) else ""
        if stripped != "0":
            continue
        offenders.append(f"L{line_no}: ENV {key}={value}")
    passed = not offenders
    desc = (
        "No ``ENV`` directive disables Python HTTPS verification."
        if passed else
        f"{len(offenders)} ``ENV`` directive(s) disable Python "
        f"HTTPS verification: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Every Python "
        f"process the image launches accepts any certificate "
        f"the upstream presents."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
