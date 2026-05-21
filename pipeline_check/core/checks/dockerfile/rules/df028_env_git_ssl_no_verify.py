"""DF-028, ``ENV GIT_SSL_NO_VERIFY`` (Git TLS bypass)."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, env_pairs

RULE = Rule(
    id="DF-028",
    title="ENV disables Git TLS certificate verification",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-D-RUNTIME-HARDENING", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-295", "CWE-319"),
    recommendation=(
        "Remove the ``ENV GIT_SSL_NO_VERIFY`` instruction (or set "
        "it to ``0`` / unset it explicitly). The variable tells "
        "every ``git clone`` / ``git fetch`` / ``git pull`` in "
        "the image to accept any TLS certificate the upstream "
        "presents. Baked into ``ENV`` it applies to:\n\n"
        "* ``RUN git clone`` in subsequent build stages\n"
        "* ``git+https://...`` deps that pip / npm / cargo / go "
        "  modules clone at install time\n"
        "* Any runtime process that shells out to ``git`` "
        "  (release-publishing scripts, mirror jobs, GitOps "
        "  agents reading from the image)\n\n"
        "If you need to clone from an internal Git server with "
        "a self-signed cert, install the CA into the image's "
        "truststore — same fix as DF-026 / DF-027. The TLS-"
        "bypass primitive doesn't need to be image-wide for any "
        "legitimate use case."
    ),
    docs_note=(
        "Fires on ``ENV GIT_SSL_NO_VERIFY`` set to any truthy "
        "value (``1``, ``true``, ``yes``, ``on``). The "
        "documented Git mechanism for disabling SSL "
        "verification per-process; in ``ENV`` form, every Git "
        "operation the image runs (and every downstream tool "
        "that shells out to ``git``) sees the bypass.\n\n"
        "Pairs with DF-026 (Node TLS), DF-027 (Python TLS), "
        "and DF-029 (Python requests TLS) for the env-var-"
        "based TLS-bypass surface."
    ),
    exploit_example=(
        "# Vulnerable: ``ENV GIT_SSL_NO_VERIFY=1`` disables git's\n"
        "# certificate verification for every clone / fetch. A\n"
        "# MITM substitutes the remote's contents on the next\n"
        "# git operation.\n"
        "FROM alpine/git@sha256:abc123...\n"
        "ENV GIT_SSL_NO_VERIFY=1\n"
        "RUN git clone https://internal.example.com/repo.git /src\n"
        "\n"
        "# Safe: install the missing CA, keep git's SSL\n"
        "# verification on. ``GIT_SSL_CAPATH`` / ``GIT_SSL_CAINFO``\n"
        "# can also be used to point git at a specific CA bundle\n"
        "# if updating the system trust store isn't an option.\n"
        "FROM alpine/git@sha256:abc123...\n"
        "COPY ci/internal-ca.crt /usr/local/share/ca-certificates/\n"
        "RUN update-ca-certificates && \\\n"
        "    git clone https://internal.example.com/repo.git /src"
    ),
)


_TRUTHY: frozenset[str] = frozenset({"1", "true", "yes", "on"})


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    for line_no, key, value in env_pairs(df):
        if key != "GIT_SSL_NO_VERIFY":
            continue
        stripped = value.strip().lower() if isinstance(value, str) else ""
        if stripped not in _TRUTHY:
            continue
        offenders.append(f"L{line_no}: ENV {key}={value}")
    passed = not offenders
    desc = (
        "No ``ENV`` directive disables Git TLS verification."
        if passed else
        f"{len(offenders)} ``ENV`` directive(s) disable Git TLS "
        f"verification: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Every ``git "
        f"clone`` / ``git fetch`` in or downstream of the image "
        f"accepts any certificate."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
