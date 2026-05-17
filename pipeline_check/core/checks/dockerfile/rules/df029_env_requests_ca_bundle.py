"""DF-029, ``ENV REQUESTS_CA_BUNDLE`` points at /dev/null or empty."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, env_pairs

RULE = Rule(
    id="DF-029",
    title="ENV neuters Python requests CA bundle",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-D-RUNTIME-HARDENING", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-295", "CWE-319"),
    recommendation=(
        "Set ``ENV REQUESTS_CA_BUNDLE`` to the path of a real "
        "CA bundle (typically ``/etc/ssl/certs/ca-certificates.crt`` "
        "on Debian or ``/etc/ssl/cert.pem`` on Alpine), or unset "
        "it entirely so the ``requests`` library falls back to "
        "``certifi``. Pointing the variable at ``/dev/null`` or "
        "an empty string is a documented anti-pattern: ``requests`` "
        "treats the empty / missing bundle as 'verify against "
        "nothing,' which silently accepts every certificate.\n\n"
        "The same shape as DF-027 (``PYTHONHTTPSVERIFY=0``) but "
        "narrower in surface — ``REQUESTS_CA_BUNDLE`` only "
        "affects ``requests`` and its descendants, not the "
        "stdlib ``urllib``. Still a real bypass because most "
        "Python network clients (pip, AWS CLI, Anchore, Trivy, "
        "every Django app) flow through ``requests``."
    ),
    docs_note=(
        "Fires when ``ENV REQUESTS_CA_BUNDLE`` resolves to a "
        "value that disables verification:\n\n"
        "* ``/dev/null`` (literal),\n"
        "* the empty string (``ENV REQUESTS_CA_BUNDLE=`` or "
        "  ``ENV REQUESTS_CA_BUNDLE=\"\"``),\n"
        "* whitespace-only values.\n\n"
        "A path to a real file (``/etc/ssl/certs/...``, "
        "``/usr/local/share/ca-certificates/internal.crt``) "
        "passes — the rule only flags the disable shapes. "
        "Pairs with DF-027 (Python TLS via env)."
    ),
)


def _disables_verification(value: object) -> bool:
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if not stripped:
        # ``ENV REQUESTS_CA_BUNDLE=`` parses to an empty value
        # and disables verification at the requests layer.
        return True
    return stripped == "/dev/null"


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    for line_no, key, value in env_pairs(df):
        if key != "REQUESTS_CA_BUNDLE":
            continue
        if not _disables_verification(value):
            continue
        offenders.append(f"L{line_no}: ENV {key}={value!r}")
    passed = not offenders
    desc = (
        "No ``ENV`` directive neuters the Python requests CA "
        "bundle."
        if passed else
        f"{len(offenders)} ``ENV`` directive(s) point "
        f"``REQUESTS_CA_BUNDLE`` at an empty / null path: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Every Python "
        f"call into ``requests`` (pip, AWS CLI, Django, …) "
        f"accepts any certificate."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
