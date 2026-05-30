"""COMPOSER-013. config.disable-tls turns off certificate verification."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ComposerFile

RULE = Rule(
    id="COMPOSER-013",
    title="composer.json config.disable-tls turns off certificate verification",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-295", "CWE-319"),
    recommendation=(
        "Remove the ``config.disable-tls: true`` entry from "
        "``composer.json`` (or set it back to ``false``). With "
        "TLS disabled, Composer skips certificate verification on "
        "every HTTPS request, so a man-in-the-middle can present a "
        "forged certificate and serve tampered packages without a "
        "warning. This is strictly worse than "
        "``secure-http: false`` (COMPOSER-010): that one allows "
        "plain HTTP, this one keeps the ``https://`` scheme but "
        "stops validating who is on the other end.\n\n"
        "If a certificate error pushed someone to set this flag, "
        "fix the trust chain (install the corporate CA, renew the "
        "expired cert) rather than turning verification off "
        "globally."
    ),
    docs_note=(
        "Fires when ``config.disable-tls`` is explicitly set to "
        "the boolean ``true`` in ``composer.json``. The default "
        "(``false``) is the safe posture, so the rule only trips "
        "on an explicit downgrade. Mirrors the one-key config "
        "lookup of COMPOSER-008 (allow-plugins) and COMPOSER-010 "
        "(secure-http)."
    ),
    known_fp=(),
    incident_refs=(
        "Composer documents ``disable-tls`` as a last-resort "
        "escape hatch precisely because it removes the only "
        "integrity guarantee on package downloads. A persistent "
        "``true`` in a committed manifest re-opens the MITM "
        "surface on every CI install run.",
    ),
    exploit_example=(
        "// Vulnerable: certificate verification off.\n"
        "{\n"
        "  \"config\": {\n"
        "    \"disable-tls\": true\n"
        "  }\n"
        "}\n"
        "\n"
        "// Risk: an attacker on the network presents a forged or\n"
        "// self-signed certificate, Composer accepts it without\n"
        "// complaint, and a backdoored package tarball installs.\n"
        "\n"
        "// Safe: drop the flag, fix the trust chain instead.\n"
        "{\n"
        "  \"config\": {}\n"
        "}"
    ),
)


def check(pom: ComposerFile) -> Finding:
    raw = pom.config.get("disable-tls")
    if raw is not True:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "config.disable-tls is unset or false (TLS "
                "verification stays on)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    locations: list[Location] = []
    idx = pom.text.find('"disable-tls"')
    if idx >= 0:
        line = pom.text[:idx].count("\n") + 1
        locations.append(Location(
            path=pom.path, start_line=line, end_line=line,
        ))
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path,
        description=(
            "config.disable-tls is explicitly set to ``true`` — "
            "Composer skips certificate verification on every "
            "HTTPS request. Remove the entry or restore "
            "``false``."
        ),
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
    )
