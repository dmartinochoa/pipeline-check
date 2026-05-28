"""PYPI-011. Requirements file disables TLS verification via --trusted-host."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import RequirementsFile, get_option_values

RULE = Rule(
    id="PYPI-011",
    title="Requirements file disables TLS verification via --trusted-host",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-6"),
    esf=("ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-295", "CWE-345"),
    recommendation=(
        "Remove every ``--trusted-host`` flag from the requirements "
        "file and fix the underlying TLS problem instead. The flag "
        "tells pip to skip certificate validation for the named "
        "host, which means any MITM along the install path can "
        "swap the wheel without detection. Three remediation "
        "patterns:\n\n"
        "* If the host is internal and has a valid certificate "
        "signed by a private CA, distribute the CA bundle to "
        "consumers (``REQUESTS_CA_BUNDLE`` / ``SSL_CERT_FILE``) "
        "and drop the flag.\n"
        "* If the host serves plain HTTP, switch to HTTPS — most "
        "internal artifact registries ship with a built-in "
        "self-signed certificate that's easy to swap for a "
        "real one.\n"
        "* If the host is genuinely external and the certificate "
        "is expired (common with abandoned mirrors), switch to "
        "the canonical PyPI URL or a maintained mirror."
    ),
    docs_note=(
        "Reads ``--trusted-host`` options from each requirements "
        "file and fires once per declared host. The flag's "
        "semantics are exactly the named-host TLS bypass: "
        "certificate validation is skipped, the certificate's "
        "expiry / signature / SAN are not consulted, and a "
        "MITM that intercepts the TCP connection to the named "
        "host can serve arbitrary wheel content without "
        "raising pip's verification.\n\n"
        "Distinct from PYPI-003 (HTTP index URL) and PYPI-005 "
        "(``--extra-index-url`` to a non-default registry): "
        "those rules catch the configuration shapes that "
        "*declare* an insecure source, this one catches the "
        "explicit-bypass shape that disables the verification "
        "that would otherwise gate the install."
    ),
    known_fp=(
        "A small number of internal mirrors that legitimately "
        "operate on HTTP within a strictly-firewalled network "
        "use ``--trusted-host`` as a deliberate posture. The "
        "rule still fires; suppress per host with a one-line "
        "rationale naming the network boundary that justifies "
        "skipping TLS.",
    ),
    incident_refs=(
        "Long-running pattern in CI debugging sessions: a "
        "transient certificate problem on an internal mirror is "
        "worked around by adding ``--trusted-host`` to "
        "requirements.txt, the certificate is fixed days later, "
        "the flag is never removed. The bypass persists "
        "indefinitely; every subsequent ``pip install`` against "
        "that requirements file accepts unauthenticated wheel "
        "content.",
    ),
    exploit_example=(
        "# Vulnerable: TLS verification disabled for the named\n"
        "# internal host.\n"
        "# requirements.txt\n"
        "--extra-index-url https://nexus.corp.example/simple/\n"
        "--trusted-host nexus.corp.example\n"
        "internal-utils==1.2.3\n"
        "\n"
        "# Attack: a runner image's DNS resolver is poisoned to\n"
        "# point ``nexus.corp.example`` at an attacker-controlled\n"
        "# host serving its own wheel for ``internal-utils``.\n"
        "# pip's cert validation is bypassed; the wheel installs;\n"
        "# the package's import-time code runs with whatever\n"
        "# privileges the runner has.\n"
        "\n"
        "# Safe: fix the cert and drop the trusted-host flag.\n"
        "# requirements.txt\n"
        "--extra-index-url https://nexus.corp.example/simple/\n"
        "internal-utils==1.2.3"
    ),
)


def check(rf: RequirementsFile) -> Finding:
    hosts = get_option_values(rf, "--trusted-host")
    offenders: list[str] = []
    locations: list[Location] = []
    for host in hosts:
        host = host.strip()
        if not host:
            continue
        offenders.append(host)
        line_no = 1
        if "--trusted-host" in rf.text:
            line_no = (
                rf.text[:rf.text.index("--trusted-host")].count("\n") + 1
            )
        locations.append(Location(
            path=rf.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "No ``--trusted-host`` flags declared."
        if passed else
        f"{len(offenders)} ``--trusted-host`` declaration(s): "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Each one disables "
        f"pip's TLS verification for the named host."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
