"""PYPI-003, requirements file uses an HTTP index or --trusted-host."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import RequirementsFile, get_option_values

RULE = Rule(
    id="PYPI-003",
    title="requirements.txt uses an HTTP index or disables TLS verification",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-319", "CWE-295"),
    recommendation=(
        "Switch ``--index-url`` and ``--extra-index-url`` to "
        "``https://`` and remove ``--trusted-host``. If your "
        "internal index has a self-signed certificate, install "
        "the CA into the build environment's truststore (or pass "
        "``PIP_CERT=/path/to/ca.pem``) instead of telling pip to "
        "skip verification. ``--trusted-host`` disables TLS "
        "verification *and* hash verification for the named host, "
        "so anyone on the network path can swap the wheel."
    ),
    docs_note=(
        "Fires when the file's top-level options include:\n\n"
        "* ``--index-url http://...`` / ``-i http://...``\n"
        "* ``--extra-index-url http://...``\n"
        "* ``--trusted-host <host>``\n\n"
        "Complements DF-021 (Dockerfile ``RUN pip install ``-i "
        "http://...``); PYPI-003 catches the same pattern when "
        "it's baked into the requirements file rather than the "
        "shell command. Note ``--trusted-host`` also weakens "
        "PYPI-002 — pip silently skips hash checking for the "
        "trusted host even when ``--require-hashes`` is set."
    ),
    exploit_example=(
        "# Vulnerable: pip resolves every package against a\n"
        "# plaintext-HTTP index. Any network attacker between the\n"
        "# build runner and the index (compromised corporate proxy,\n"
        "# malicious VPN exit, BGP hijack on the internal mirror)\n"
        "# swaps the wheel in flight. ``--trusted-host`` is worse:\n"
        "# pip then SKIPS hash verification for that host, so even\n"
        "# a ``--require-hashes`` file installs unverified bytes.\n"
        "# requirements.txt\n"
        "--index-url http://internal-pypi.example.com/simple\n"
        "--trusted-host internal-pypi.example.com\n"
        "requests==2.31.0\n"
        "\n"
        "# Safe: HTTPS with the index's certificate validated. For\n"
        "# an internal index on a private CA, install the CA into\n"
        "# the agent trust store or pass ``PIP_CERT=/path/to/ca.pem``\n"
        "# — never ``--trusted-host``. Hashes stay enforced.\n"
        "# requirements.txt\n"
        "--index-url https://internal-pypi.example.com/simple\n"
        "--require-hashes\n"
        "requests==2.31.0 \\\n"
        "    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1"
    ),
)


def check(rf: RequirementsFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for flag in ("--index-url", "-i", "--extra-index-url"):
        for value in get_option_values(rf, flag):
            if value.lower().startswith("http://"):
                offenders.append(f"{flag} {value}")
    trusted = get_option_values(rf, "--trusted-host")
    for host in trusted:
        offenders.append(f"--trusted-host {host}")
    if offenders:
        # Locate the first matching option in the original text.
        for needle in (
            "--index-url", "--extra-index-url", "--trusted-host", "-i ",
        ):
            idx = rf.text.find(needle)
            if idx >= 0:
                line_no = rf.text[:idx].count("\n") + 1
                locations.append(Location(
                    path=rf.path, start_line=line_no, end_line=line_no,
                ))
                break
    passed = not offenders
    desc = (
        "No HTTP index URL or --trusted-host declared."
        if passed else
        f"{len(offenders)} insecure pip option(s): "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Anyone on the "
        f"network path between the build and the index can ship "
        f"arbitrary wheels."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
