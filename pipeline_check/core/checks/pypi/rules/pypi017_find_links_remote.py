"""PYPI-017, --find-links points at a remote host."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import RequirementsFile, get_option_values, has_option

RULE = Rule(
    id="PYPI-017",
    title="requirements.txt uses a remote --find-links source",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Resolve packages from a single trusted index instead of a "
        "remote ``--find-links`` URL. ``--find-links`` adds an extra "
        "place pip looks for distributions, and pip will install a "
        "wheel or sdist found there outside the normal index "
        "resolution, so the host becomes an unreviewed package "
        "source. If you must serve files this way, use an "
        "``https://`` host you control and pin every requirement with "
        "``==`` (PYPI-001) and a ``--hash`` (PYPI-002) so the bytes "
        "are verified regardless of where pip found them."
    ),
    docs_note=(
        "Fires on a top-level ``--find-links`` / ``-f`` whose value is "
        "a remote ``http(s)`` URL. Local directory paths "
        "(``./vendor/wheels``, ``/opt/wheels``) carry no host and are "
        "not flagged. URLs on canonical PyPI hosts are not flagged.\n\n"
        "Severity escalates from MEDIUM to HIGH when ``--no-index`` is "
        "also set in the same file (find-links becomes the only source "
        "pip uses, with no index to fall back on) or when the URL is "
        "plain ``http://`` (the download is tamperable in transit). "
        "``--find-links`` was parsed before but unused; this rule is "
        "the consumer."
    ),
    known_fp=(
        "A ``--find-links`` to a vetted internal artifact host "
        "serving immutable, hashed files can be intentional. Pin the "
        "requirements with ``--hash`` and suppress per file once the "
        "host is verified.",
    ),
    exploit_example=(
        "# Vulnerable: --no-index makes find-links the SOLE source.\n"
        "# pip ignores PyPI entirely and installs whatever this one\n"
        "# HTTP host serves, so an on-path attacker (or the host\n"
        "# operator) supplies a backdoored wheel for any requested\n"
        "# package. http:// adds in-transit tampering on top.\n"
        "# requirements.txt\n"
        "--no-index\n"
        "--find-links http://wheels.example.com/\n"
        "requests==2.31.0\n"
        "\n"
        "# Safe: resolve from a single trusted index over HTTPS and\n"
        "# pin + hash every requirement.\n"
        "# requirements.txt\n"
        "--index-url https://pypi.org/simple\n"
        "--require-hashes\n"
        "requests==2.31.0 \\\n"
        "    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1"
    ),
)


_PYPI_HOSTS: tuple[str, ...] = ("pypi.org", "files.pythonhosted.org")


def _host_of(url: str) -> str:
    """Return the lowercase host of a URL, or ``""`` for a local path."""
    if "://" not in url:
        return ""
    rest = url.split("://", 1)[1]
    authority = rest.split("/", 1)[0]
    authority = authority.rsplit("@", 1)[-1]
    return authority.split(":", 1)[0].lower()


def _is_pypi_host(host: str) -> bool:
    return host in _PYPI_HOSTS or host.endswith(".pythonhosted.org")


def check(rf: RequirementsFile) -> Finding:
    no_index = has_option(rf, "--no-index")
    offenders: list[str] = []
    locations: list[Location] = []
    escalate = False
    for flag in ("--find-links", "-f"):
        for value in get_option_values(rf, flag):
            value = value.strip()
            if not value:
                continue
            host = _host_of(value)
            # Local directory paths have no remote host.
            if not host or _is_pypi_host(host):
                continue
            is_http = value.lower().startswith("http://")
            if no_index or is_http:
                escalate = True
            offenders.append(f"{flag} {value}")
            line_no = 1
            if flag in rf.text:
                line_no = rf.text[:rf.text.index(flag)].count("\n") + 1
            locations.append(Location(
                path=rf.path, start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    severity = Severity.HIGH if escalate else RULE.severity
    if passed:
        desc = "No remote --find-links source declared."
    else:
        reason = (
            " --no-index is set, so find-links is the only source pip "
            "uses."
            if no_index else
            " An http:// URL is tamperable in transit."
            if escalate else
            ""
        )
        desc = (
            f"{len(offenders)} remote --find-links source(s): "
            f"{', '.join(offenders[:5])}"
            f"{'…' if len(offenders) > 5 else ''}.{reason} pip will "
            f"install distributions found there outside the normal "
            f"index resolution."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
