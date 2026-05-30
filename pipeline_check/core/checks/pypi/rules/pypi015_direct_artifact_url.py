"""PYPI-015, requirement installed from a direct artifact URL."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import RequirementsFile, iter_specs

RULE = Rule(
    id="PYPI-015",
    title="requirements.txt installs from a direct artifact URL",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-494"),
    recommendation=(
        "Install the package from an index by ``name==version`` "
        "(PYPI-001) with a recorded ``--hash`` (PYPI-002) instead of a "
        "direct artifact URL. A ``name @ https://host/foo.whl`` or a "
        "bare wheel / tarball URL pulls bytes from one host with no "
        "name, version, or hash gating, so a takeover of that host, or "
        "a swap of the file behind a stable URL, lands arbitrary code "
        "in the build. If a direct URL is genuinely unavoidable, pin "
        "it with an inline ``--hash=sha256:...`` so the downloaded "
        "bytes are verified, and serve it over HTTPS from a host you "
        "control."
    ),
    docs_note=(
        "Fires on a requirement whose spec is an ``http(s)`` artifact "
        "URL: the PEP 508 ``name @ https://...`` form and the bare "
        "``https://host/foo.whl`` / ``foo.tar.gz`` / ``foo.zip`` "
        "direct-download form. VCS schemes (``git+``, ``hg+``, ``svn+``, "
        "``bzr+``) are PYPI-004's surface and are skipped here. URLs "
        "pointing at canonical PyPI hosts (``pypi.org`` / "
        "``files.pythonhosted.org``) are not flagged. A line that "
        "carries an inline ``--hash=`` is not flagged, the hash makes "
        "the direct download verifiable.\n\n"
        "Complements PYPI-001 (which skips URL specs) and PYPI-004 "
        "(which only matches VCS schemes), closing the http(s)-"
        "artifact gap neither one sees."
    ),
    known_fp=(
        "An internal release server that publishes immutable, "
        "content-addressed artifacts may legitimately use direct "
        "URLs. Add an inline ``--hash`` to pin the bytes (which also "
        "silences this rule), or suppress per line with a rationale "
        "once the URL is verified out of band.",
    ),
    exploit_example=(
        "# Vulnerable: the wheel is fetched from one host with no\n"
        "# name / version / hash gating. Whoever controls that host\n"
        "# (or its DNS / TLS, or just the file behind the stable URL)\n"
        "# replaces the wheel with a backdoored build, and every\n"
        "# ``pip install -r requirements.txt`` pulls the poisoned\n"
        "# bytes. Wheel install runs no package code, but the\n"
        "# attacker controls the entire wheel, including its\n"
        "# import-time module bodies.\n"
        "# requirements.txt\n"
        "mypkg @ https://downloads.example.com/mypkg-1.0-py3-none-any.whl\n"
        "https://files.example.org/other-2.0.tar.gz\n"
        "\n"
        "# Safe: install from an index by name==version with a hash,\n"
        "# or, if a direct URL is unavoidable, pin the bytes inline.\n"
        "# requirements.txt\n"
        "--require-hashes\n"
        "mypkg==1.0 \\\n"
        "    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1"
    ),
)


_PYPI_HOSTS: tuple[str, ...] = ("pypi.org", "files.pythonhosted.org")
_ARTIFACT_SUFFIXES: tuple[str, ...] = (
    ".whl", ".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar.xz", ".egg",
)
_VCS_SCHEMES: tuple[str, ...] = ("git+", "hg+", "svn+", "bzr+")


def _host_of(url: str) -> str:
    """Return the lowercase host of an http(s) URL, or ``""``."""
    rest = url.split("://", 1)[1] if "://" in url else url
    authority = rest.split("/", 1)[0]
    # Drop any ``user:pass@`` prefix and ``:port`` suffix.
    authority = authority.rsplit("@", 1)[-1]
    return authority.split(":", 1)[0].lower()


def _is_pypi_host(host: str) -> bool:
    return host in _PYPI_HOSTS or host.endswith(".pythonhosted.org")


def _artifact_url(body: str) -> str | None:
    """Return the direct http(s) artifact URL in *body*, or ``None``.

    Handles the PEP 508 ``name @ https://...`` form and a bare
    ``https://host/foo.whl`` line. VCS schemes are PYPI-004's surface
    and return ``None`` here.
    """
    tokens = body.split()
    if not tokens:
        return None
    # ``name @ url`` direct-URL form.
    if "@" in body:
        _, _, rest = body.partition("@")
        candidate = rest.strip().split(maxsplit=1)
        if candidate:
            url = candidate[0]
            low = url.lower()
            if low.startswith(_VCS_SCHEMES):
                return None
            if low.startswith(("http://", "https://")):
                return url
    head = tokens[0]
    low = head.lower()
    if low.startswith(_VCS_SCHEMES):
        return None
    if low.startswith(("http://", "https://")):
        return head
    return None


def check(rf: RequirementsFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for line in iter_specs(rf):
        url = _artifact_url(line.body)
        if url is None:
            continue
        # Strip any ``#fragment`` before checking the suffix / host.
        bare = url.split("#", 1)[0].split("?", 1)[0]
        host = _host_of(bare)
        if _is_pypi_host(host):
            continue
        # An inline hash makes the direct download verifiable.
        if line.flags:
            continue
        # Bare URL lines must look like an artifact; ``name @ url`` is
        # already an explicit direct-URL install regardless of suffix.
        is_named = "@" in line.body
        if not is_named and not bare.lower().endswith(_ARTIFACT_SUFFIXES):
            continue
        offenders.append(f"L{line.line_no}: {url}")
        locations.append(Location(
            path=rf.path, start_line=line.line_no, end_line=line.line_no,
        ))
    passed = not offenders
    desc = (
        "No requirement installs from an unverified direct artifact URL."
        if passed else
        f"{len(offenders)} requirement(s) install from a direct "
        f"artifact URL with no hash: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A takeover of the host "
        f"or a swap of the file behind the URL lands arbitrary code "
        f"in the build."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
