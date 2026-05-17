"""PYPI-001, requirements line missing an exact version pin."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import RequirementsFile, iter_specs

RULE = Rule(
    id="PYPI-001",
    title="requirements.txt entry missing an exact version pin",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Pin every requirement to an exact version (``foo==1.2.3``). "
        "Range specifiers (``>=``, ``~=``, ``<``) and unpinned names "
        "let pip pick a later release on the next install, so a "
        "compromised patch version (PyTorch typosquat, ctx package, "
        "request-PR worm) reaches the build without a code change. "
        "Generate the file with ``pip-compile`` to lock the full "
        "transitive set, and pair the pin with ``--require-hashes`` "
        "(PYPI-002) so the lock is verified at install time."
    ),
    docs_note=(
        "Fires on any requirement that does not use ``==`` to pin a "
        "single version, including:\n\n"
        "* Bare names (``requests``)\n"
        "* Range specifiers (``django>=4,<5``, ``urllib3~=2.0``)\n"
        "* Lone upper-bound (``packaging<24``)\n\n"
        "Skips VCS specs (``git+https://...``), URL specs "
        "(``https://example.com/foo.tar.gz``), editable installs "
        "(``-e .``), and local paths (``./packages/foo``) — those "
        "have different pinning shapes and are handled by PYPI-004 "
        "or fall outside the version-pinning surface. Complements "
        "PYPI-002 (hash pinning) and PYPI-004 (VCS commit pin); "
        "PYPI-001 is the version-name layer."
    ),
    known_fp=(
        "Files that are pip-tools *inputs* (``requirements.in``) "
        "carry unpinned ranges by design, the resolved ``*.txt`` "
        "is the artifact pip installs. If you're scanning a "
        "``*.in`` file intentionally, suppress with a rationale "
        "naming the compiled output.",
    ),
)


_PIN_RE = re.compile(r"==[^=,;\s]+")
_VCS_OR_URL_PREFIXES: tuple[str, ...] = (
    "git+", "hg+", "svn+", "bzr+",
    "http://", "https://", "ftp://", "file:",
)


def _is_url_or_vcs(body: str) -> bool:
    head = body.lstrip().split(maxsplit=1)[0].lower()
    return head.startswith(_VCS_OR_URL_PREFIXES)


def _is_editable_or_local(body: str) -> bool:
    stripped = body.lstrip()
    if stripped.startswith(("-e ", "-e\t", "--editable")):
        return True
    head = stripped.split(maxsplit=1)[0]
    if head.startswith((".", "/", "./", "../")):
        return True
    return False


def check(rf: RequirementsFile) -> Finding:
    # ``*.in`` is a pip-tools input file by convention; ranges are
    # expected there. Treat the scan as informational by passing.
    if rf.path.endswith(".in"):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=rf.path,
            description="pip-tools input file (.in); ranges are expected.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for line in iter_specs(rf):
        body = line.body
        if _is_url_or_vcs(body) or _is_editable_or_local(body):
            continue
        if _PIN_RE.search(body):
            continue
        snippet = body if len(body) <= 60 else body[:57] + "..."
        offenders.append(f"L{line.line_no}: {snippet}")
        locations.append(Location(
            path=rf.path, start_line=line.line_no, end_line=line.line_no,
        ))
    passed = not offenders
    desc = (
        "Every requirement is pinned to an exact version."
        if passed else
        f"{len(offenders)} requirement(s) lack an exact ``==`` pin: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The next install can "
        f"pick a later release, including a compromised one."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
