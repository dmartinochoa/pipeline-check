"""PYPI-004, VCS requirement uses a mutable ref instead of a commit SHA."""
from __future__ import annotations

import re

from ..._primitives.sha_ref import SHA_RE_IGNORECASE as _SHA_RE
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import RequirementsFile, iter_specs

RULE = Rule(
    id="PYPI-004",
    title="requirements.txt VCS dependency uses a mutable ref",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-9"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-494"),
    recommendation=(
        "Pin VCS requirements to a 40-character commit SHA: "
        "``foo @ git+https://github.com/owner/repo.git@<sha>`` "
        "(or the legacy ``-e git+...@<sha>#egg=foo`` form). Branch "
        "and tag refs (``@main``, ``@v1.2.3``) are mutable, anyone "
        "with push access to the upstream repo can swap the contents "
        "of what your build pulls without changing the requirement "
        "line. A 40-char SHA is immutable. If the upstream isn't "
        "yours, prefer vendoring a fork into a private index and "
        "pinning by version + hash (PYPI-001 / PYPI-002)."
    ),
    docs_note=(
        "Fires on requirement lines whose URL is a VCS scheme "
        "(``git+https://``, ``git+ssh://``, ``hg+``, ``svn+``, "
        "``bzr+``) and whose ``@<ref>`` segment is not a 40-character "
        "SHA. A line with no ``@<ref>`` at all also fires — that "
        "resolves to the default branch HEAD, the most mutable form. "
        "Note: ``foo @ git+https://...`` (PEP 508 direct URL) and "
        "``-e git+https://...#egg=foo`` (legacy editable install) "
        "are both detected."
    ),
    exploit_example=(
        "# Vulnerable: every ``pip install -r requirements.txt``\n"
        "# resolves ``@main`` against the upstream repo. Whoever\n"
        "# can push to ``main`` (legitimate co-maintainer, leaked\n"
        "# PAT, account compromise on the upstream owner) ships\n"
        "# code into your build silently. Tag refs like ``@v1.2.3``\n"
        "# are barely better — git tags are mutable on the upstream\n"
        "# side and can be force-pushed at any time.\n"
        "# requirements.txt\n"
        "shared-utils @ git+https://github.com/myorg/shared-utils.git@main\n"
        "-e git+https://github.com/myorg/legacy.git@v1.2.3#egg=legacy\n"
        "\n"
        "# Safe: pin to a 40-character commit SHA. The git object\n"
        "# is immutable — a re-push under the same SHA fails the\n"
        "# hash check on fetch. Renovate / Dependabot's pip-vcs\n"
        "# ecosystem updaters bump these in reviewable PRs.\n"
        "# requirements.txt\n"
        "shared-utils @ git+https://github.com/myorg/shared-utils.git@0123456789abcdef0123456789abcdef01234567\n"
        "-e git+https://github.com/myorg/legacy.git@fedcba9876543210fedcba9876543210fedcba98#egg=legacy"
    ),
)


_VCS_SCHEMES: tuple[str, ...] = (
    "git+", "hg+", "svn+", "bzr+",
)
# Match ``...@<ref>`` where ``<ref>`` is what follows the *last* ``@``
# in the URL portion (so ``user:pass@host.com/path@ref`` still parses).
_REF_RE = re.compile(r"@([^@/#?\s]+)(?=[#?\s]|$)")


def _extract_vcs_url(body: str) -> str | None:
    """Return the VCS URL substring in *body*, or ``None``.

    Handles three shapes: ``-e git+...``, ``foo @ git+...`` (PEP 508
    direct URL), and a bare ``git+...`` line.
    """
    tokens = body.split()
    if not tokens:
        return None
    if tokens[0] in ("-e", "--editable"):
        if len(tokens) < 2:
            return None
        candidate = tokens[1]
        return candidate if candidate.lower().startswith(_VCS_SCHEMES) else None
    if "@" in body and " " in body:
        # ``name @ url`` PEP 508 direct URL.
        head, _, rest = body.partition("@")
        rest = rest.strip()
        if rest.lower().startswith(_VCS_SCHEMES):
            return rest.split(maxsplit=1)[0]
    head_tok = tokens[0]
    if head_tok.lower().startswith(_VCS_SCHEMES):
        return head_tok
    return None


def check(rf: RequirementsFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for line in iter_specs(rf):
        url = _extract_vcs_url(line.body)
        if url is None:
            continue
        # Strip ``#egg=...`` / ``#subdirectory=...`` fragments so the
        # ref-extraction doesn't pick up the fragment as the ref.
        stripped_url = url.split("#", 1)[0]
        matches = _REF_RE.findall(stripped_url)
        if not matches:
            offenders.append(f"L{line.line_no}: no @<ref> ({url})")
        else:
            ref = matches[-1]
            if not _SHA_RE.match(ref):
                offenders.append(f"L{line.line_no}: @{ref} is not a SHA")
            else:
                continue
        locations.append(Location(
            path=rf.path, start_line=line.line_no, end_line=line.line_no,
        ))
    passed = not offenders
    desc = (
        "Every VCS requirement pins a 40-character commit SHA."
        if passed else
        f"{len(offenders)} VCS requirement(s) use a mutable ref: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Anyone with push "
        f"access to the upstream can swap the contents without "
        f"changing the requirement line."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
