"""GHA-066. ``actions/upload-artifact`` wildcards sweep the workspace.

zizmor proposal #195 (``artifact-poisoning``) and #1208
(``if-no-files-found``). An ``upload-artifact`` step whose ``path:``
is ``**/*`` or ``.`` (or a similarly unconstrained shape) sweeps the
entire workspace into an artifact, including ``.git/config`` (which
carries an ``actions/checkout``-persisted token unless persist-
credentials was explicitly turned off), ``node_modules`` /
``vendor`` content from install-script execution, and any other
PR-staged tree the workflow happened to materialize.

The published artifact lives in a namespace any PR-reviewer can
read for the workflow run's lifetime. A naïve wildcard upload is
the canonical credential-leakage primitive the ArtiPACKED writeup
demonstrated against real workflows.
"""
from __future__ import annotations

import re
from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-066",
    title="``actions/upload-artifact`` path is a workspace wildcard",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-9"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-200", "CWE-538"),
    recommendation=(
        "Replace the wildcard with a minimal allowlist of artifact "
        "paths. ``path: build/`` (or ``path: |\\n  dist/\\n  "
        "coverage.xml``) keeps the artifact bounded to the build "
        "output the downstream consumer actually needs. If you need "
        "a debug dump of the workspace, scope it to a temporary "
        "directory the workflow assembles, then upload that. Always "
        "explicitly exclude ``.git/`` and any ``node_modules`` / "
        "``vendor`` trees from a wildcard upload."
    ),
    docs_note=(
        "Fires when a step's ``uses:`` matches "
        "``actions/upload-artifact`` (any major version) AND its "
        "``with.path:`` value is one of:\n\n"
        "* ``**/*`` (recursive everything),\n"
        "* ``.`` (current directory),\n"
        "* ``/`` or ``./`` (root),\n"
        "* ``${{ github.workspace }}`` (the entire workspace),\n"
        "* ``${{ github.workspace }}/**`` and similar suffixes.\n\n"
        "Multi-line ``path:`` values (a YAML scalar block listing "
        "multiple paths) are scanned line by line; one wildcard "
        "line is enough to fire. The rule pairs with GHA-019 (the "
        "credential-persistence side: an unconstrained upload after "
        "an unconstrained checkout is the full ArtiPACKED chain)."
    ),
    known_fp=(
        "A workflow that genuinely wants to archive the whole "
        "build output as a release artifact in a job whose "
        "GITHUB_TOKEN was already minimized (``persist-credentials: "
        "false`` on the checkout step, no ``id-token: write``) "
        "and where ``.git/`` isn't checked out (or was removed). "
        "Suppress per-step via ignore-file when the operator has "
        "audited that the archive doesn't carry credential-shaped "
        "files. Note that an ``id-token: write``-scoped workflow "
        "is never safe to wildcard-upload from.",
    ),
    incident_refs=(
        "ArtiPACKED (Palo Alto Unit 42, 2024): "
        "https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/",
        "zizmor proposal #195 (artifact-poisoning audit): "
        "https://github.com/zizmorcore/zizmor/issues/195",
    ),
    exploit_example=(
        "# Vulnerable: ``path: '.'`` includes ``.git/config`` which\n"
        "# the checkout step seeded with a ``http.<host>.extraheader``\n"
        "# carrying the workflow's GITHUB_TOKEN. The uploaded\n"
        "# artifact is readable for the run's lifetime by any user\n"
        "# with the PR open, including fork-PR contributors.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: ./build.sh\n"
        "      - uses: actions/upload-artifact@<sha>\n"
        "        with:\n"
        "          name: debug-bundle\n"
        "          path: .\n"
        "\n"
        "# Safe: scope to a freshly-staged dir.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "        with: { persist-credentials: false }\n"
        "      - run: |\n"
        "          ./build.sh\n"
        "          mkdir _staged\n"
        "          cp -r dist/ coverage.xml _staged/\n"
        "      - uses: actions/upload-artifact@<sha>\n"
        "        with:\n"
        "          name: build-output\n"
        "          path: _staged/"
    ),
)


_UPLOAD_USES_RE = re.compile(
    r"^actions/upload-artifact(?:/[^@]*)?(?:@.*)?$",
    re.IGNORECASE,
)

#: Path values that sweep the workspace. Whitespace is stripped from
#: each line before comparison. The ``${{ github.workspace }}`` shape
#: is matched via substring because the same expression may carry a
#: trailing slash or ``/**``.
_WORKSPACE_WILDCARDS: tuple[str, ...] = (
    "**/*",
    "**",
    ".",
    "./",
    "/",
    "*",
)


def _is_workspace_wildcard(path_line: str) -> bool:
    """True if *path_line* is a workspace-wide sweep pattern."""
    line = path_line.strip()
    if not line:
        return False
    # Exact-match shapes
    if line in _WORKSPACE_WILDCARDS:
        return True
    # ``${{ github.workspace }}`` and its ``/**`` sweeps are workspace-
    # wide, but a bounded subdirectory (``${{ github.workspace }}/dist``)
    # is scoped and safe. Strip the expression and flag only when the
    # remainder is the whole tree.
    if "github.workspace" in line:
        remainder = re.sub(
            r"\$\{\{\s*github\.workspace\s*\}\}", "", line,
        ).strip()
        return remainder in ("", "/", "/**", "/**/*", "/.")
    # ``./**``, ``./**/*`` and similar bare-prefix expansions
    if line.startswith("./") and (line == "./**" or line == "./**/*"):
        return True
    return False


def _scan_upload_path(value: Any) -> list[str]:
    """Return wildcard offender lines from a ``path:`` value.

    ``upload-artifact`` accepts the value as a string (single path
    or YAML block scalar with newlines) or a list. Both shapes get
    flattened to a per-line list before checking.
    """
    if isinstance(value, str):
        lines = value.splitlines() if "\n" in value else [value]
    elif isinstance(value, list):
        lines = [str(v) for v in value]
    else:
        return []
    return [line.strip() for line in lines if _is_workspace_wildcard(line)]


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            uses = step.get("uses")
            if not isinstance(uses, str) or not _UPLOAD_USES_RE.match(uses):
                continue
            with_block = step.get("with")
            if not isinstance(with_block, dict):
                continue
            offenders_here = _scan_upload_path(with_block.get("path"))
            if not offenders_here:
                continue
            offenders.append(
                f"{job_id}[{idx}]: path={', '.join(repr(o) for o in offenders_here)}"
            )
            line = _line_of(step)
            if line is not None:
                locations.append(Location(
                    path=path, start_line=line, end_line=line,
                ))
    passed = not offenders
    desc = (
        "No ``actions/upload-artifact`` step uses a workspace wildcard path."
        if passed else
        f"{len(offenders)} ``actions/upload-artifact`` step(s) "
        f"wildcard-upload the workspace: "
        f"{'; '.join(offenders[:3])}"
        f"{'...' if len(offenders) > 3 else ''}. The archive "
        f"includes ``.git/config`` (token-bearing after checkout) "
        f"and any other PR-staged tree."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
