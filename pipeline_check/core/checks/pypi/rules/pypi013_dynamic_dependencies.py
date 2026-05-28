"""PYPI-013. pyproject.toml defers dependency resolution via ``dynamic``."""
from __future__ import annotations

import tomllib
from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import RequirementsFile

RULE = Rule(
    id="PYPI-013",
    title="pyproject.toml defers dependency resolution via dynamic",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Move every entry out of ``[project].dynamic`` and into "
        "an explicit static field on ``[project]``. ``dynamic`` "
        "tells the build backend to compute the value at build "
        "time, typically by reading ``setup.py`` / ``setup.cfg`` / "
        "a vendor-specific extension. Static analysis can't see "
        "those values, which means every linter, IDE, "
        "SBOM-generator, and supply-chain scanner (this one "
        "included) is blind to the dependency set.\n\n"
        "The migration is mechanical:\n\n"
        "* ``dynamic = [\"dependencies\"]`` → move runtime deps "
        "into ``[project].dependencies`` as a static list.\n"
        "* ``dynamic = [\"optional-dependencies\"]`` → move into "
        "``[project.optional-dependencies]``.\n"
        "* ``dynamic = [\"version\"]`` → if computed from "
        "``__version__``, switch to a ``setuptools_scm``-style "
        "version-from-VCS configuration that's at least declared "
        "in the manifest, or commit to an explicit literal.\n\n"
        "After the migration, this rule passes and PYPI-001 takes "
        "over for the floating-spec audit of the now-visible "
        "dependency list."
    ),
    docs_note=(
        "Re-parses ``pyproject.toml`` and inspects "
        "``[project].dynamic`` for entries that defer dependency "
        "resolution: ``\"dependencies\"`` and "
        "``\"optional-dependencies\"`` specifically (other dynamic "
        "fields like ``\"version\"`` are also flagged but at "
        "informational priority — they don't affect supply-chain "
        "audit, just hygiene).\n\n"
        "The rule's value is closing a static-analysis blind "
        "spot: a project that lists no dependencies in "
        "``[project].dependencies`` while declaring "
        "``dynamic = [\"dependencies\"]`` looks dependency-free "
        "to PYPI-001 / PYPI-002 / PYPI-008, but ships with a full "
        "real-world dependency graph that was computed at build "
        "time."
    ),
    known_fp=(
        "Some libraries use ``dynamic = [\"version\"]`` with "
        "``setuptools_scm`` legitimately so a single source of "
        "truth (a git tag) drives both the package version and "
        "the changelog. The version-only case is the lowest-"
        "impact form; suppress per file with a one-line rationale "
        "naming the scm-driven version policy. The "
        "``dependencies`` / ``optional-dependencies`` cases "
        "should not be suppressed without static-analysis parity "
        "evidence.",
    ),
    incident_refs=(
        "Static-analysis blind-spot class commonly surfaced in "
        "audits of libraries that ship pyproject.toml as a "
        "modern facade over a legacy setup.py: the manifest "
        "looks PEP 621-compliant but ``dynamic = "
        "[\"dependencies\"]`` punts the real list to ``setup.py``, "
        "which can do anything (read environment variables, fetch "
        "lists over the network, derive deps from a config file "
        "in the repo). Every supply-chain audit downstream has "
        "to know setup.py's dynamic behavior to be accurate.",
    ),
    exploit_example=(
        "# Vulnerable: dependencies deferred to setup.py.\n"
        "# pyproject.toml\n"
        "[project]\n"
        "name = \"my-app\"\n"
        "version = \"0.1.0\"\n"
        "dynamic = [\"dependencies\"]\n"
        "\n"
        "[build-system]\n"
        "requires = [\"setuptools\"]\n"
        "build-backend = \"setuptools.build_meta\"\n"
        "\n"
        "# setup.py reads an environment variable to decide which\n"
        "# version of ``urllib3`` to require. Any static analysis\n"
        "# of the pyproject.toml above sees zero deps; the real\n"
        "# dependency set differs per build environment.\n"
        "\n"
        "# Safe: static dependency list.\n"
        "# pyproject.toml\n"
        "[project]\n"
        "name = \"my-app\"\n"
        "version = \"0.1.0\"\n"
        "dependencies = [\n"
        "    \"urllib3==2.1.0\",\n"
        "    \"requests==2.31.0\",\n"
        "]\n"
        "\n"
        "# Now every scanner, IDE, and SBOM tool sees the real\n"
        "# dependency graph and can audit it."
    ),
)


def _parse_dynamic_fields(text: str) -> list[str]:
    """Return the ``[project].dynamic`` array. Empty list when
    parse fails or the field is absent."""
    try:
        data: Any = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    project = data.get("project")
    if not isinstance(project, dict):
        return []
    dyn = project.get("dynamic")
    if not isinstance(dyn, list):
        return []
    return [entry for entry in dyn if isinstance(entry, str)]


_DEPENDENCY_FIELDS: frozenset[str] = frozenset({
    "dependencies",
    "optional-dependencies",
})


def check(rf: RequirementsFile) -> Finding:
    if not rf.path.endswith("pyproject.toml"):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=rf.path,
            description=(
                "Not a pyproject.toml; dynamic-fields audit does "
                "not apply."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    fields = _parse_dynamic_fields(rf.text)
    offenders = [f for f in fields if f in _DEPENDENCY_FIELDS]
    locations: list[Location] = []
    if offenders:
        line_no = 1
        if "dynamic" in rf.text:
            line_no = (
                rf.text[:rf.text.index("dynamic")].count("\n") + 1
            )
        locations.append(Location(
            path=rf.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "[project].dynamic does not defer dependency resolution."
        if passed else
        f"[project].dynamic defers {', '.join(offenders)} to the "
        f"build backend. Static-analysis tools (this scanner "
        f"included) see no deps in the manifest; the real "
        f"dependency set is computed at build time."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
