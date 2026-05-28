"""PYPI-012. pyproject.toml [build-system].requires uses floating versions."""
from __future__ import annotations

import re
import tomllib
from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import RequirementsFile

RULE = Rule(
    id="PYPI-012",
    title="pyproject.toml [build-system].requires uses floating versions",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357", "CWE-829"),
    recommendation=(
        "Pin every entry in ``[build-system].requires`` to an exact "
        "version (``setuptools==69.0.2``, ``wheel==0.42.0``). "
        "Build-system requirements differ from runtime "
        "dependencies in one critical way: they run during package "
        "installation — ``setup.py``, ``setup.cfg``, "
        "``pyproject.toml``-driven build hooks — before any "
        "runtime sandbox is in place. A compromised "
        "``setuptools`` patch release executes arbitrary Python in "
        "the install environment and inherits whatever privileges "
        "the install process has (CI runner write access, deploy "
        "keys, AWS credentials in the environment).\n\n"
        "After exact-pinning the build-system requires, audit the "
        "pins quarterly: subscribe to ``setuptools`` / ``wheel`` "
        "GHSA feeds, dependabot-style automated bumps, and "
        "consider running ``pip install --no-build-isolation`` "
        "against a pre-warmed wheel cache so the build environment "
        "is reproducible across runs."
    ),
    docs_note=(
        "Re-parses each ``pyproject.toml`` (or ``pyproject.toml`` "
        "synthesized into the requirements view) and inspects "
        "``[build-system].requires`` for entries without an exact "
        "``==X.Y.Z`` pin. Caret (``^``), tilde (``~``), comparison "
        "(``>=`` / ``<``), wildcard (``*``), and unbounded "
        "(``setuptools``) all trip the rule.\n\n"
        "Distinct from PYPI-001 (general missing-pin), which audits "
        "every dependency table in the same view. This rule scopes "
        "to the build-system requires specifically because the "
        "build-time install hook surface is higher-risk than "
        "runtime deps: the latter at least have a chance to be "
        "caught by a sandboxed CI test before they ship; the "
        "former runs at ``pip install`` time, before any test "
        "ever executes."
    ),
    known_fp=(
        "Some library projects deliberately leave "
        "``setuptools>=64`` unbounded so downstream consumers can "
        "pick a compatible patch automatically. The rule still "
        "fires; suppress per file with a one-line rationale "
        "naming the publish-time intent. Application repos "
        "(not libraries) should pin.",
    ),
    incident_refs=(
        "Build-time compromise pattern: a popular ``setuptools`` "
        "patch release ships with a poisoned post-install hook "
        "that executes during every downstream ``pip install``. "
        "Floating build-system requires inherit the malicious "
        "version automatically; exact pins survive the incident "
        "until the consumer chooses to bump. The xz-utils style "
        "patch-release smuggle pattern works on every ecosystem "
        "with floating build-time deps, not just system "
        "packages.",
    ),
    exploit_example=(
        "# Vulnerable: unpinned build-system requires.\n"
        "# pyproject.toml\n"
        "[build-system]\n"
        "requires = [\"setuptools\", \"wheel\"]\n"
        "build-backend = \"setuptools.build_meta\"\n"
        "\n"
        "# Attack: a poisoned setuptools 70.0.1 ships with a\n"
        "# malicious egg-info hook. Every ``pip install`` against\n"
        "# this project picks up the latest setuptools, runs the\n"
        "# hook in the install process, and inherits whatever\n"
        "# privileges the install environment carries.\n"
        "\n"
        "# Safe: exact pin.\n"
        "[build-system]\n"
        "requires = [\"setuptools==69.0.2\", \"wheel==0.42.0\"]\n"
        "build-backend = \"setuptools.build_meta\"\n"
        "\n"
        "# Patch upgrades are now explicit: review the diff, run\n"
        "# the test suite, commit the bump."
    ),
)


_EXACT_PIN_RE = re.compile(r"==\s*\d")


def _parse_build_requires(text: str) -> list[str]:
    """Return ``[build-system].requires`` entries from a pyproject.toml
    body. Empty list on parse error or missing table."""
    try:
        data: Any = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    bs = data.get("build-system")
    if not isinstance(bs, dict):
        return []
    requires = bs.get("requires")
    if not isinstance(requires, list):
        return []
    out: list[str] = []
    for entry in requires:
        if isinstance(entry, str) and entry.strip():
            out.append(entry.strip())
    return out


def check(rf: RequirementsFile) -> Finding:
    if not rf.path.endswith("pyproject.toml"):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=rf.path,
            description=(
                "Not a pyproject.toml; build-system requires audit "
                "does not apply."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    requires = _parse_build_requires(rf.text)
    if not requires:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=rf.path,
            description=(
                "pyproject.toml declares no [build-system].requires."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for entry in requires:
        if _EXACT_PIN_RE.search(entry):
            continue
        offenders.append(entry)
        # Best-effort line lookup.
        # The first token of the entry is the package name; search
        # for it in the original text.
        head = entry.split(None, 1)[0].split("[")[0]
        head = head.strip("\"'")
        line_no = 1
        if head and head in rf.text:
            line_no = (
                rf.text[:rf.text.index(head)].count("\n") + 1
            )
        locations.append(Location(
            path=rf.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "Every [build-system].requires entry pins to an exact "
        "version."
        if passed else
        f"{len(offenders)} [build-system].requires entry / entries "
        f"are not exact-pinned: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A compromised patch "
        f"release of any one of these runs at install time before "
        f"any sandbox is in place."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
