"""PYPI-005, requirements file declares --extra-index-url (dependency confusion)."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import RequirementsFile, get_option_values

RULE = Rule(
    id="PYPI-005",
    title="requirements.txt declares --extra-index-url (dependency-confusion surface)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-427"),
    recommendation=(
        "Replace ``--extra-index-url`` with a single ``--index-url`` "
        "pointing at the index you actually want (an internal proxy "
        "or a curated private index), and configure that index to "
        "transparently mirror PyPI for any package not published "
        "internally. With ``--extra-index-url``, pip queries *both* "
        "indexes for every name and picks the highest version — so "
        "a public PyPI publisher who registers your internal "
        "package name (``acme-internal``) with a higher version "
        "wins the resolution. The single-index pattern eliminates "
        "the dependency-confusion vector entirely."
    ),
    docs_note=(
        "Fires when the file declares ``--extra-index-url`` at any "
        "level. The flag itself is the anti-pattern, the URL value "
        "doesn't matter, pip will query both the primary and the "
        "extra index for every package and pick the higher version. "
        "An attacker who registers a public PyPI package with the "
        "same name as an internal-only dependency wins the version "
        "comparison and ships their code into the build.\n\n"
        "If the extra index is a hash-locked internal proxy that "
        "serves *both* internal and mirrored-public packages, "
        "consolidating it into the primary ``--index-url`` removes "
        "the surface without losing any capability. Suppress with a "
        "rationale only when both indexes share an operator-"
        "controlled allow-list of names."
    ),
    incident_refs=(
        "Alex Birsan, \"Dependency Confusion: How I Hacked Into "
        "Apple, Microsoft and Dozens of Other Companies\" (2021): "
        "internal package names harvested from public-facing "
        "manifests were registered on public PyPI / npm with higher "
        "version numbers; victim builds that declared the public "
        "index as an extra automatically pulled the attacker's "
        "package on the next install.",
        "PyTorch ``torchtriton`` (December 2022): a typosquat name "
        "on PyPI's public index was preferred over the internal "
        "nightly build, exfiltrating SSH keys via a postinstall "
        "step. Single-index installations were unaffected.",
    ),
    exploit_example=(
        "# Vulnerable: pip queries BOTH indexes for every package\n"
        "# name and picks the highest version. ``acme-internal`` is\n"
        "# an internal-only package the org publishes to the\n"
        "# private index. An attacker registers ``acme-internal``\n"
        "# on public PyPI with version ``99.0.0``; the next ``pip\n"
        "# install`` resolves to the attacker's wheel because\n"
        "# 99.0.0 > 1.2.3. This is the Birsan dependency-confusion\n"
        "# class — Apple / Microsoft / Yelp / Tesla / Uber all paid\n"
        "# Birsan a bounty for this exact shape.\n"
        "# requirements.txt\n"
        "--index-url https://internal-pypi.example.com/simple\n"
        "--extra-index-url https://pypi.org/simple\n"
        "acme-internal==1.2.3\n"
        "requests==2.31.0\n"
        "\n"
        "# Safe: single index. Configure the internal proxy to\n"
        "# transparently mirror PyPI for any name not published\n"
        "# internally; pip then resolves every package against ONE\n"
        "# source whose name allow-list the operator controls.\n"
        "# requirements.txt\n"
        "--index-url https://internal-pypi.example.com/simple\n"
        "acme-internal==1.2.3\n"
        "requests==2.31.0"
    ),
)


def check(rf: RequirementsFile) -> Finding:
    values = get_option_values(rf, "--extra-index-url")
    if not values:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=rf.path,
            description="No --extra-index-url declared.",
            recommendation=RULE.recommendation, passed=True,
        )
    locations: list[Location] = []
    idx = rf.text.find("--extra-index-url")
    if idx >= 0:
        line_no = rf.text[:idx].count("\n") + 1
        locations.append(Location(
            path=rf.path, start_line=line_no, end_line=line_no,
        ))
    desc = (
        f"{len(values)} --extra-index-url entries declared: "
        f"{', '.join(values[:3])}"
        f"{'…' if len(values) > 3 else ''}. pip queries every "
        f"declared index for every package name and picks the "
        f"highest version, an attacker who registers your internal "
        f"name on PyPI wins."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
    )
