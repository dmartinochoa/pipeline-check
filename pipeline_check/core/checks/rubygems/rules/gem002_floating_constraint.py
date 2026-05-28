"""GEM-002. ``gem`` entry uses a floating version constraint."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GemFile, is_floating_constraint

RULE = Rule(
    id="GEM-002",
    title="Gemfile gem entry uses a floating version constraint",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Replace the floating constraint with an exact pin "
        "(``gem \"rails\", \"7.0.4\"``). A committed Gemfile.lock "
        "pins resolved versions at install time and is the "
        "primary defense; tightening the manifest constraint is "
        "the secondary defense (makes the tolerated upgrade "
        "window in ``bundle update`` explicit). The tilde-arrow "
        "operator (``~>``), no-version-at-all "
        "(``gem \"rails\"``), and comparison operators "
        "(``>=``, ``< 8``, ``!=``) let ``bundle update`` pull "
        "in any release matching the range — including a "
        "poisoned patch release published moments before the "
        "build. Bundler's ``~>`` is also tighter than people "
        "remember (``\"~> 7.0\"`` is ``>= 7.0, < 8.0``, not "
        "``>= 7.0, < 7.1``)."
    ),
    docs_note=(
        "Fires when any ``gem`` entry's first version constraint "
        "is anything other than an exact triple (``X.Y.Z``). "
        "Tilde-arrow (``~> 7.0``), comparison (``>= 7``, "
        "``< 8``), no version at all, and ranges all trip the "
        "rule. The right operator response is either an exact "
        "pin or a committed Gemfile.lock (GEM-001)."
    ),
    known_fp=(
        "Rails, Rack, and a few core gems publish patches "
        "frequently and a strict exact-pin posture is "
        "operationally painful. Suppress per gem with a "
        "one-line rationale (``# pipeline_check:ignore GEM-002 "
        "- follows-rails-minor-track``) once the team has "
        "committed Gemfile.lock.",
    ),
    incident_refs=(
        "Repeated supply-chain pattern: ``gem \"rest-client\"`` "
        "(no version) in a CI image without Gemfile.lock pulls "
        "the latest release on every build. The 2019 "
        "rest-client compromise (CVE-2019-15224) propagated "
        "exactly this way for the time window before the gem "
        "was yanked.",
    ),
    exploit_example=(
        "# Vulnerable: floating constraint, no lockfile.\n"
        "source \"https://rubygems.org\"\n"
        "gem \"rails\", \"~> 7.0\"\n"
        "gem \"some_helper\"   # no version at all = most floating\n"
        "\n"
        "# Risk: ``bundle install`` (without lockfile) resolves\n"
        "# to whatever ~> 7.x release rubygems.org serves at\n"
        "# install time. A maintainer-account compromise that\n"
        "# publishes a 7.x release with a credential exfil\n"
        "# payload lands on the next CI build.\n"
        "\n"
        "# Safe: exact pin + Gemfile.lock.\n"
        "source \"https://rubygems.org\"\n"
        "gem \"rails\", \"7.0.4\"\n"
        "gem \"some_helper\", \"1.2.3\""
    ),
)


def check(pom: GemFile) -> Finding:
    offenders: list[tuple[str, str]] = []
    locations: list[Location] = []
    for dep in pom.dependencies:
        # Skip git / path entries — they're audited by GEM-005 and
        # GEM-008 instead. The version slot on those entries is
        # informational at most.
        if dep.is_git or dep.is_path:
            continue
        if is_floating_constraint(dep.version):
            display = dep.version if dep.version else "<unpinned>"
            offenders.append((dep.name, display))
            locations.append(Location(
                path=pom.path,
                start_line=dep.line_no, end_line=dep.line_no,
            ))
    passed = not offenders
    if passed:
        desc = "All gem entries use exact-pin constraints."
    else:
        rendered = ", ".join(
            f"{name} ({spec})" for name, spec in offenders[:5]
        )
        suffix = "…" if len(offenders) > 5 else ""
        desc = (
            f"{len(offenders)} gem entry / entries use a floating "
            f"constraint: {rendered}{suffix}. Replace with an exact "
            f"pin and commit Gemfile.lock."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
