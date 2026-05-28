"""GEM-006. Gemfile requires a known-compromised gem version."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from .._compromised_gems import lookup
from ..base import GemFile

RULE = Rule(
    id="GEM-006",
    title="Gemfile requires a known-compromised gem version",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357", "CWE-829"),
    recommendation=(
        "Bump the offending gem to a patched version (named in "
        "the cited advisory) and refresh Gemfile.lock with "
        "``bundle update <gemname>``. If the advisory has no "
        "patched release, pin to the last known-good version "
        "and add a follow-up TODO to replace or remove the gem. "
        "After the bump, re-run the scan; if GEM-006 still "
        "fires, an indirect dependency is pulling the bad "
        "version back in — use ``bundle why <gemname>`` (Bundler "
        "3.0+) or ``bundle viz`` to find the path."
    ),
    docs_note=(
        "Reads the curated registry under "
        "``pipeline_check.core.checks.rubygems._compromised_gems`` "
        "(table of ``(gem, malicious_versions, advisory)`` "
        "entries) and fires when any ``gem`` entry — direct "
        "Gemfile dependency — matches. The registry is "
        "hand-curated and append-only; adding a new entry is a "
        "one-line table edit plus the citing advisory in the "
        "commit message.\n\n"
        "Mirrors NPM-006 / PYPI-005 / MVN-006 / NUGET-005 / "
        "GOMOD-006 / CARGO-006 / COMPOSER-007 and shares the "
        "version-matching primitive "
        "(``_primitives.compromised.match_version``). The "
        "version literal compared is whatever the manifest "
        "declares; operators wanting *resolved* version "
        "coverage should also commit Gemfile.lock (GEM-001), at "
        "which point the lockfile-side audit can lift the "
        "matching from manifest to resolved-graph."
    ),
    known_fp=(
        "A manifest may legitimately pin a known-bad version "
        "because the consumer has applied a downstream patch or "
        "sandbox. The rule still fires; suppress per gem with a "
        "one-line rationale naming the patch.",
    ),
    incident_refs=(
        "rest-client 1.6.10-1.6.13 (CVE-2019-15224): "
        "maintainer-token compromise published gems that "
        "exfiltrated env vars and opened a remote shell. "
        "strong_password 0.0.7 (CVE-2019-13354): backdoored "
        "release ran eval(open(...).read) on a remote Pastebin "
        "payload at boot. Future entries follow the same shape: "
        "append ``(gem, version, advisory)`` to "
        "_compromised_gems.py with the citing advisory in the "
        "commit message.",
    ),
    exploit_example=(
        "# Vulnerable: pinned to a yanked / compromised version.\n"
        "gem \"rest-client\", \"1.6.13\"\n"
        "\n"
        "# Risk: CVE-2019-15224. The 1.6.10..1.6.13 line was\n"
        "# pushed by an attacker who took over the maintainer\n"
        "# account; it exfiltrated env vars and opened a remote\n"
        "# shell on every consumer's machine.\n"
        "\n"
        "# Safe: bump to a patched release.\n"
        "gem \"rest-client\", \"2.1.0\"\n"
        "# Then ``bundle update rest-client`` to refresh\n"
        "# Gemfile.lock."
    ),
)


def check(pom: GemFile) -> Finding:
    offenders: list[tuple[str, str, str]] = []
    locations: list[Location] = []
    for dep in pom.dependencies:
        if dep.version is None:
            continue
        # Strip operators and bare ``=`` so ``"= 1.6.13"`` matches
        # the registry literal ``"1.6.13"``.
        spec = dep.version.strip()
        for op in ("~>", ">=", "<=", "!=", "=", ">", "<"):
            if spec.startswith(op):
                spec = spec[len(op):].strip()
        entry = lookup(dep.name, spec)
        if entry is None:
            continue
        offenders.append((dep.name, dep.version, entry.advisory))
        locations.append(Location(
            path=pom.path,
            start_line=dep.line_no, end_line=dep.line_no,
        ))
    passed = not offenders
    if passed:
        desc = (
            "No Gemfile dependency matches the curated "
            "compromised-gem registry."
        )
    else:
        rendered = ", ".join(
            f"{name}@{ver} ({advisory})"
            for name, ver, advisory in offenders[:5]
        )
        suffix = "…" if len(offenders) > 5 else ""
        desc = (
            f"{len(offenders)} gem(s) match a known-compromised "
            f"registry entry: {rendered}{suffix}. Bump to a "
            f"patched version named in the cited advisory and "
            f"refresh Gemfile.lock."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
