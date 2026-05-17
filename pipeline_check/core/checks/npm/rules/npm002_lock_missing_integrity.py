"""NPM-002, ``package-lock.json`` entry missing ``integrity`` SHA."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmLock, iter_lock_packages

RULE = Rule(
    id="NPM-002",
    title="package-lock.json entry missing integrity hash",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-9"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-353", "CWE-494"),
    recommendation=(
        "Regenerate the lockfile with ``npm install`` against a "
        "registry that returns SRI integrity hashes (the default "
        "``https://registry.npmjs.org``). Every entry should carry "
        "an ``integrity`` field like ``sha512-...`` keyed off the "
        "tarball contents. A missing hash means npm has nothing to "
        "compare against at install time, so a registry that swaps "
        "the tarball mid-flight (cache poisoning, MITM, malicious "
        "mirror) ships arbitrary code without detection."
    ),
    docs_note=(
        "Walks every entry under ``packages`` (npm 7+ schema "
        "``lockfileVersion: 2`` / ``3``) or ``dependencies`` (npm 6 "
        "schema ``lockfileVersion: 1``) and flags records missing "
        "an ``integrity`` field that has a ``resolved`` URL (a "
        "fetched tarball without integrity is the unsafe case). "
        "Skips link entries (``link: true``) and workspace entries, "
        "which have no tarball to hash. Local file dependencies "
        "(``file:`` specs) are caught by NPM-003. Complements "
        "NPM-003 (non-registry source URL); NPM-002 is the case "
        "where the source URL exists but the verification anchor "
        "doesn't."
    ),
    known_fp=(
        "Lockfiles produced by old npm versions (npm < 5) wrote "
        "``sha1-...`` integrity strings that some downstream tools "
        "regenerate as missing. The fix is the same in both cases: "
        "regenerate with a current npm version against a hash-"
        "providing registry.",
    ),
)


def check(lock: NpmLock) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for install_path, record in iter_lock_packages(lock):
        # Linked workspace entries and bundled packages have no tarball
        # to hash, so they legitimately lack ``integrity``.
        if record.get("link") is True:
            continue
        resolved = record.get("resolved")
        if not isinstance(resolved, str) or not resolved.strip():
            # No tarball URL — handled by NPM-003 if non-registry.
            continue
        integrity = record.get("integrity")
        if isinstance(integrity, str) and integrity.strip():
            continue
        offenders.append(install_path)
        # Best-effort: line of the install-path key in the file.
        idx = lock.text.find(f'"{install_path}"')
        line_no = lock.text[:idx].count("\n") + 1 if idx >= 0 else 1
        locations.append(Location(
            path=lock.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "Every resolved package in the lockfile carries an integrity "
        "hash."
        if passed else
        f"{len(offenders)} lockfile entries missing ``integrity``: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. An attacker who can "
        f"swap the upstream tarball ships arbitrary code on the "
        f"next install."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=lock.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
