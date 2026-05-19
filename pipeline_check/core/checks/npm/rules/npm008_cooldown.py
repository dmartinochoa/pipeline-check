"""NPM-008, direct dependency was published within the cooldown window."""
from __future__ import annotations

import datetime as _dt
import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmContext, NpmManifest, iter_manifest_dependencies

RULE = Rule(
    id="NPM-008",
    title="Direct dependency was published within the cooldown window",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-494"),
    recommendation=(
        "Either skip the just-published version (pin to the last "
        "release older than the cooldown window) or wait until the "
        "cooldown has elapsed before bumping the lockfile. Most "
        "publisher-account compromises (Shai-Hulud / TanStack / "
        "axios -> plain-crypto-js) are detected and yanked from "
        "the registry within hours-to-days of publication; "
        "holding back N days converts a publisher-compromise "
        "window into a vulnerability-disclosure window where "
        "either the publisher rotates the malicious version off "
        "the registry or the security community files an "
        "advisory you can match against NPM-006. Tune the cooldown "
        "via ``--npm-cooldown-days`` (default 7)."
    ),
    docs_note=(
        "Network-dependent: needs ``--resolve-remote`` to populate "
        "the per-package publish timestamps from "
        "``registry.npmjs.org``. Walks every direct dependency in "
        "``dependencies`` / ``devDependencies`` / ``peerDependencies`` "
        "/ ``optionalDependencies`` (transitive packages aren't "
        "covered, the cooldown applies to what *you* chose to bump). "
        "Lockfile entries are out of scope, the rule reasons about "
        "the manifest's pinned spec since that's what changes when "
        "a maintainer bumps a dep. When ``--resolve-remote`` is off "
        "or the registry can't be reached, the rule passes silently "
        "so the absence of the network path doesn't trip CI."
    ),
    known_fp=(
        "Pre-release versions (``foo@1.0.0-rc.1``) are often "
        "freshly published; the cooldown applies to them too "
        "because pre-release tags have been used as carriers in "
        "real compromises (see the @ctrl/* / nx campaigns). "
        "Suppress per-resource via ``--ignore-file`` when a "
        "release-train workflow legitimately bumps to a same-day "
        "RC.",
        "Same-day patch upgrades from a maintainer the team "
        "directly trusts (e.g. a vendored fork the team owns) "
        "are flagged. Suppress per-resource, the cooldown is a "
        "default-safe gate, not a hard rule.",
    ),
    incident_refs=(
        "Shai-Hulud-class npm worm (Sep 2025): malicious versions "
        "published, detected, and yanked within 48h on multiple "
        "packages. Consumers who held a 7-day cooldown caught "
        "the takedown before the version hit their lockfile.",
        "@ctrl/tinycolor maintainer-account takeover (May 2024): "
        "the malicious versions stayed live for ~36 hours before "
        "GitHub Advisory and npm coordinated removal. Cooldown "
        "of any meaningful length would have skipped them.",
    ),
)


# Exact-version specs the cooldown rule can reason about. Range
# specs (``^1.2.3`` / ``~1.2.3`` / ``>=1.2.3``), dist-tag specs
# (``latest`` / ``next``), and source specs
# (``file:./local`` / ``workspace:*`` / ``git+https://...``) all
# return None — the cooldown applies to a *specific* version
# literal because that's what the maintainer chose to pin.
# Accepted prefixes: bare, ``=`` (npm exact-equality operator),
# ``v`` (legacy v-prefix common in older manifests).
_EXACT_SPEC_RE = re.compile(r"^(?:=|v)?(\d+\.\d+\.\d+(?:-[\w.+-]+)?)$")


def _exact_version_from_spec(spec: str) -> str | None:
    """Return the exact version literal if *spec* names one, else None.

    Accepts the npm ``=1.2.3`` / ``1.2.3`` / ``v1.2.3`` shapes.
    Anything range-flavored returns None — that's the rule's
    silent-pass path.
    """
    m = _EXACT_SPEC_RE.match(spec.strip())
    if m is None:
        return None
    return m.group(1)


def _within_cooldown(
    publish_time: _dt.datetime,
    now: _dt.datetime,
    cooldown_days: int,
) -> bool:
    """True iff *publish_time* is younger than *cooldown_days* ago.

    Both inputs are normalized to UTC tz-aware; a tz-naive *now*
    (test fixture default) is treated as UTC.
    """
    if now.tzinfo is None:
        now = now.replace(tzinfo=_dt.UTC)
    if publish_time.tzinfo is None:
        publish_time = publish_time.replace(tzinfo=_dt.UTC)
    delta = now - publish_time
    return delta < _dt.timedelta(days=cooldown_days)


def check(manifest: NpmManifest, ctx: NpmContext | None = None) -> Finding:
    publish_times: dict[str, dict[str, _dt.datetime]] = (
        ctx.publish_times if ctx is not None else {}
    )
    cooldown_days = 7
    if ctx is not None:
        # Future: expose --npm-cooldown-days from the CLI as a
        # context-level attr. For now the rule reads the constant
        # but the docs already promise the tunable so the wire-up
        # is a small follow-up.
        cooldown_days = int(
            getattr(ctx, "npm_cooldown_days", 7) or 7,
        )
    if not publish_times:
        # No metadata — silent pass. The rule's docs_note documents
        # the --resolve-remote dependency so users discover the
        # opt-in path; we don't fail CI just because they didn't
        # ask for network resolution.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "No publish-time metadata available (re-run with "
                "``--resolve-remote`` to enable cooldown analysis)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    now = _dt.datetime.now(_dt.UTC)
    offenders: list[str] = []
    locations: list[Location] = []
    for section, name, spec in iter_manifest_dependencies(manifest):
        version = _exact_version_from_spec(spec)
        if version is None:
            continue  # range spec — skip, not the rule's scope
        per_version = publish_times.get(name)
        if not per_version:
            continue  # registry didn't resolve this package
        published = per_version.get(version)
        if published is None:
            continue  # version isn't in the registry's metadata
        if not _within_cooldown(published, now, cooldown_days):
            continue
        age = (now.replace(tzinfo=_dt.UTC) - published).days
        offenders.append(
            f"{section}.{name}@{version} "
            f"(published {age}d ago, cooldown {cooldown_days}d)"
        )
        idx = manifest.text.find(f'"{name}"')
        line_no = manifest.text[:idx].count("\n") + 1 if idx >= 0 else 1
        locations.append(Location(
            path=manifest.path, start_line=line_no, end_line=line_no,
        ))

    passed = not offenders
    desc = (
        f"Every direct dependency was published more than "
        f"{cooldown_days} day(s) ago."
        if passed else
        f"{len(offenders)} direct dependency / dependencies were "
        f"published within the {cooldown_days}-day cooldown window: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A publisher-account "
        f"compromise typically gets caught and yanked within "
        f"hours-to-days; holding back converts the window into a "
        f"vulnerability-disclosure window."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
