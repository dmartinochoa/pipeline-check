"""PYPI-008, direct dependency was published within the cooldown window."""
from __future__ import annotations

import datetime as _dt
import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PypiContext, RequirementsFile, iter_specs

RULE = Rule(
    id="PYPI-008",
    title="Direct dependency was published within the cooldown window",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-494"),
    recommendation=(
        "Either skip the just-published version (pin to the last "
        "release older than the cooldown window) or wait until the "
        "cooldown has elapsed before bumping the requirements file. "
        "Most publisher-account compromises on PyPI (``ctx`` 2022, "
        "``requests-darwin-lite`` 2024, ``ultralytics`` 2024, the "
        "``rspack`` / ``vant`` / ``nx`` / ``@ctrl/*`` campaigns) "
        "are detected and yanked from the index within hours-to-"
        "days of publication; holding back N days converts a "
        "publisher-compromise window into a vulnerability-"
        "disclosure window where either the maintainer rotates "
        "the malicious version off the index or the security "
        "community files an advisory that PYPI-006 can match "
        "against."
    ),
    docs_note=(
        "Network-dependent: needs ``--resolve-remote`` to populate "
        "the per-package publish timestamps from the PyPI JSON API "
        "(``https://pypi.org/pypi/<name>/json``). Walks every "
        "exact-version requirement (``foo==1.2.3``) and flags ones "
        "whose newest file record landed within the cooldown "
        "window (default 7 days). Range specs (``foo>=1.2``, "
        "``foo~=1.2``), unpinned specs, VCS / URL / editable "
        "lines, and dist-tag-style specs are out of scope — the "
        "cooldown applies to a specific version literal because "
        "that's what the maintainer chose to pin. When "
        "``--resolve-remote`` is off or the registry can't be "
        "reached, the rule passes silently so the absence of the "
        "network path doesn't trip CI."
    ),
    known_fp=(
        "Pre-release versions (``foo==1.0.0rc1``) are often "
        "freshly published; the cooldown applies to them too "
        "because pre-release tags have been used as carriers in "
        "real compromises. Suppress per-resource via "
        "``--ignore-file`` when a release-train workflow "
        "legitimately pins to a same-day RC.",
        "Same-day patch upgrades from a maintainer the team "
        "directly trusts (e.g. a vendored fork the team owns) "
        "are flagged. Suppress per-resource — the cooldown is a "
        "default-safe gate, not a hard rule.",
    ),
    incident_refs=(
        "ctx package compromise (May 2022): the abandoned ``ctx`` "
        "package was claimed by an attacker and republished with "
        "an env-var exfiltration payload. The malicious 0.2.x "
        "versions stayed live until PyPI yanked them ~24h later. "
        "Consumers who held a 7-day cooldown caught the takedown "
        "before installing.",
        "requests-darwin-lite 2.27.1 "
        "([GHSA-7gjg-3qcj-9jvg](https://github.com/advisories/GHSA-7gjg-3qcj-9jvg), "
        "May 2024): typosquat-flavored package whose wheel embedded "
        "the Geneva malware framework. The malicious version was "
        "live for less than 48 hours before disclosure and yank.",
    ),
    exploit_example=(
        "# Vulnerable: pinning to ``shiny-lib==17.0.99`` 2 hours\n"
        "# after its publication is exactly the window in which\n"
        "# publisher-account compromises live. PyPI yanks malicious\n"
        "# versions within hours-to-days once flagged; ``ctx``,\n"
        "# ``requests-darwin-lite``, and ``ultralytics`` all\n"
        "# followed this shape. The next ``pip install`` after the\n"
        "# malicious publish installs the wheel before the takedown.\n"
        "# requirements.txt\n"
        "--require-hashes\n"
        "shiny-lib==17.0.99 \\\n"
        "    --hash=sha256:bad1234bad1234bad1234bad1234bad1234bad1234bad1234bad1234bad1234b\n"
        "# ``17.0.99`` was published 2 hours ago\n"
        "\n"
        "# Safe: pin to the most recent release that's older than\n"
        "# the cooldown window. ``pipeline_check --pipeline pypi\n"
        "# --resolve-remote`` queries the PyPI JSON API for\n"
        "# publish timestamps and surfaces anything inside the 7-\n"
        "# day window. Hold the bump until the cooldown elapses,\n"
        "# or skip the freshly-pushed version entirely.\n"
        "# requirements.txt\n"
        "--require-hashes\n"
        "shiny-lib==17.0.98 \\\n"
        "    --hash=sha256:c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff\n"
        "# ``17.0.98`` was published 3 weeks ago"
    ),
)


# Match an exact-version PyPI requirement: ``name==version`` with
# optional ``[extras]`` and an optional ``; markers`` suffix that
# we strip before extracting. Returns ``(name, version)`` for an
# exact pin, ``None`` otherwise. Mirrors PYPI-006's
# ``_NAME_VERSION_RE`` so the cooldown gate and the compromised-
# package gate agree on what counts as a "specific version".
_NAME_VERSION_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)"
    r"(?:\[[^\]]*\])?"                # optional ``[extras]``
    r"\s*==\s*([^;\s]+)"
)


def _now() -> _dt.datetime:
    """Indirection so tests can freeze wall-clock time via monkeypatch."""
    return _dt.datetime.now(_dt.UTC)


def _exact_spec(body: str) -> tuple[str, str] | None:
    m = _NAME_VERSION_RE.match(body)
    if m is None:
        return None
    return m.group(1).strip().lower(), m.group(2).strip()


def _within_cooldown(
    publish_time: _dt.datetime,
    now: _dt.datetime,
    cooldown_days: int,
) -> bool:
    """True iff *publish_time* is younger than *cooldown_days* ago.

    Both inputs normalized to UTC tz-aware; a tz-naive *now* (test
    fixture default) is treated as UTC.
    """
    if now.tzinfo is None:
        now = now.replace(tzinfo=_dt.UTC)
    if publish_time.tzinfo is None:
        publish_time = publish_time.replace(tzinfo=_dt.UTC)
    return (now - publish_time) < _dt.timedelta(days=cooldown_days)


def check(
    rf: RequirementsFile, ctx: PypiContext | None = None,
) -> Finding:
    publish_times: dict[str, dict[str, _dt.datetime]] = (
        ctx.publish_times if ctx is not None else {}
    )
    cooldown_days = 7
    if not publish_times:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=rf.path,
            description=(
                "No publish-time metadata available (re-run with "
                "``--resolve-remote`` to enable cooldown analysis)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    now = _now()
    offenders: list[str] = []
    locations: list[Location] = []
    for line in iter_specs(rf):
        parsed = _exact_spec(line.body)
        if parsed is None:
            continue
        name, version = parsed
        per_version = publish_times.get(name)
        if not per_version:
            continue
        published = per_version.get(version)
        if published is None:
            continue
        if not _within_cooldown(published, now, cooldown_days):
            continue
        # Normalize so the subtraction is tz-aware.
        published_aware = (
            published if published.tzinfo is not None
            else published.replace(tzinfo=_dt.UTC)
        )
        age = (now - published_aware).days
        offenders.append(
            f"{name}=={version} "
            f"(published {age}d ago, cooldown {cooldown_days}d)"
        )
        locations.append(Location(
            path=rf.path, start_line=line.line_no, end_line=line.line_no,
        ))

    passed = not offenders
    desc = (
        f"Every exact-pin requirement was published more than "
        f"{cooldown_days} day(s) ago."
        if passed else
        f"{len(offenders)} requirement(s) were published within the "
        f"{cooldown_days}-day cooldown window: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A publisher-account "
        f"compromise typically gets caught and yanked within "
        f"hours-to-days; holding back converts the window into a "
        f"vulnerability-disclosure window."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
