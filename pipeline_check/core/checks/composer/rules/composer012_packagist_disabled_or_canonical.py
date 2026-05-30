"""COMPOSER-012. Packagist disabled or a custom repo marked canonical."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ComposerFile

RULE = Rule(
    id="COMPOSER-012",
    title="composer.json disables Packagist or marks a custom repo canonical",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Keep Packagist enabled and avoid marking a custom "
        "repository canonical unless you fully trust it for every "
        "coordinate it can serve. Disabling Packagist with "
        "``{\"packagist.org\": false}`` (or the legacy "
        "``\"packagist\": false``), or setting "
        "``\"canonical\": true`` on a custom repo, lets that "
        "single source answer for any package name, including "
        "ones it should not own. That is the broadest form of the "
        "dependency-confusion surface COMPOSER-011 catches per "
        "entry."
    ),
    docs_note=(
        "Fires on two exact shapes inside ``repositories``: a "
        "Packagist disable (``{\"packagist.org\": false}`` or "
        "``{\"packagist\": false}``), or a custom repo with "
        "``\"canonical\": true``. Both hand package resolution to "
        "a non-default source for the names it provides. Exact "
        "key / value reads keep this the lowest-false-positive "
        "rule of the repository set. Companion to COMPOSER-011 "
        "(custom vcs / package repo)."
    ),
    known_fp=(),
    incident_refs=(
        "Disabling Packagist or marking a mirror canonical is the "
        "documented Composer way to force every dependency "
        "through one source. When that source is attacker-owned, "
        "the whole graph resolves through it, the worst-case "
        "version of dependency confusion.",
    ),
    exploit_example=(
        "// Vulnerable: Packagist off, attacker mirror canonical.\n"
        "{\n"
        "  \"repositories\": [\n"
        "    {\n"
        "      \"type\": \"composer\",\n"
        "      \"url\": \"https://mirror.attacker/composer\",\n"
        "      \"canonical\": true\n"
        "    },\n"
        "    {\"packagist.org\": false}\n"
        "  ]\n"
        "}\n"
        "\n"
        "// Risk: every dependency resolves through the attacker\n"
        "// mirror, so any package can be served as a malicious\n"
        "// build.\n"
        "\n"
        "// Safe: leave Packagist enabled, no canonical override.\n"
        "{\n"
        "  \"repositories\": [\n"
        "    {\"type\": \"composer\", "
        "\"url\": \"https://mirror.internal/composer\"}\n"
        "  ]\n"
        "}"
    ),
)


_DISABLE_KEYS: tuple[str, ...] = ("packagist.org", "packagist")


def check(pom: ComposerFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for repo in pom.repositories:
        # ``{"packagist.org": false}`` disables the default source.
        # The repo loader keeps the raw object, so read the disable
        # keys directly.
        for key in _DISABLE_KEYS:
            if repo.raw.get(key) is False:
                offenders.append(f"{key} disabled")
                locations.append(Location(
                    path=pom.path,
                    start_line=repo.line_no, end_line=repo.line_no,
                ))
        if repo.raw.get("canonical") is True:
            where = repo.url or repo.type or "custom repository"
            offenders.append(f"canonical: {where}")
            locations.append(Location(
                path=pom.path,
                start_line=repo.line_no, end_line=repo.line_no,
            ))
    passed = not offenders
    if passed:
        desc = (
            "Packagist is enabled and no custom repository is "
            "marked canonical."
        )
    else:
        rendered = "; ".join(offenders[:3])
        suffix = "…" if len(offenders) > 3 else ""
        desc = (
            f"Package resolution is handed to a non-default "
            f"source: {rendered}{suffix}. Re-enable Packagist or "
            f"drop the canonical flag."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
