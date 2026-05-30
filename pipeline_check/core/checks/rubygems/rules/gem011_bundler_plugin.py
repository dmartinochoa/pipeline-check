"""GEM-011. Gemfile registers a Bundler plugin that runs at install time."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GemFile

RULE = Rule(
    id="GEM-011",
    title="Gemfile registers a Bundler plugin that runs at install time",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-1"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-94"),
    recommendation=(
        "Treat every ``plugin`` directive as build-time code that "
        "runs before any application code. Bundler executes a "
        "plugin's ``plugins.rb`` during ``bundle install`` (and on "
        "``bundle plugin install``), so a compromised plugin "
        "release runs arbitrary Ruby with the installer's "
        "privileges (CI runner write access, any credentials in the "
        "environment) before your app, your tests, or any sandbox "
        "exist. Pin the plugin to an immutable source: a "
        "``git:`` + ``ref:`` SHA, or an exact ``version:``, never a "
        "floating version or a branch. Audit the plugin's source "
        "before adding it, vendor it where practical, and drop any "
        "``plugin`` line whose generator the build no longer needs. "
        "A plugin you don't control is strictly more dangerous than "
        "an ordinary gem dependency."
    ),
    docs_note=(
        "Fires on any ``plugin \"name\"`` directive in the Gemfile. "
        "Bundler plugins are not gems: their ``plugins.rb`` runs at "
        "install time, before the lockfile-pinned application "
        "dependencies are even resolved, which is why GEM-010 "
        "(dynamic gem-list resolution) explicitly does not match "
        "``plugin``. The Ruby analog of an npm install script "
        "(NPM lifecycle) or a Maven build-time plugin (MVN-015).\n\n"
        "Single regex over the raw Gemfile text; comment lines are "
        "skipped. The directive name and any pinned source / "
        "version are surfaced so a reviewer can confirm the plugin "
        "is pinned and trusted."
    ),
    known_fp=(
        "Repos that legitimately use a trusted, pinned Bundler "
        "plugin (``bundler-audit`` via plugin, a vendored internal "
        "plugin) will fire. The directive is not itself a "
        "vulnerability; suppress per line with a rationale once the "
        "plugin source is confirmed pinned and reviewed.",
    ),
    incident_refs=(
        "Install-time code execution is the class behind the npm "
        "``postinstall`` supply-chain attacks and the xz-utils "
        "build-step backdoor. A Bundler plugin is the same primitive "
        "in the Ruby ecosystem: code that runs during dependency "
        "installation, before the consumer inspects anything.",
    ),
    exploit_example=(
        "# Vulnerable: a plugin runs at bundle install time.\n"
        "source \"https://rubygems.org\"\n"
        "plugin \"some-bundler-plugin\"\n"
        "gem \"rails\", \"7.0.4\"\n"
        "\n"
        "# Attack: the plugin author (or whoever took over the\n"
        "# account) ships a release whose plugins.rb shells out to\n"
        "# exfiltrate the CI runner's environment. `bundle install`\n"
        "# runs it before rails is ever loaded; nothing in the app\n"
        "# or its tests gets a chance to catch it.\n"
        "\n"
        "# Safe: pin the plugin to an immutable git ref (or drop it).\n"
        "plugin \"some-bundler-plugin\", "
        "git: \"https://github.com/org/plugin\", "
        "ref: \"a1b2c3d4e5f6...\""
    ),
)


# A ``plugin "name"`` / ``plugin 'name'`` directive, capturing the
# name and the remainder of the line (for source / version reporting).
_PLUGIN_RE = re.compile(
    r"^[\t ]*plugin\s+['\"](?P<name>[^'\"]+)['\"]"
    r"(?P<rest>[^\n#]*)",
    re.MULTILINE,
)


def _line_of(text: str, idx: int) -> int:
    return text[:idx].count("\n") + 1


def check(pom: GemFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m in _PLUGIN_RE.finditer(pom.text):
        # Skip a match that sits inside a comment line.
        line_start = pom.text.rfind("\n", 0, m.start()) + 1
        prefix = pom.text[line_start:m.start()]
        if "#" in prefix:
            continue
        name = m.group("name")
        rest = m.group("rest").strip().rstrip(",").strip()
        label = f"{name}{(' (' + rest + ')') if rest else ''}"
        offenders.append(label)
        locations.append(Location(
            path=pom.path,
            start_line=_line_of(pom.text, m.start()),
            end_line=_line_of(pom.text, m.start()),
        ))
    passed = not offenders
    desc = (
        "Gemfile registers no Bundler plugins."
        if passed else
        f"{len(offenders)} Bundler plugin(s) run at install time: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Each plugin's "
        f"plugins.rb executes during ``bundle install`` with the "
        f"installer's privileges; pin every plugin to an immutable "
        f"source and confirm it's trusted."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
