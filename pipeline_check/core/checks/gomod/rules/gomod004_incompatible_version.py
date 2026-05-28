"""GOMOD-004. Direct require pinned to a +incompatible version."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GoModFile, is_incompatible_version, iter_direct_requires

RULE = Rule(
    id="GOMOD-004",
    title="Direct require pinned to a +incompatible version",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1395",),
    recommendation=(
        "The ``+incompatible`` suffix is a Go-module-system "
        "backward-compatibility band-aid: it lets a module tagged "
        "``v2.0.0`` (or higher) be imported without the standard "
        "``/v2`` module-path suffix that semantic import "
        "versioning requires. The module gets pulled, but several "
        "of the guarantees the module system normally enforces "
        "(major-version isolation, automatic-upgrade safety, the "
        "ability to depend on multiple major versions simultaneously) "
        "are turned off for it.\n\n"
        "Migrate the consumer to a real ``/v2``-suffixed import "
        "path when the upstream maintainer ships one (most active "
        "Go projects have done this for years; a stuck "
        "``+incompatible`` usually means the dep is unmaintained "
        "or the consumer hasn't been updated). Where the upstream "
        "genuinely refuses to add the suffix (some "
        "infrastructure-y projects deliberately stay on "
        "``+incompatible``), accept the limitation explicitly via "
        "a suppression rationale that names the upstream policy."
    ),
    docs_note=(
        "Fires on any direct require whose version ends in "
        "``+incompatible``. Indirect requires are exempt; they "
        "rolled up from a transitive dep's tagging policy and the "
        "consumer can't directly fix them without changing the "
        "transitive dep itself. The rule is informational-leaning "
        "MEDIUM rather than HIGH: ``+incompatible`` is a posture / "
        "maintenance signal, not a direct exploit primitive, but "
        "modules that have shipped ``v2.0.0`` without a "
        "module-path bump are statistically over-represented "
        "among unmaintained or single-maintainer projects, which "
        "is its own supply-chain exposure."
    ),
    known_fp=(
        "A small set of canonical infra modules (``github.com/"
        "Sirupsen/logrus`` historically, before it moved to "
        "``github.com/sirupsen/logrus``; some etcd client "
        "lineages) shipped at ``+incompatible`` versions on "
        "purpose because the maintainer chose not to bump the "
        "module path. Suppress per directive when the upstream "
        "policy is known and stable.",
    ),
    incident_refs=(
        "Pattern of long-stuck +incompatible deps in Go monorepos "
        "where the upstream maintainer abandoned the project at "
        "the v2.0.0+ tag. Consumers stay on the +incompatible "
        "version indefinitely; no patches roll out because the "
        "module is effectively read-only. The rule surfaces the "
        "drift class so an audit cycle can plan migration off "
        "the unmaintained dependency.",
    ),
    exploit_example=(
        "// Vulnerable: stuck on a +incompatible upstream that\n"
        "// hasn't shipped a patch in 4 years.\n"
        "module example.com/myapp\n"
        "go 1.22\n"
        "require github.com/example/unmaintained v3.7.1+incompatible\n"
        "\n"
        "// Risk surface: a published CVE against\n"
        "// github.com/example/unmaintained v3.x has no patched\n"
        "// release; the project never shipped a /v3-suffixed\n"
        "// module path so no version-bump fix is even possible\n"
        "// without forking. The consumer either ships the\n"
        "// vulnerability or eats the migration cost.\n"
        "\n"
        "// Safe: when the upstream offers a proper /v3 import\n"
        "// path, switch to it:\n"
        "//   require github.com/example/maintained/v3 v3.7.2\n"
        "// If the upstream is unmaintained, fork-and-patch, then\n"
        "// pin the fork under its own module path; the\n"
        "// +incompatible dep no longer needs to exist."
    ),
)


def check(pom: GoModFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for req in iter_direct_requires(pom):
        if not is_incompatible_version(req.version):
            continue
        offenders.append(f"{req.path} {req.version}")
        locations.append(Location(
            path=pom.path,
            start_line=req.line_no,
            end_line=req.line_no,
        ))
    passed = not offenders
    desc = (
        "No direct require uses a +incompatible version."
        if passed else
        f"{len(offenders)} direct require(s) pinned to "
        f"+incompatible: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The module is "
        f"published at v2+ without the matching /vN import-path "
        f"suffix; several module-system guarantees are turned off "
        f"for it."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
