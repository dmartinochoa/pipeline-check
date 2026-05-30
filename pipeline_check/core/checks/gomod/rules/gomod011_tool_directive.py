"""GOMOD-011. go.mod ``tool`` directive pulls an executable build dependency."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GoModFile

RULE = Rule(
    id="GOMOD-011",
    title="go.mod tool directive pulls an executable build dependency",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-4"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Confirm every ``tool`` directive points at a module you "
        "trust to run at build time. The Go 1.24 ``tool`` directive "
        "promotes a module to a build-time executable that "
        "``go tool`` and ``go generate`` invoke directly, so the "
        "module's ``main`` runs with the build's privileges (CI "
        "runner write access, any mounted deploy keys / cloud "
        "credentials) before the application is ever built. Pin "
        "each tool module to an exact version on its ``require`` "
        "line (no floating range, no pseudo-version drift), keep "
        "the matching ``go.sum`` entries committed (GOMOD-001), and "
        "prefer vendoring a tool you can audit over pulling a fresh "
        "build each run. Drop any ``tool`` line that no longer "
        "corresponds to a generator the build actually needs."
    ),
    docs_note=(
        "Fires when ``go.mod`` declares one or more ``tool`` "
        "directives (single-line ``tool example.com/cmd/foo`` or "
        "the ``tool ( ... )`` block form, Go 1.24+). The directive "
        "is the module-graph analog of an npm ``postinstall`` "
        "script or a Maven build-time plugin (MVN-015): the named "
        "module's code executes during the build, not at "
        "application runtime, so a compromised tool release runs "
        "in CI before any runtime sandbox exists.\n\n"
        "This is a posture / visibility signal (MEDIUM), not proof "
        "of compromise. ``tool`` is a normal, useful feature; the "
        "rule surfaces the build-time-execution surface so a "
        "reviewer can confirm each entry is pinned and trusted. "
        "Tooling-heavy repos that legitimately register several "
        "generators will fire and can suppress with a rationale."
    ),
    known_fp=(
        "Repos that legitimately register code generators "
        "(``stringer``, ``mockgen``, ``protoc-gen-go``, "
        "``sqlc``) via ``tool`` will fire. The directive itself "
        "is not a vulnerability; suppress per file with a "
        "rationale once each tool module is confirmed pinned "
        "(GOMOD-001 / GOMOD-009) and trusted.",
    ),
    incident_refs=(
        "Build-time code execution is the class behind the "
        "xz-utils backdoor (the malicious payload ran from the "
        "build step, not the shipped library) and the recurring "
        "npm lifecycle-script attacks. The Go ``tool`` directive "
        "is the same surface expressed in the module graph: a "
        "poisoned tool release runs on every ``go generate`` "
        "before anyone inspects the output.",
    ),
    exploit_example=(
        "// Vulnerable: a tool module runs at build time.\n"
        "module example.com/myapp\n"
        "go 1.24\n"
        "tool example.com/x/gen\n"
        "require example.com/x/gen v1.2.0\n"
        "\n"
        "// Attack: example.com/x/gen ships a poisoned v1.2.1. A\n"
        "// developer (or CI) runs `go generate ./...`; the go\n"
        "// toolchain builds and runs gen's main(), which now\n"
        "// exfiltrates $GITHUB_TOKEN / cloud creds from the runner\n"
        "// environment. The generated output looks normal, so the\n"
        "// commit passes review.\n"
        "\n"
        "// Safe: pin the tool module to an exact, sum-verified\n"
        "// version, keep go.sum committed, and review the tool's\n"
        "// source before bumping it:\n"
        "//   tool example.com/x/gen\n"
        "//   require example.com/x/gen v1.2.0  // + go.sum entry"
    ),
)


def check(pom: GoModFile) -> Finding:
    if not pom.tools:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="go.mod declares no tool directives.",
            recommendation=RULE.recommendation, passed=True,
        )
    # Resolve each tool path to its require-pinned version (when one
    # exists) so the description names the concrete coordinate a
    # reviewer needs to audit.
    versions: dict[str, str] = {r.path: r.version for r in pom.requires}
    offenders: list[str] = []
    locations: list[Location] = []
    for tool in pom.tools:
        version = versions.get(tool.path)
        offenders.append(
            f"{tool.path}{(' ' + version) if version else ''}"
        )
        locations.append(Location(
            path=pom.path,
            start_line=tool.line_no, end_line=tool.line_no,
        ))
    desc = (
        f"{len(offenders)} tool directive(s) register build-time "
        f"executables: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Each runs during "
        f"``go generate`` / ``go tool`` with the build's "
        f"privileges; confirm every entry is pinned and trusted."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
    )
