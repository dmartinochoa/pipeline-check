"""GOMOD-008. go.mod replace directive points to a module without a version pin."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GoModFile

RULE = Rule(
    id="GOMOD-008",
    title="go.mod replace directive points to a module without a version pin",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-1357"),
    recommendation=(
        "Add an explicit version on the right side of every "
        "``replace`` directive that targets a module path. The "
        "fully-qualified form is "
        "``replace <orig> => <new> <version>``. Without the "
        "trailing version, ``go mod tidy`` resolves the "
        "replacement to whatever the default branch of the "
        "replacement module currently points at, which mirrors "
        "the mutable-ref class of risk GOMOD-002 catches for "
        "local-path replacements but at the module-coordinate "
        "layer.\n\n"
        "Example:\n\n"
        "    # Vulnerable\n"
        "    replace github.com/foo/bar => github.com/myorg/bar\n"
        "    # Safe\n"
        "    replace github.com/foo/bar => github.com/myorg/bar v1.2.3"
    ),
    docs_note=(
        "Fires on ``replace`` directives where the right side "
        "names a module path (``github.com/...``) but omits the "
        "version. Local-path replacements (``=> ../local``) are "
        "GOMOD-002's surface and are skipped here; "
        "module-to-module replacements with a version pin "
        "(``=> foo v1.2.3``) pass this rule.\n\n"
        "The check exists because Go's module resolution "
        "treats a versionless replace as ``go get`` does — it "
        "fetches the default branch's tip. Force-pushes to that "
        "branch redirect every consumer's build, mirroring the "
        "tag-following pattern CARGO-002 catches for cargo "
        "dependencies."
    ),
    known_fp=(
        "Some vendoring tools (older versions of ``dep`` migrating "
        "to modules) emit versionless replaces during a "
        "conversion pass. The fix is to run ``go mod tidy`` "
        "against a modern toolchain, which resolves the "
        "replacement to a concrete version. Suppress per "
        "directive while the migration is in flight.",
    ),
    incident_refs=(
        "Pattern of versionless replaces shipping in commits "
        "from contributors using older Go toolchains; ``go mod "
        "tidy`` rewrites them once the project upgrades to "
        "1.21+, but the unmigrated form lives in repo history "
        "until then.",
    ),
    exploit_example=(
        "// Vulnerable: replacement module without version pin.\n"
        "module example.com/myapp\n"
        "go 1.22\n"
        "require github.com/upstream/lib v1.2.3\n"
        "replace github.com/upstream/lib => github.com/myorg/lib\n"
        "\n"
        "// Attack: a maintainer of github.com/myorg/lib\n"
        "// force-pushes the default branch with a malicious\n"
        "// commit. The next ``go build`` against this go.mod\n"
        "// resolves the replace to the new HEAD, fetching\n"
        "// the malicious code transparently.\n"
        "\n"
        "// Safe: pin the replacement version.\n"
        "replace github.com/upstream/lib => github.com/myorg/lib v1.2.3-patched.1"
    ),
)


def check(pom: GoModFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for replace in pom.replaces:
        if replace.is_local:
            continue  # GOMOD-002 owns local-path replacements
        if replace.new_version:
            continue  # version-pinned, safe
        offenders.append(
            f"{replace.orig_path} => {replace.new_path}"
        )
        locations.append(Location(
            path=pom.path,
            start_line=replace.line_no, end_line=replace.line_no,
        ))
    passed = not offenders
    desc = (
        "Every cross-module replace directive pins to a version."
        if passed else
        f"{len(offenders)} replace directive(s) target a module "
        f"path without a version pin: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Each one resolves "
        f"to the replacement module's default branch on the next "
        f"build."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
