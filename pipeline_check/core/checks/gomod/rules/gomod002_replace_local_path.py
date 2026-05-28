"""GOMOD-002. go.mod replace directive points to a local filesystem path."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GoModFile

RULE = Rule(
    id="GOMOD-002",
    title="go.mod replace directive points to a local filesystem path",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Local-path replacements (``replace foo/bar => ../local/copy``) "
        "are a dev-loop convenience: they bypass the module proxy + "
        "checksum database and pull the dependency from the working "
        "tree instead. Shipping one into a committed ``go.mod`` "
        "means CI builds either fail (the path doesn't exist on the "
        "runner) or — worse — silently use whatever directory tree "
        "happens to live at that path inside the runner image. "
        "Either remove the directive entirely (the normal "
        "go-proxy fetch will reach the real upstream), or split "
        "the local path into a separate ``go.work`` file (the "
        "Go workspace mechanism designed for multi-module dev "
        "checkouts) that you do NOT commit. ``go.work`` overrides "
        "``go.mod`` replaces locally without leaking into the "
        "committed manifest."
    ),
    docs_note=(
        "Fires on any ``replace`` directive whose right-hand side "
        "resolves to a filesystem path: starts with ``./``, ``../``, "
        "``/``, or a Windows drive letter (``C:\\``). Module-to-"
        "module replacements (``replace foo => bar v1.2.3``) are "
        "a separate concern handled by GOMOD-003. Local-path "
        "replacements in a committed go.mod are a common artifact "
        "of a contributor's dev loop that was never reverted "
        "before merging.\n\n"
        "A local-path replacement breaks reproducibility (every "
        "runner needs the path to exist), bypasses the module "
        "proxy (the replacement isn't fetched through GOPROXY), "
        "and bypasses the checksum database (``go mod verify`` "
        "skips local-path replacements). All three failure modes "
        "stack so a local-path replace is effectively an "
        "unauditable supply-chain blank check."
    ),
    known_fp=(
        "Vendored monorepo subprojects sometimes legitimately use "
        "``replace ./vendored/<pkg>`` to pin a fork inside the "
        "repo. The modern equivalent is a ``go.work`` file or a "
        "module-to-module replace at a tagged fork; suppress per "
        "directive if the vendored layout predates go.work "
        "(introduced in Go 1.18).",
    ),
    incident_refs=(
        "Common contributor-laptop leakage: ``replace "
        "github.com/myorg/mylib => ../mylib-fork`` lands in a PR "
        "because the local dev loop pointed at a sibling clone, "
        "the test suite passed on the contributor's machine, and "
        "CI's lenient module resolution swallowed the missing "
        "path. Production builds end up running the prior version "
        "of mylib (the one cached in the module proxy) while the "
        "contributor believed they were testing against their "
        "fork.",
    ),
    exploit_example=(
        "// Vulnerable: replace directive overrides an upstream\n"
        "// module with a local-path copy.\n"
        "module example.com/myapp\n"
        "go 1.22\n"
        "require github.com/myorg/mylib v1.0.0\n"
        "replace github.com/myorg/mylib => ../mylib-fork\n"
        "\n"
        "// Attack scenario: a contractor with write access on the\n"
        "// build runner edits /opt/build/mylib-fork/. The next CI\n"
        "// build pulls the modified code without any module-proxy\n"
        "// fetch, without any go.sum hash check, and without any\n"
        "// audit-log trail tying the change to a published\n"
        "// version. Indistinguishable from a normal build to\n"
        "// every static audit downstream.\n"
        "\n"
        "// Safe: remove the replace. Use a go.work file (not\n"
        "// committed) for local dev overrides:\n"
        "//   go work init ./myapp ../mylib-fork\n"
        "// go.work is honored locally and ignored by CI."
    ),
)


def check(pom: GoModFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for replace in pom.replaces:
        if not replace.is_local:
            continue
        offenders.append(
            f"{replace.orig_path} => {replace.new_path}"
        )
        locations.append(Location(
            path=pom.path,
            start_line=replace.line_no,
            end_line=replace.line_no,
        ))
    passed = not offenders
    desc = (
        "No local-path replace directives in go.mod."
        if passed else
        f"{len(offenders)} local-path replace directive(s): "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Local-path "
        f"replacements bypass the module proxy and the checksum "
        f"database, so builds are non-reproducible and the "
        f"replaced module isn't audit-trail-tied to any "
        f"published version."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
