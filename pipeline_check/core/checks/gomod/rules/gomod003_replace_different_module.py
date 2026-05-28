"""GOMOD-003. go.mod replace substitutes a different upstream module."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GoModFile

RULE = Rule(
    id="GOMOD-003",
    title="go.mod replace directive substitutes a different module",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Module-to-module replacements (``replace foo/bar => "
        "baz/quux v1.2.3``) substitute a completely different "
        "upstream for the requested one. The substitution is "
        "transparent to downstream code (imports of ``foo/bar`` "
        "succeed and link against ``baz/quux``'s implementation), "
        "which is exactly the affordance an attacker who lands "
        "one well-placed replace exploits: ship a malicious "
        "fork at ``attacker/fork``, replace a widely-imported "
        "upstream with it, and every consumer's build inherits "
        "the swap without an import-site code change.\n\n"
        "If the goal is to pin a security patch from a friendly "
        "fork, prefer the same-module replace form (``replace "
        "foo/bar => foo/bar v1.2.3-mybranch.0``) so the rule "
        "doesn't fire and the substitution is auditable as a "
        "version-pin override rather than an upstream swap. If a "
        "true upstream change is intentional (e.g. forked + "
        "maintained internally), suppress per directive with a "
        "rationale naming both the original and replacement "
        "modules."
    ),
    docs_note=(
        "Fires on ``replace orig => new ver`` directives whose "
        "``orig`` and ``new`` module paths differ. Same-module "
        "version-pin replaces (``replace foo => foo v1.2.4``) "
        "pass since they're an auditable version override, not a "
        "supply-chain swap. Local-path replacements are GOMOD-002's "
        "surface (different failure mode, different fix); this "
        "rule only fires on module-to-module substitutions.\n\n"
        "The check operates on the static go.mod text, not on "
        "whether the replacement upstream is actually compromised "
        "(that would require a live registry lookup). The "
        "premise: any cross-module substitution warrants explicit "
        "operator review at audit time."
    ),
    known_fp=(
        "Forked / patched dependencies maintained at a different "
        "module path (``replace upstream/lib => myorg/lib-patched "
        "v1.2.3``) trip this rule deliberately. The right "
        "operator response is to either fold the patch upstream "
        "or suppress per directive with a one-line rationale "
        "naming the fork's maintainer and rotation policy.",
    ),
    incident_refs=(
        "Long-running pattern in Go monorepos where a one-line "
        "replace directive added during an emergency hotfix is "
        "never reverted; downstream consumers continue building "
        "against the temporary fork for years. The rule surfaces "
        "the deviation at every scan so the operator can decide "
        "whether the fork is still load-bearing.",
    ),
    exploit_example=(
        "// Vulnerable: a widely-imported upstream is silently\n"
        "// swapped for an attacker-controlled fork.\n"
        "module example.com/myapp\n"
        "go 1.22\n"
        "require github.com/popular/lib v1.2.3\n"
        "replace github.com/popular/lib => github.com/attacker/fork v1.2.3\n"
        "\n"
        "// Attack: ``github.com/attacker/fork`` is a maintained\n"
        "// drop-in replacement that adds a single shell-out in\n"
        "// the init() of one obscure package. Every consumer of\n"
        "// the replaced module inherits the swap; the change is\n"
        "// transparent at the import site (no source-code diff\n"
        "// in the consumer repo to review).\n"
        "\n"
        "// Safe: drop the replace. Pin upstream directly:\n"
        "//   require github.com/popular/lib v1.2.3\n"
        "// or, if a patched fork is genuinely needed, pin the\n"
        "// fork module under its own name and import it at the\n"
        "// import site:\n"
        "//   require github.com/myorg/popular-lib-patched v1.2.3"
    ),
)


def check(pom: GoModFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for replace in pom.replaces:
        if not replace.substitutes_different_module:
            continue
        new_pin = (
            f" {replace.new_version}" if replace.new_version else ""
        )
        offenders.append(
            f"{replace.orig_path} => {replace.new_path}{new_pin}"
        )
        locations.append(Location(
            path=pom.path,
            start_line=replace.line_no,
            end_line=replace.line_no,
        ))
    passed = not offenders
    desc = (
        "No cross-module replace substitutions in go.mod."
        if passed else
        f"{len(offenders)} replace directive(s) substitute a "
        f"different module: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Each substitution "
        f"silently redirects every import of the original upstream "
        f"into the replacement, transparent to import-site code "
        f"review."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
