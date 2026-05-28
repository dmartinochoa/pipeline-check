"""GOMOD-005. go.mod does not declare a minimum Go toolchain version."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GoModFile

RULE = Rule(
    id="GOMOD-005",
    title="go.mod does not declare a minimum Go toolchain version",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1395",),
    recommendation=(
        "Add a ``go <version>`` directive at the top of ``go.mod`` "
        "naming the minimum supported toolchain (e.g. ``go 1.22``). "
        "The directive tells the Go toolchain which language "
        "features are enabled, which standard-library API "
        "guarantees hold, and which security-relevant compiler "
        "defaults (memory model, race-detector behavior, panic "
        "handling) apply. Without the directive, the build "
        "succeeds under whatever toolchain happens to be "
        "installed, which on a long-lived CI runner often means "
        "an older release that lacks recent security fixes. "
        "Pair with a ``toolchain go<X.Y.Z>`` directive to pin an "
        "exact compiler version when reproducibility is a "
        "concern."
    ),
    docs_note=(
        "Fires when the ``go`` directive is absent from the "
        "manifest. Single-rule LOW: a missing ``go`` line is a "
        "posture / maintenance issue, not an exploit primitive, "
        "but it removes the operator's ability to reason about "
        "which language semantics the build relies on. Often "
        "co-occurs with the no-CI / no-CODEOWNERS pattern in "
        "low-maintenance internal projects, so the rule doubles "
        "as a maintenance indicator."
    ),
    known_fp=(
        "Some module templates (cookiecutter / generator-go) "
        "deliberately omit the directive on the first commit to "
        "let the consumer pick a version. The rule still fires; "
        "suppress per-file with a one-line rationale referencing "
        "the template policy, or — better — bump the template to "
        "emit ``go 1.22`` by default.",
    ),
    incident_refs=(
        "Posture-drift class commonly surfaced in internal-tool "
        "audits of long-lived Go projects: no ``go`` directive, "
        "CI runner pinned to Go 1.17, several CVEs in the "
        "stdlib net/http (e.g. CVE-2023-39325) silently in scope. "
        "Updating the directive to ``go 1.22`` forces the runner "
        "image bump or a hard build failure — the audit signal "
        "the rule is meant to surface.",
    ),
    exploit_example=(
        "// Vulnerable: no ``go`` directive.\n"
        "module example.com/myapp\n"
        "require github.com/foo/bar v1.2.3\n"
        "\n"
        "// Risk: the build picks up whatever Go is installed on\n"
        "// the runner. A long-lived CI image may still run\n"
        "// Go 1.17 with several patched-in-newer-releases CVEs\n"
        "// in the stdlib. No build-time signal warns the\n"
        "// operator that the language version assumption is\n"
        "// stale.\n"
        "\n"
        "// Safe: pin the minimum.\n"
        "module example.com/myapp\n"
        "go 1.22\n"
        "require github.com/foo/bar v1.2.3"
    ),
)


def check(pom: GoModFile) -> Finding:
    if pom.go_version:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                f"go.mod declares minimum toolchain "
                f"``go {pom.go_version}``."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path,
        description=(
            "go.mod has no ``go`` directive. The build will "
            "succeed under whatever toolchain happens to be "
            "installed; long-lived CI runners often carry older "
            "releases that lack recent security fixes."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
