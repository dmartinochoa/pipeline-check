"""GOMOD-001. go.mod present without a sibling go.sum integrity manifest."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GoModFile

RULE = Rule(
    id="GOMOD-001",
    title="go.mod present without sibling go.sum integrity manifest",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-345", "CWE-494"),
    recommendation=(
        "Commit the generated ``go.sum`` alongside ``go.mod``. The "
        "sum file records ``h1:<base64-sha256>`` hashes for every "
        "module zip and ``go.mod`` referenced by the build; without "
        "it the Go toolchain falls back to consulting the public "
        "checksum database (``sum.golang.org``) at build time, which "
        "is fine in normal operation but doesn't survive an "
        "offline / hermetic build, and is silently bypassed when "
        "``GOFLAGS=-insecure``, ``GONOSUMCHECK=1``, or "
        "``GOSUMDB=off`` is set in the build environment. Generate "
        "the file once with ``go mod tidy`` and check it in; from "
        "that point ``go build`` will refuse to proceed if any "
        "module zip's hash drifts from the recorded value."
    ),
    docs_note=(
        "Fires when the ``go.mod`` file's directory has no "
        "``go.sum`` sibling at scan time. The check is a presence "
        "probe only, the hash payloads themselves are not audited "
        "(``go mod verify`` is the canonical verifier and runs "
        "against a live module cache). Catches the common "
        "misconfiguration where ``go.sum`` is added to "
        "``.gitignore`` (a stale dev habit imported from the "
        "pre-modules ``dep`` / ``glide`` era when vendoring made "
        "lockfiles redundant).\n\n"
        "Skipped when the module's ``require`` block is empty "
        "(an experimental / placeholder module with no third-party "
        "deps); the absent sum file is a no-op there since there's "
        "nothing to verify."
    ),
    known_fp=(
        "A first-commit go.mod with no requires legitimately ships "
        "without a go.sum, the rule already exempts that case. "
        "Some monorepo migration scripts also temporarily strip "
        "go.sum during a rebase; suppress per-file with a "
        "one-line rationale if your migration tooling requires it.",
    ),
    incident_refs=(
        "Long-running pattern of go.sum exclusions in dev / staging "
        "Go projects that hit production CI before a contributor "
        "regenerates it. The Go toolchain's checksum-database "
        "fallback masks the missing file under normal network "
        "conditions; offline builds, airgapped CI runners, and "
        "GOSUMDB=off configurations land directly on the "
        "unprotected path.",
    ),
    exploit_example=(
        "# Vulnerable: go.mod committed, go.sum gitignored.\n"
        "# Build environment sets GOFLAGS=-insecure for vendor\n"
        "# warmup, so the toolchain neither consults the public\n"
        "# checksum DB nor enforces local hashes.\n"
        "$ cat .gitignore\n"
        "go.sum\n"
        "\n"
        "$ cat go.mod\n"
        "module example.com/myapp\n"
        "go 1.22\n"
        "require github.com/foo/bar v1.2.3\n"
        "\n"
        "# Attack: a man-in-the-middle proxy intercepts the GOPROXY\n"
        "# fetch and returns a tampered v1.2.3 zip. With no\n"
        "# committed go.sum and GOFLAGS bypassing the database, the\n"
        "# build accepts the poisoned bytes; the bug ships.\n"
        "\n"
        "# Safe: commit go.sum. The toolchain refuses to proceed\n"
        "# when the on-disk zip's hash drifts from the recorded\n"
        "# h1:<base64-sha256>= line."
    ),
)


def check(pom: GoModFile) -> Finding:
    if not pom.requires:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "go.mod declares no third-party requires; absent "
                "go.sum is a no-op (nothing to verify)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if pom.has_sumfile:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                f"Integrity manifest ``go.sum`` present at "
                f"``{pom.sumfile_path}``."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path,
        description=(
            f"No sibling ``go.sum`` for ``{pom.path}``. The Go "
            f"toolchain has no local hash table to verify module "
            f"zips against, so a tampered fetch (MITM, GOPROXY "
            f"misconfiguration, GOSUMDB=off) lands without "
            f"detection. {len(pom.requires)} require(s) would "
            f"otherwise be locked to specific content hashes."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
