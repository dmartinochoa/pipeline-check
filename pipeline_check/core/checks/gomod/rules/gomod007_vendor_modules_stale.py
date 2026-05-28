"""GOMOD-007. vendor/modules.txt missing or stale relative to go.mod."""
from __future__ import annotations

from pathlib import Path

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GoModFile

RULE = Rule(
    id="GOMOD-007",
    title="vendor/modules.txt missing or stale relative to go.mod",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS", "ESF-S-PIN-DEPS"),
    cwe=("CWE-345", "CWE-829"),
    recommendation=(
        "Run ``go mod vendor`` to regenerate ``vendor/modules.txt`` "
        "and ``vendor/`` from the current ``go.mod`` / ``go.sum``. "
        "Commit the result. The file is the manifest the Go "
        "toolchain consults when ``-mod=vendor`` is set: it pins "
        "every direct + indirect dep to the version checked into "
        "``vendor/``. A stale ``vendor/modules.txt`` (older "
        "require set than ``go.mod`` declares, or absent "
        "entirely while ``vendor/`` is populated) means the build "
        "uses different versions depending on whether "
        "``GOFLAGS=-mod=vendor`` is set in the build environment, "
        "and a contributor who edits ``go.mod`` without re-"
        "running ``go mod vendor`` ships an unreviewed mismatch "
        "between the manifest and the vendored content.\n\n"
        "Add ``go mod verify`` to CI to catch drift at build "
        "time; the verification fails when the vendored content "
        "doesn't match the checksums in ``go.sum``."
    ),
    docs_note=(
        "Fires when the ``go.mod`` file's directory has a "
        "``vendor/`` sibling without a ``vendor/modules.txt`` "
        "file, OR when ``vendor/modules.txt`` declares fewer "
        "direct requires than ``go.mod`` does (best-effort "
        "staleness detection — a full diff against every "
        "require would require parsing modules.txt's nested "
        "format).\n\n"
        "Projects that don't ship a ``vendor/`` directory pass "
        "the rule silently. ``go.mod`` projects use vendor mode "
        "selectively, the rule's value is catching the case "
        "where vendor mode is in use but its manifest has "
        "drifted."
    ),
    known_fp=(
        "Pre-Go-1.14 projects that vendored without a "
        "``vendor/modules.txt`` (the file became required at "
        "Go 1.14) trip this rule. The right fix is to run "
        "``go mod vendor`` once under a modern toolchain to "
        "regenerate the manifest; suppress per file if the "
        "legacy vendor layout is intentional.",
    ),
    incident_refs=(
        "Pattern in long-lived Go monorepos where a vendor/ "
        "directory carries pre-modules-era dependencies but the "
        "modules.txt manifest was never generated. Builds "
        "succeed under both ``-mod=mod`` (fetches fresh, ignores "
        "vendor) and ``-mod=vendor`` (uses vendor, ignores "
        "go.mod), but the resulting binaries can diverge.",
    ),
    exploit_example=(
        "# Vulnerable: vendor/ committed without modules.txt.\n"
        "$ ls vendor/\n"
        "github.com/  golang.org/  modules.txt   ← missing\n"
        "\n"
        "# Risk: a CI build with ``GOFLAGS=-mod=vendor`` runs\n"
        "# against the older vendored content; a local developer\n"
        "# without the flag fetches the current upstream. The two\n"
        "# binaries differ; reproducing the CI build locally\n"
        "# requires figuring out which flag was set.\n"
        "\n"
        "# Safe: run go mod vendor and commit the result.\n"
        "$ go mod vendor\n"
        "$ git add vendor/ && git commit"
    ),
)


def check(pom: GoModFile) -> Finding:
    parent = Path(pom.path).parent
    vendor_dir = parent / "vendor"
    if not vendor_dir.is_dir():
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "Project does not ship a vendor/ directory; "
                "vendor-mode audit is not applicable."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    modules_txt = vendor_dir / "modules.txt"
    if not modules_txt.is_file():
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                f"vendor/ directory present at ``{vendor_dir}`` "
                f"but vendor/modules.txt is missing. The "
                f"toolchain has no manifest to map vendored "
                f"content back to the go.mod requires; "
                f"``-mod=vendor`` builds will silently use "
                f"whatever the directory contains."
            ),
            recommendation=RULE.recommendation, passed=False,
        )
    # Best-effort staleness check: count distinct module entries
    # in modules.txt and compare to the go.mod direct require
    # count. Entries in modules.txt start with ``# <path> <version>``.
    try:
        text = modules_txt.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=str(modules_txt),
            description=(
                "vendor/modules.txt is unreadable; can't compare "
                "against go.mod."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    declared_paths: set[str] = set()
    for line in text.splitlines():
        if line.startswith("# ") and " " in line[2:]:
            head = line[2:].split(" ", 1)[0]
            if head:
                declared_paths.add(head)
    required_paths = {r.path for r in pom.requires}
    missing = required_paths - declared_paths
    if not missing:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=str(modules_txt),
            description=(
                f"vendor/modules.txt covers every go.mod require "
                f"({len(declared_paths)} module(s) vendored)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=str(modules_txt),
        description=(
            f"{len(missing)} go.mod require(s) absent from "
            f"vendor/modules.txt: {', '.join(sorted(missing)[:5])}"
            f"{'…' if len(missing) > 5 else ''}. The vendor "
            f"manifest is stale relative to go.mod; "
            f"``-mod=vendor`` and ``-mod=mod`` builds will "
            f"produce different binaries."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
