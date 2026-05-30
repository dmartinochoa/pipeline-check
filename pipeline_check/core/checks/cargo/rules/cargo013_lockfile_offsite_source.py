"""CARGO-013. Cargo.lock package sourced off crates.io."""
from __future__ import annotations

import tomllib

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import CargoFile

RULE = Rule(
    id="CARGO-013",
    title="Cargo.lock package sourced off crates.io",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Confirm every off-crates.io ``source`` in ``Cargo.lock`` "
        "is intentional and trusted. A ``[[package]]`` whose "
        "``source`` is a ``git+`` URL or an alternate registry "
        "(``registry+`` / ``sparse+`` pointing somewhere other than "
        "crates.io) is resolved outside the crates.io index and its "
        "checksum, so a transitive dependency can be substituted "
        "without any change to your ``Cargo.toml``. Prefer "
        "crates.io releases; where a git / alternate source is "
        "genuinely needed, pin it (``rev`` SHA for git, a trusted "
        "internal registry for alternates) and review what pulled "
        "it in. The manifest rules (CARGO-002 / CARGO-005 / "
        "CARGO-008) only see your direct declarations; the lockfile "
        "is where transitive substitution shows up."
    ),
    docs_note=(
        "Parses the committed ``Cargo.lock`` body and flags any "
        "``[[package]]`` whose ``source`` is a ``git+`` URL or an "
        "alternate registry (a ``registry+`` / ``sparse+`` source "
        "that is not the canonical crates.io index). Packages with "
        "no ``source`` (local path / workspace members) are "
        "skipped.\n\n"
        "Catches transitive source substitution the manifest rules "
        "can't reach: CARGO-002 (git dep mutable ref), CARGO-005 "
        "(alternate registry), and CARGO-008 (``[patch]`` / "
        "``[replace]``) all read ``Cargo.toml`` direct declarations, "
        "while a substituted source can enter the graph "
        "transitively and only appears in the lockfile."
    ),
    known_fp=(
        "Workspaces that legitimately depend on a git fork (pending "
        "an upstream release) or pull internal crates from a "
        "trusted alternate registry will fire. Suppress per repo "
        "with a rationale once each off-crates.io source is "
        "confirmed; pin git sources to a ``rev`` SHA so the resolved "
        "commit is immutable.",
    ),
    incident_refs=(
        "Transitive source-substitution class: a dependency-of-a-"
        "dependency silently resolved from a git fork or alternate "
        "registry rather than the audited crates.io release, "
        "invisible to anyone reading only the top-level manifest.",
    ),
    exploit_example=(
        "# Vulnerable Cargo.lock: a transitive crate off crates.io.\n"
        "[[package]]\n"
        'name = "useful-helper"\n'
        'version = "1.2.3"\n'
        'source = "git+https://github.com/attacker/useful-helper"\n'
        "\n"
        "# Risk: nothing in Cargo.toml declared this git source; it\n"
        "# entered the graph transitively (a [patch] upstream, a\n"
        "# dependency's own git dep). The build pulls a mutable git\n"
        "# tree with no crates.io checksum.\n"
        "\n"
        "# Safe: the crates.io registry source.\n"
        "[[package]]\n"
        'name = "useful-helper"\n'
        'version = "1.2.3"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    ),
)


#: The two canonical crates.io source forms: the classic git index
#: and the sparse protocol (default since Cargo 1.70).
_CRATES_IO_SOURCES: tuple[str, ...] = (
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
)


def _classify(source: str) -> str | None:
    """Return a category for an off-crates.io source, or ``None`` when
    the source is the canonical crates.io index."""
    if source in _CRATES_IO_SOURCES:
        return None
    low = source.lower()
    if low.startswith("git+"):
        return "git"
    if low.startswith(("registry+", "sparse+")):
        return "alternate registry"
    return "non-crates.io"


def check(manifest: CargoFile) -> Finding:
    if not manifest.lockfile_text:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description="No Cargo.lock body to audit.",
            recommendation=RULE.recommendation, passed=True,
        )
    try:
        data = tomllib.loads(manifest.lockfile_text)
    except tomllib.TOMLDecodeError:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.lockfile_path or manifest.path,
            description="Cargo.lock parse error; can't audit sources.",
            recommendation=RULE.recommendation, passed=True,
        )
    packages = data.get("package")
    resource = manifest.lockfile_path or manifest.path
    offenders: list[str] = []
    locations: list[Location] = []
    if isinstance(packages, list):
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            source = pkg.get("source")
            if not isinstance(source, str) or not source:
                continue  # local / path / workspace member
            category = _classify(source)
            if category is None:
                continue
            name = str(pkg.get("name", "?"))
            offenders.append(f"{name} ({category})")
            marker = f'name = "{name}"'
            line_no = 1
            if marker in manifest.lockfile_text:
                line_no = (
                    manifest.lockfile_text[
                        : manifest.lockfile_text.index(marker)
                    ].count("\n") + 1
                )
            locations.append(Location(
                path=resource, start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        "Every locked package resolves from crates.io."
        if passed else
        f"{len(offenders)} locked package(s) resolve off crates.io: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A git / "
        f"alternate-registry source bypasses the crates.io index "
        f"checksum and can substitute a transitive crate."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=resource, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
