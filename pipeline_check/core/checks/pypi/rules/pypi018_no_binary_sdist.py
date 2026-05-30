"""PYPI-018, --no-binary forces the install-time sdist build path."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import RequirementsFile, get_option_values, has_option

RULE = Rule(
    id="PYPI-018",
    title="requirements.txt forces source builds via --no-binary",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Drop ``--no-binary`` and install prebuilt wheels where "
        "possible. ``--no-binary`` tells pip to skip wheels and build "
        "from the source distribution, and an sdist build runs the "
        "package's ``setup.py`` (or PEP 517 backend) on the build "
        "machine, so installing the dependency executes arbitrary "
        "code at install time. A wheel install runs no package code, "
        "so this option widens the install-time code-execution "
        "surface. If a source build is genuinely required (a package "
        "with no wheel, or a C extension you must compile), scope "
        "``--no-binary`` to the specific package rather than "
        "``:all:``, and run the build in a sandboxed, network-isolated "
        "step with pinned, hashed requirements."
    ),
    docs_note=(
        "Fires on any top-level ``--no-binary`` option, including the "
        "``--no-binary :all:`` form and the package-scoped "
        "``--no-binary <name>`` form. The complementary "
        "``--only-binary`` is the safer direction (it forbids source "
        "builds) and is not flagged.\n\n"
        "This is the install-time code-execution surface that the "
        "wheel-only path avoids: pip building an sdist invokes the "
        "package's build backend, which is attacker-controlled code "
        "for any dependency whose source you don't audit."
    ),
    known_fp=(
        "Some packages ship only an sdist, or you compile a C "
        "extension against the build host on purpose. In that case "
        "the source build is intentional; scope ``--no-binary`` to "
        "the named package and suppress per file with a rationale.",
    ),
)


def check(rf: RequirementsFile) -> Finding:
    if not has_option(rf, "--no-binary"):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=rf.path,
            description="No --no-binary option; wheels are not forced off.",
            recommendation=RULE.recommendation, passed=True,
        )
    values = get_option_values(rf, "--no-binary")
    targets = ", ".join(v.strip() for v in values if v.strip()) or ":all:"
    locations: list[Location] = []
    line_no = 1
    if "--no-binary" in rf.text:
        line_no = rf.text[:rf.text.index("--no-binary")].count("\n") + 1
    locations.append(Location(
        path=rf.path, start_line=line_no, end_line=line_no,
    ))
    desc = (
        f"--no-binary forces the sdist build path ({targets}). Each "
        f"affected package's setup.py / PEP 517 backend runs on the "
        f"build machine at install time, so installing the dependency "
        f"executes arbitrary code."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
    )
