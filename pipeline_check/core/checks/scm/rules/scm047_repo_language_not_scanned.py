"""SCM-047. Repo language excluded from default code-scanning coverage.

Default code-scanning's auto-language detection picks the languages
the setup will analyze. When the linguist-detected language set
includes a CodeQL-supported language that's missing from the
scanning configuration, that language's code lands in the repo
unscanned even though SCM-003 / SCM-045 / SCM-046 all pass.

Only flags **CodeQL-supported** languages. A repo dominated by an
unsupported language (Shell, Lua) doesn't fail this rule — a
third-party SAST workflow is the remediation, not default setup.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    archived_state_label,
    repo_resource,
)

#: GitHub's linguist label → CodeQL language identifier. Only
#: languages CodeQL can analyze are listed; presence in the repo
#: triggers a finding when the language isn't in the scanning set.
#: Source: GitHub Code Scanning docs (CodeQL-supported languages
#: list, current as of 2026 spec sync).
_CODEQL_SUPPORTED: dict[str, str] = {
    "C": "cpp",
    "C++": "cpp",
    "C#": "csharp",
    "Go": "go",
    "Java": "java-kotlin",
    "Kotlin": "java-kotlin",
    "JavaScript": "javascript-typescript",
    "TypeScript": "javascript-typescript",
    "Python": "python",
    "Ruby": "ruby",
    "Swift": "swift",
}

#: Languages must represent at least this fraction of the repo's
#: linguist-detected bytes to be considered "present enough to
#: matter". Tiny vendored snippets in an otherwise pure-Python repo
#: shouldn't trigger findings.
_SIGNIFICANT_SHARE = 0.05


RULE = Rule(
    id="SCM-047",
    title="Repo language excluded from default code-scanning coverage",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    esf=("ESF-V-VULN-MGMT",),
    cwe=("CWE-1059",),
    recommendation=(
        "Open the default code-scanning setup configuration "
        "(``Settings → Code security → Code scanning → Default "
        "setup → Edit configuration``) and add the missing "
        "languages to the analyzed set. If a language isn't "
        "CodeQL-supported (e.g. Shell, Lua), set up a third-party "
        "SAST workflow that uploads SARIF for that subset — "
        "default setup's auto-detect doesn't cover every language."
    ),
    docs_note=(
        "Cross-references the linguist ``languages`` endpoint "
        "against the default-setup ``languages`` slot. Fires "
        "when a CodeQL-supported language present at ≥5% of "
        "repo bytes is missing from the scanning set. Passes "
        "silently when default scanning isn't configured "
        "(SCM-003 / SCM-046 own those cases) or when the "
        "languages endpoint is unavailable."
    ),
    known_fp=(
        "Monorepos may intentionally exclude legacy subdirectories "
        "from CodeQL analysis (e.g. a vendored fork). Suppress per "
        "repo with a rationale that names the excluded path; the "
        "default-setup language toggle is repo-wide, so a per-path "
        "exclusion requires a hand-authored workflow.",
    ),
)


def _scanning_languages(setup: dict[str, Any]) -> set[str]:
    raw = setup.get("languages")
    if not isinstance(raw, list):
        return set()
    return {
        lang.lower() for lang in raw if isinstance(lang, str)
    }


def _significant_repo_languages(
    languages: dict[str, int],
) -> list[tuple[str, str]]:
    """Return ``[(linguist_label, codeql_id)]`` for CodeQL-supported
    languages present at ≥5% of repo bytes. Empty list when nothing
    significant is detectable."""
    total = sum(v for v in languages.values() if isinstance(v, int))
    if total <= 0:
        return []
    found: list[tuple[str, str]] = []
    seen_codeql: set[str] = set()
    for label, byte_count in languages.items():
        if not isinstance(byte_count, int) or byte_count <= 0:
            continue
        if byte_count / total < _SIGNIFICANT_SHARE:
            continue
        codeql_id = _CODEQL_SUPPORTED.get(label)
        if codeql_id is None or codeql_id in seen_codeql:
            continue
        seen_codeql.add(codeql_id)
        found.append((label, codeql_id))
    return found


def check(snapshot: SCMRepoSnapshot) -> Finding:
    if label := archived_state_label(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=f"Repo is {label}; language-coverage check skipped.",
            recommendation=RULE.recommendation, passed=True,
        )
    setup = snapshot.code_scanning_default_setup
    if not isinstance(setup, dict) or setup.get("state") != "configured":
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "Default code scanning is not configured; "
                "SCM-003 owns that case."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    languages = snapshot.repo_languages
    if languages is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "repos/languages endpoint unavailable; "
                "language-coverage posture not evaluated."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    significant = _significant_repo_languages(languages)
    if not significant:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "No CodeQL-supported languages at ≥5% byte share "
                "in the repo; nothing for default setup to cover."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    scanning = _scanning_languages(setup)
    missing = [
        label for label, codeql_id in significant
        if codeql_id not in scanning
    ]
    passed = not missing
    if passed:
        desc = (
            f"Default code scanning covers every CodeQL-supported "
            f"language present at ≥5% byte share "
            f"({', '.join(label for label, _ in significant)})."
        )
    else:
        desc = (
            f"Default code scanning does not analyze "
            f"{', '.join(missing)}, which represent ≥5% of the "
            f"repo's byte share. Add the missing language(s) to "
            f"the default-setup configuration."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
