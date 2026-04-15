"""GitLab CI pipeline security checks.

GL-001  Image not pinned to specific version or digest        HIGH      CICD-SEC-3
GL-002  Script injection via untrusted commit/MR context      HIGH      CICD-SEC-4
GL-003  Variables contain literal secret values               CRITICAL  CICD-SEC-6
GL-004  Deploy job lacks manual approval or environment gate  MEDIUM    CICD-SEC-1
GL-005  include: pulls remote / project without pinned ref    HIGH      CICD-SEC-3
"""
from __future__ import annotations

import re
from typing import Any

from ..base import Finding, Severity
from .base import GitLabBaseCheck, iter_jobs, job_scripts

_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
# A version tag is any tag that looks semver-ish (has a digit, not "latest").
_VERSION_TAG_RE = re.compile(r":[^:]*\d[^:]*$")

# Attacker-controllable GitLab CI predefined variables — commit / MR metadata
# derived from branch name, commit message, MR title/description.
_UNTRUSTED_VAR_RE = re.compile(
    r"\$\{?(?:"
    r"CI_COMMIT_MESSAGE|CI_COMMIT_DESCRIPTION|CI_COMMIT_TITLE"
    r"|CI_COMMIT_REF_NAME|CI_COMMIT_BRANCH|CI_COMMIT_TAG"
    r"|CI_COMMIT_AUTHOR"
    r"|CI_MERGE_REQUEST_TITLE|CI_MERGE_REQUEST_DESCRIPTION"
    r"|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"
    r")\}?"
)

# AWS access key ID pattern + well-known credential key names.
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_SECRETISH_KEY_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|apikey|api_key|private_key)"
)


class GitLabPipelineChecks(GitLabBaseCheck):
    """Runs every GL-XXX check against the loaded pipeline documents."""

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for p in self.ctx.pipelines:
            findings.extend(self._check_pipeline(p.path, p.data))
        return findings

    def _check_pipeline(self, path: str, doc: dict[str, Any]) -> list[Finding]:
        return [
            self._gl001_image_pinning(path, doc),
            self._gl002_script_injection(path, doc),
            self._gl003_literal_secrets(path, doc),
            self._gl004_deploy_gating(path, doc),
            self._gl005_include_pinning(path, doc),
        ]

    # ------------------------------------------------------------------
    # GL-001 — image pinning
    # ------------------------------------------------------------------

    @staticmethod
    def _image_ref(v: Any) -> str | None:
        if isinstance(v, str):
            return v
        if isinstance(v, dict):
            n = v.get("name")
            return n if isinstance(n, str) else None
        return None

    @classmethod
    def _gl001_image_pinning(cls, path: str, doc: dict[str, Any]) -> Finding:
        unpinned: list[str] = []

        def _inspect(ref: str, where: str) -> None:
            if _DIGEST_RE.search(ref):
                return
            # split tag
            if ":" not in ref.rsplit("/", 1)[-1]:
                unpinned.append(f"{where}: {ref} (no tag)")
                return
            tag = ref.rsplit(":", 1)[1]
            if tag == "latest" or not _VERSION_TAG_RE.search(ref):
                unpinned.append(f"{where}: {ref}")

        top = cls._image_ref(doc.get("image"))
        if top:
            _inspect(top, "<top-level>")
        for name, job in iter_jobs(doc):
            ref = cls._image_ref(job.get("image"))
            if ref:
                _inspect(ref, name)

        passed = not unpinned
        desc = (
            "Every `image:` reference is pinned to a specific version or digest."
            if passed else
            f"{len(unpinned)} `image:` reference(s) are floating or untagged: "
            f"{', '.join(unpinned[:5])}{'…' if len(unpinned) > 5 else ''}. "
            f"Floating tags (`latest` or major-only) can be silently swapped "
            f"under the job."
        )
        return Finding(
            check_id="GL-001",
            title="Image not pinned to specific version or digest",
            severity=Severity.HIGH,
            resource=path,
            description=desc,
            recommendation=(
                "Reference images by `@sha256:<digest>` or at minimum a full "
                "immutable version tag (e.g. `python:3.12.1-slim`). Avoid "
                "`:latest` and bare tags like `:3`."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # GL-002 — script injection
    # ------------------------------------------------------------------

    @staticmethod
    def _gl002_script_injection(path: str, doc: dict[str, Any]) -> Finding:
        offenders: list[str] = []
        for name, job in iter_jobs(doc):
            for line in job_scripts(job):
                if _UNTRUSTED_VAR_RE.search(line) and not _is_quoted_assignment(line):
                    offenders.append(name)
                    break
        passed = not offenders
        desc = (
            "No script interpolates attacker-controllable commit/MR metadata."
            if passed else
            f"Script(s) in job(s) {', '.join(sorted(set(offenders)))} interpolate "
            f"attacker-controllable variables (CI_COMMIT_MESSAGE, "
            f"CI_MERGE_REQUEST_TITLE, CI_COMMIT_BRANCH, etc.) directly into "
            f"shell commands."
        )
        return Finding(
            check_id="GL-002",
            title="Script injection via untrusted commit/MR context",
            severity=Severity.HIGH,
            resource=path,
            description=desc,
            recommendation=(
                "Read these values into intermediate `variables:` entries or "
                "shell variables and quote them defensively (`\"$BRANCH\"`). "
                "Never inline `$CI_COMMIT_MESSAGE` / `$CI_MERGE_REQUEST_TITLE` "
                "into a shell command."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # GL-003 — literal secrets in variables
    # ------------------------------------------------------------------

    @staticmethod
    def _gl003_literal_secrets(path: str, doc: dict[str, Any]) -> Finding:
        offenders: list[str] = []

        def _scan(varmap: Any, where: str) -> None:
            if not isinstance(varmap, dict):
                return
            for key, value in varmap.items():
                if not isinstance(key, str):
                    continue
                # value may be a dict (with value/description) or a scalar
                raw = value.get("value") if isinstance(value, dict) else value
                if not isinstance(raw, str):
                    continue
                if _AWS_KEY_RE.search(raw):
                    offenders.append(f"{where}.{key} (AWS access key)")
                    continue
                if _SECRETISH_KEY_RE.search(key) and raw and "$" not in raw:
                    offenders.append(f"{where}.{key}")

        _scan(doc.get("variables"), "<top>")
        for name, job in iter_jobs(doc):
            _scan(job.get("variables"), name)

        passed = not offenders
        desc = (
            "No `variables:` entry holds a literal credential-shaped value."
            if passed else
            f"{len(offenders)} variable(s) contain literal credential values: "
            f"{', '.join(offenders[:5])}{'…' if len(offenders) > 5 else ''}. "
            f"Secrets committed to CI YAML are visible in every fork and every "
            f"pipeline run log."
        )
        severity = Severity.CRITICAL if any("AWS" in o for o in offenders) else (
            Severity.HIGH if offenders else Severity.HIGH
        )
        return Finding(
            check_id="GL-003",
            title="Variables contain literal secret values",
            severity=severity,
            resource=path,
            description=desc,
            recommendation=(
                "Store credentials as protected + masked CI/CD variables in "
                "project or group settings, and reference them by name from "
                "the YAML. For cloud access prefer short-lived OIDC tokens."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # GL-004 — deploy job gating
    # ------------------------------------------------------------------

    _DEPLOY_RE = re.compile(r"(?i)(deploy|release|publish|promote)")

    @classmethod
    def _gl004_deploy_gating(cls, path: str, doc: dict[str, Any]) -> Finding:
        ungated: list[str] = []
        for name, job in iter_jobs(doc):
            stage = job.get("stage")
            is_deploy = (
                (isinstance(stage, str) and cls._DEPLOY_RE.search(stage))
                or cls._DEPLOY_RE.search(name)
            )
            if not is_deploy:
                continue
            manual = job.get("when") == "manual" or _rules_manual(job.get("rules"))
            has_env = bool(job.get("environment"))
            if not (manual or has_env):
                ungated.append(name)
        passed = not ungated
        desc = (
            "All deploy-like jobs are gated by manual approval or environment."
            if passed else
            f"{len(ungated)} deploy job(s) run automatically without a manual "
            f"gate or `environment:` binding: {', '.join(ungated)}. Any push "
            f"to the trigger branch will ship to the target."
        )
        return Finding(
            check_id="GL-004",
            title="Deploy job lacks manual approval or environment gate",
            severity=Severity.MEDIUM,
            resource=path,
            description=desc,
            recommendation=(
                "Add `when: manual` (optionally with `rules:` for protected "
                "branches) or bind the job to an `environment:` with a "
                "deployment tier so approvals and audit are enforced by "
                "GitLab's environment controls."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # GL-005 — include pinning
    # ------------------------------------------------------------------

    @classmethod
    def _gl005_include_pinning(cls, path: str, doc: dict[str, Any]) -> Finding:
        includes = doc.get("include")
        if includes is None:
            return Finding(
                check_id="GL-005",
                title="include: pulls remote / project without pinned ref",
                severity=Severity.HIGH,
                resource=path,
                description="Pipeline has no `include:` directive.",
                recommendation="No action required.",
                passed=True,
            )
        items = includes if isinstance(includes, list) else [includes]
        unpinned: list[str] = []
        for entry in items:
            if isinstance(entry, str):
                # shorthand string form — local file path is safe; URL is not
                if entry.startswith(("http://", "https://")):
                    unpinned.append(f"remote: {entry}")
                continue
            if not isinstance(entry, dict):
                continue
            if "project" in entry and not entry.get("ref"):
                unpinned.append(f"project: {entry.get('project')} (no ref)")
            elif "project" in entry:
                ref = str(entry.get("ref"))
                # Bare branch names (main/master) are unpinned; require a tag
                # or SHA-looking value.
                if ref.lower() in {"main", "master", "develop", "head"}:
                    unpinned.append(f"project: {entry.get('project')} @{ref}")
            if "remote" in entry:
                # Remote includes over HTTP(S) can't be cryptographically pinned
                # — the content at that URL can change at any time. Flag any
                # remote include as unpinned by policy.
                unpinned.append(f"remote: {entry.get('remote')}")
        passed = not unpinned
        desc = (
            "All `include:` entries reference a pinned ref."
            if passed else
            f"{len(unpinned)} `include:` entr(ies) pull from a remote or "
            f"upstream project without a pinned ref: {', '.join(unpinned[:5])}"
            f"{'…' if len(unpinned) > 5 else ''}."
        )
        return Finding(
            check_id="GL-005",
            title="include: pulls remote / project without pinned ref",
            severity=Severity.HIGH,
            resource=path,
            description=desc,
            recommendation=(
                "Pin `include: project:` entries with `ref:` set to a tag or "
                "commit SHA. Avoid `include: remote:` for untrusted URLs; "
                "mirror the content into a trusted project and pin it."
            ),
            passed=passed,
        )


def _is_quoted_assignment(line: str) -> bool:
    """Heuristic — `VAR="$CI_COMMIT_MESSAGE"` is safe assignment, not injection."""
    return bool(re.match(r'\s*\w+="[^"]*\$\{?\w+\}?[^"]*"\s*$', line))


def _rules_manual(rules: Any) -> bool:
    if not isinstance(rules, list):
        return False
    for rule in rules:
        if isinstance(rule, dict) and rule.get("when") == "manual":
            return True
    return False
