"""Azure DevOps Pipelines security checks.

ADO-001  Task reference not pinned to specific version            HIGH      CICD-SEC-3
ADO-002  Script injection via attacker-controllable context       HIGH      CICD-SEC-4
ADO-003  Variables contain literal secret values                  CRITICAL  CICD-SEC-6
ADO-004  Deployment job missing environment binding               MEDIUM    CICD-SEC-1
ADO-005  Container image not pinned to specific version           HIGH      CICD-SEC-3
ADO-006  Artifacts not signed                                     MEDIUM    ESF-D-SIGN-ARTIFACTS
ADO-007  SBOM not produced                                        MEDIUM    ESF-D-SBOM
"""
from __future__ import annotations

import re
from typing import Any

from ..base import Finding, Severity, has_sbom, has_signing
from .base import AzureBaseCheck, iter_jobs, iter_steps

# `- task: Org.Task@N.M.P` — pinned; `@N` alone is floating-major.
_TASK_PIN_RE = re.compile(r"@\d+\.\d+(?:\.\d+)?(?:[-.][\w\d]+)*$")

# Attacker-controllable ADO predefined variables.
#
# Build.SourceBranch / SourceBranchName / SourceVersionMessage — branch
# and commit metadata under the pusher's control.
# System.PullRequest.* — PR metadata under the PR author's control.
# Build.RequestedFor(Email) — user who triggered the build (controllable
# by anyone with contribute rights).
_UNTRUSTED_VAR_RE = re.compile(
    r"\$\(\s*(?:"
    r"Build\.SourceBranch(?:Name)?"
    r"|Build\.SourceVersion(?:Message)?"
    r"|Build\.RequestedFor(?:Email)?"
    r"|System\.PullRequest\.(?:SourceBranch|SourceRepositoryURI|PullRequestId|PullRequestNumber)"
    r")\s*\)"
)

_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_SECRETISH_KEY_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|apikey|api_key|private_key)"
)

_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
_VERSION_TAG_RE = re.compile(r":[^:]*\d[^:]*$")


class AzurePipelineChecks(AzureBaseCheck):
    """Runs every ADO-XXX check against the loaded pipeline documents."""

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for p in self.ctx.pipelines:
            findings.extend(self._check_doc(p.path, p.data))
        return findings

    def _check_doc(self, path: str, doc: dict[str, Any]) -> list[Finding]:
        jobs = list(iter_jobs(doc))
        return [
            self._ado001_task_pinning(path, jobs),
            self._ado002_script_injection(path, jobs),
            self._ado003_literal_secrets(path, doc, jobs),
            self._ado004_deployment_env(path, jobs),
            self._ado005_container_pinning(path, doc, jobs),
            self._ado006_signing(path, doc),
            self._ado007_sbom(path, doc),
        ]

    # ------------------------------------------------------------------
    # ADO-006 — artifact signing
    # ------------------------------------------------------------------

    @staticmethod
    def _ado006_signing(path: str, doc: dict[str, Any]) -> Finding:
        passed = has_signing(doc)
        desc = (
            "Pipeline invokes a signing tool (cosign / sigstore / notation)."
            if passed else
            "Pipeline produces build artifacts but does not invoke any signing "
            "tool (cosign, sigstore, notation). Unsigned artifacts cannot be "
            "verified downstream, so a tampered build is indistinguishable "
            "from a legitimate one."
        )
        return Finding(
            check_id="ADO-006",
            title="Artifacts not signed",
            severity=Severity.MEDIUM,
            resource=path,
            description=desc,
            recommendation=(
                "Add a task that runs `cosign sign` or `notation sign` — Azure "
                "Pipelines' workload identity federation enables keyless "
                "signing. Publish the signature to the artifact feed and "
                "verify it at deploy time."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # ADO-007 — SBOM generation
    # ------------------------------------------------------------------

    @staticmethod
    def _ado007_sbom(path: str, doc: dict[str, Any]) -> Finding:
        passed = has_sbom(doc)
        desc = (
            "Pipeline produces an SBOM (CycloneDX / syft / Microsoft sbom-tool)."
            if passed else
            "Pipeline does not produce a software bill of materials (SBOM). "
            "Without an SBOM, downstream consumers cannot audit the exact set "
            "of dependencies shipped in the artifact."
        )
        return Finding(
            check_id="ADO-007",
            title="SBOM not produced",
            severity=Severity.MEDIUM,
            resource=path,
            description=desc,
            recommendation=(
                "Add an SBOM step — `microsoft/sbom-tool`, `syft . -o "
                "cyclonedx-json`, or `anchore/sbom-action`. Publish the SBOM "
                "as a pipeline artifact so downstream consumers can ingest it."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # ADO-001 — task version pinning
    # ------------------------------------------------------------------

    @staticmethod
    def _ado001_task_pinning(
        path: str, jobs: list[tuple[str, dict[str, Any]]]
    ) -> Finding:
        unpinned: list[str] = []
        for job_loc, job in jobs:
            for step_loc, step in iter_steps(job):
                ref = step.get("task")
                if not isinstance(ref, str) or "@" not in ref:
                    continue
                if not _TASK_PIN_RE.search(ref):
                    unpinned.append(f"{job_loc}.{step_loc}: {ref}")
        passed = not unpinned
        desc = (
            "Every `task:` reference is pinned to a specific version."
            if passed else
            f"{len(unpinned)} `task:` reference(s) pinned to a major-only "
            f"version: {', '.join(unpinned[:5])}"
            f"{'…' if len(unpinned) > 5 else ''}. A floating major tag can "
            f"roll forward silently when the task publisher ships a breaking "
            f"or malicious update."
        )
        return Finding(
            check_id="ADO-001",
            title="Task reference not pinned to specific version",
            severity=Severity.HIGH,
            resource=path,
            description=desc,
            recommendation=(
                "Reference tasks by a full semver (`DownloadSecureFile@1.2.3`)"
                " or extension-published-version. Track task updates "
                "explicitly via Azure DevOps extension settings rather than "
                "letting `@1` drift."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # ADO-002 — script injection
    # ------------------------------------------------------------------

    @staticmethod
    def _ado002_script_injection(
        path: str, jobs: list[tuple[str, dict[str, Any]]]
    ) -> Finding:
        offenders: list[str] = []
        for job_loc, job in jobs:
            for step_loc, step in iter_steps(job):
                for key in ("script", "bash", "pwsh", "powershell"):
                    body = step.get(key)
                    if not isinstance(body, str):
                        continue
                    if _UNTRUSTED_VAR_RE.search(body) and not _is_quoted_assignment(body):
                        offenders.append(f"{job_loc}.{step_loc}")
                        break
        passed = not offenders
        desc = (
            "No script interpolates attacker-controllable build or PR metadata."
            if passed else
            f"Script(s) in {', '.join(sorted(set(offenders))[:5])} "
            f"interpolate $(Build.SourceBranch*), $(Build.SourceVersionMessage), "
            f"or $(System.PullRequest.*) directly into shell commands. A "
            f"crafted branch name or commit message can execute inline."
        )
        return Finding(
            check_id="ADO-002",
            title="Script injection via attacker-controllable context",
            severity=Severity.HIGH,
            resource=path,
            description=desc,
            recommendation=(
                "Pass these values through an intermediate pipeline "
                "variable declared with `readonly: true`, and reference "
                "that variable through an environment variable rather "
                "than `$(...)` macro interpolation. ADO expands `$(…)` "
                "before shell quoting, so inline use is never safe."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # ADO-003 — literal secrets in variables
    # ------------------------------------------------------------------

    @staticmethod
    def _ado003_literal_secrets(
        path: str, doc: dict[str, Any],
        jobs: list[tuple[str, dict[str, Any]]],
    ) -> Finding:
        offenders: list[str] = []

        def _scan_mapping(mapping: Any, where: str) -> None:
            if isinstance(mapping, dict):
                for key, value in mapping.items():
                    if not isinstance(key, str) or not isinstance(value, str):
                        continue
                    if _AWS_KEY_RE.search(value):
                        offenders.append(f"{where}.{key} (AWS access key)")
                    elif _SECRETISH_KEY_RE.search(key) and value and "$" not in value:
                        offenders.append(f"{where}.{key}")
            elif isinstance(mapping, list):
                # The `- name: X, value: Y` form.
                for entry in mapping:
                    if not isinstance(entry, dict):
                        continue
                    name = entry.get("name")
                    value = entry.get("value")
                    if not isinstance(name, str) or not isinstance(value, str):
                        continue
                    if _AWS_KEY_RE.search(value):
                        offenders.append(f"{where}.{name} (AWS access key)")
                    elif _SECRETISH_KEY_RE.search(name) and value and "$" not in value:
                        offenders.append(f"{where}.{name}")

        _scan_mapping(doc.get("variables"), "<top>")
        for job_loc, job in jobs:
            _scan_mapping(job.get("variables"), job_loc)

        passed = not offenders
        desc = (
            "No `variables:` entry holds a literal credential-shaped value."
            if passed else
            f"{len(offenders)} variable(s) contain literal credential values: "
            f"{', '.join(offenders[:5])}{'…' if len(offenders) > 5 else ''}."
        )
        severity = (
            Severity.CRITICAL if any("AWS" in o for o in offenders)
            else Severity.HIGH
        )
        return Finding(
            check_id="ADO-003",
            title="Variables contain literal secret values",
            severity=severity,
            resource=path,
            description=desc,
            recommendation=(
                "Store secrets in an Azure Key Vault or a Library variable "
                "group with the secret flag set; reference them via "
                "`$(SECRET_NAME)` at runtime. For cloud access prefer "
                "Azure workload identity federation."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # ADO-004 — deployment environment binding
    # ------------------------------------------------------------------

    @staticmethod
    def _ado004_deployment_env(
        path: str, jobs: list[tuple[str, dict[str, Any]]]
    ) -> Finding:
        ungated: list[str] = []
        for job_loc, job in jobs:
            if not isinstance(job.get("deployment"), str):
                continue
            env = job.get("environment")
            if not env:
                ungated.append(job_loc)
        passed = not ungated
        desc = (
            "Every deployment job binds an `environment`."
            if passed else
            f"{len(ungated)} deployment job(s) have no `environment:` "
            f"binding: {', '.join(ungated)}. Without it, ADO cannot enforce "
            f"approvals, checks, or deployment history against a named "
            f"resource."
        )
        return Finding(
            check_id="ADO-004",
            title="Deployment job missing environment binding",
            severity=Severity.MEDIUM,
            resource=path,
            description=desc,
            recommendation=(
                "Add `environment: <name>` to every `deployment:` job. "
                "Configure approvals, required branches, and business-hours "
                "checks on the matching Environment in the ADO UI."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # ADO-005 — container image pinning
    # ------------------------------------------------------------------

    @classmethod
    def _ado005_container_pinning(
        cls, path: str, doc: dict[str, Any],
        jobs: list[tuple[str, dict[str, Any]]],
    ) -> Finding:
        # Container images can be declared at:
        # - resources.containers[].image
        # - pool.container (reference to a resource above, ignore)
        # - job.container (string image ref or dict with image:)
        unpinned: list[str] = []

        # resources.containers[]
        resources = doc.get("resources", {})
        if isinstance(resources, dict):
            for rc in resources.get("containers", []) or []:
                if isinstance(rc, dict):
                    img = rc.get("image")
                    name = rc.get("container", "")
                    if isinstance(img, str):
                        reason = cls._image_reason(img)
                        if reason:
                            unpinned.append(f"resources.containers[{name}]: {reason}")

        # per-job container
        for job_loc, job in jobs:
            c = job.get("container")
            img = None
            if isinstance(c, str):
                # Could be an image ref or a reference to a resource name.
                # If it looks like "foo:bar" or contains "/", treat as image.
                if ":" in c or "/" in c or "." in c:
                    img = c
            elif isinstance(c, dict):
                i = c.get("image")
                if isinstance(i, str):
                    img = i
            if img:
                reason = cls._image_reason(img)
                if reason:
                    unpinned.append(f"{job_loc}.container: {reason}")

        passed = not unpinned
        desc = (
            "Every container image is pinned to a specific version or digest."
            if passed else
            f"{len(unpinned)} container image(s) are floating / untagged: "
            f"{', '.join(unpinned[:5])}{'…' if len(unpinned) > 5 else ''}."
        )
        return Finding(
            check_id="ADO-005",
            title="Container image not pinned to specific version",
            severity=Severity.HIGH,
            resource=path,
            description=desc,
            recommendation=(
                "Reference images by `@sha256:<digest>` or at minimum a full "
                "immutable version tag. Avoid `:latest` and untagged refs."
            ),
            passed=passed,
        )

    @staticmethod
    def _image_reason(img: str) -> str | None:
        """Return a human reason the image is unpinned, or None if it's OK."""
        if _DIGEST_RE.search(img):
            return None
        if ":" not in img.rsplit("/", 1)[-1]:
            return f"{img} (no tag)"
        tag = img.rsplit(":", 1)[1]
        if tag == "latest" or not _VERSION_TAG_RE.search(img):
            return img
        return None


def _is_quoted_assignment(line: str) -> bool:
    """Heuristic — ``VAR="$(Build.SourceBranch)"`` captures, doesn't execute."""
    return bool(re.match(r'\s*\w+="[^"]*\$\([^)]+\)[^"]*"\s*$', line))
