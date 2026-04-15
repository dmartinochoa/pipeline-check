"""GitHub Actions workflow security checks.

GHA-001  Action not pinned to commit SHA                HIGH      CICD-SEC-3
GHA-002  pull_request_target checks out PR head         CRITICAL  CICD-SEC-4
GHA-003  Script injection via untrusted context         HIGH      CICD-SEC-4
GHA-004  Workflow has no explicit permissions block     MEDIUM    CICD-SEC-5
GHA-005  AWS auth uses long-lived access keys           MEDIUM    CICD-SEC-6
GHA-006  Artifacts not signed (no cosign/sigstore step) MEDIUM    ESF-D-SIGN-ARTIFACTS
GHA-007  SBOM not produced (no CycloneDX/syft step)     MEDIUM    ESF-D-SBOM
GHA-008  Credential-shaped literal in workflow body     CRITICAL  CICD-SEC-6
"""
from __future__ import annotations

import re
from typing import Any

from .._secrets import find_secret_values
from ..base import Finding, Severity, has_sbom, has_signing
from .base import GitHubBaseCheck, iter_jobs, iter_steps, workflow_triggers

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# Untrusted attacker-controllable context expressions inside `run:` bodies.
# Not exhaustive — covers the high-signal fields flagged by StepSecurity /
# GitHub Security Lab.
_UNTRUSTED_CONTEXT_RE = re.compile(
    r"\$\{\{\s*github\.event\.(?:"
    r"issue\.(?:title|body)"
    r"|pull_request\.(?:title|body|head\.ref|head\.label)"
    r"|comment\.body"
    r"|review\.body"
    r"|pages\.[^\}]*?\.page_name"
    r"|head_commit\.(?:message|author\.(?:name|email))"
    r"|discussion\.(?:title|body)"
    r"|workflow_run\.head_branch"
    r")\s*\}\}"
)

_PR_HEAD_REF_RE = re.compile(
    r"\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}"
)


class WorkflowChecks(GitHubBaseCheck):
    """Runs every GHA-XXX check against the loaded workflows."""

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for wf in self.ctx.workflows:
            findings.extend(self._check_workflow(wf.path, wf.data))
        return findings

    def _check_workflow(self, path: str, wf: dict[str, Any]) -> list[Finding]:
        return [
            self._gha001_pinned_actions(path, wf),
            self._gha002_pull_request_target(path, wf),
            self._gha003_script_injection(path, wf),
            self._gha004_permissions(path, wf),
            self._gha005_aws_long_lived(path, wf),
            self._gha006_signing(path, wf),
            self._gha007_sbom(path, wf),
            self._gha008_literal_secrets(path, wf),
        ]

    # ------------------------------------------------------------------
    # GHA-008 — credential-shaped literal anywhere in the workflow
    # ------------------------------------------------------------------

    @staticmethod
    def _gha008_literal_secrets(path: str, wf: dict[str, Any]) -> Finding:
        hits = find_secret_values(wf)
        passed = not hits
        desc = (
            "No string in the workflow matches a known credential pattern."
            if passed else
            f"Workflow contains {len(hits)} literal value(s) matching known "
            f"credential patterns (AWS keys, GitHub tokens, Slack tokens, JWTs): "
            f"{', '.join(hits[:5])}{'…' if len(hits) > 5 else ''}. "
            f"Secrets committed to YAML are visible in every fork and in every "
            f"build log, and must be considered compromised."
        )
        return Finding(
            check_id="GHA-008",
            title="Credential-shaped literal in workflow body",
            severity=Severity.CRITICAL,
            resource=path,
            description=desc,
            recommendation=(
                "Rotate the exposed credential immediately. Move the value to "
                "an encrypted repository or environment secret and reference "
                "it via `${{ secrets.NAME }}`. For cloud access, prefer OIDC "
                "federation over long-lived keys."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # GHA-006 — artifact signing
    # ------------------------------------------------------------------

    @staticmethod
    def _gha006_signing(path: str, wf: dict[str, Any]) -> Finding:
        passed = has_signing(wf)
        desc = (
            "Workflow invokes a signing tool (cosign / sigstore / slsa-github-"
            "generator / notation)."
            if passed else
            "Workflow produces build artifacts but does not invoke any "
            "signing tool (cosign, sigstore, slsa-github-generator, notation). "
            "Unsigned artifacts cannot be verified downstream, so a tampered "
            "build is indistinguishable from a legitimate one."
        )
        return Finding(
            check_id="GHA-006",
            title="Artifacts not signed (no cosign/sigstore step)",
            severity=Severity.MEDIUM,
            resource=path,
            description=desc,
            recommendation=(
                "Add a signing step — e.g. `sigstore/cosign-installer` followed "
                "by `cosign sign`, or `slsa-framework/slsa-github-generator` for "
                "keyless SLSA provenance. Publish the signature alongside the "
                "artifact and verify it at consumption time."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # GHA-007 — SBOM generation
    # ------------------------------------------------------------------

    @staticmethod
    def _gha007_sbom(path: str, wf: dict[str, Any]) -> Finding:
        passed = has_sbom(wf)
        desc = (
            "Workflow produces an SBOM (CycloneDX / syft / anchore / Trivy-SBOM)."
            if passed else
            "Workflow does not produce a software bill of materials (SBOM). "
            "Without an SBOM, downstream consumers cannot audit the exact set "
            "of dependencies shipped in the artifact, delaying vulnerability "
            "response when a transitive dep is disclosed."
        )
        return Finding(
            check_id="GHA-007",
            title="SBOM not produced (no CycloneDX/syft/Trivy-SBOM step)",
            severity=Severity.MEDIUM,
            resource=path,
            description=desc,
            recommendation=(
                "Add an SBOM generation step — `anchore/sbom-action`, "
                "`syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or "
                "Microsoft's `sbom-tool`. Attach the SBOM to the release so "
                "consumers can ingest it into their vuln-management pipeline."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # GHA-001 — pin actions by SHA
    # ------------------------------------------------------------------

    @staticmethod
    def _gha001_pinned_actions(path: str, wf: dict[str, Any]) -> Finding:
        unpinned: list[str] = []
        for _, job in iter_jobs(wf):
            for step in iter_steps(job):
                uses = step.get("uses")
                if not isinstance(uses, str) or "@" not in uses:
                    continue
                # Docker image refs (``docker://``) and local path refs
                # (``./action``) are not subject to this check.
                if uses.startswith(("docker://", "./", "/")):
                    continue
                ref = uses.rsplit("@", 1)[1]
                if not _SHA_RE.match(ref):
                    unpinned.append(uses)
        passed = not unpinned
        desc = (
            "Every `uses:` reference is pinned to a 40-char commit SHA."
            if passed else
            f"{len(unpinned)} action reference(s) are pinned to a tag or branch "
            f"rather than a commit SHA: {', '.join(sorted(set(unpinned))[:5])}"
            f"{'…' if len(set(unpinned)) > 5 else ''}. "
            f"Tags and branches can be moved to malicious commits by whoever "
            f"controls the upstream repository."
        )
        return Finding(
            check_id="GHA-001",
            title="Action not pinned to commit SHA",
            severity=Severity.HIGH,
            resource=path,
            description=desc,
            recommendation=(
                "Replace tag/branch references (`@v4`, `@main`) with the full "
                "40-char commit SHA. Use Dependabot or StepSecurity to keep the "
                "pins fresh."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # GHA-002 — pull_request_target + checkout of PR head
    # ------------------------------------------------------------------

    @staticmethod
    def _gha002_pull_request_target(path: str, wf: dict[str, Any]) -> Finding:
        triggers = workflow_triggers(wf)
        if "pull_request_target" not in triggers:
            return Finding(
                check_id="GHA-002",
                title="pull_request_target checks out PR head",
                severity=Severity.CRITICAL,
                resource=path,
                description="Workflow is not triggered by pull_request_target.",
                recommendation="No action required.",
                passed=True,
            )
        offending: list[str] = []
        for job_id, job in iter_jobs(wf):
            for idx, step in enumerate(iter_steps(job)):
                uses = step.get("uses")
                if not isinstance(uses, str):
                    continue
                if not uses.startswith("actions/checkout@"):
                    continue
                ref = ((step.get("with") or {}).get("ref") or "")
                if isinstance(ref, str) and _PR_HEAD_REF_RE.search(ref):
                    offending.append(f"{job_id}[{idx}]")
        passed = not offending
        desc = (
            "pull_request_target workflow does not check out untrusted PR head code."
            if passed else
            f"pull_request_target workflow explicitly checks out the PR head "
            f"ref in steps: {', '.join(offending)}. This executes attacker-"
            f"controlled code with a write-scope GITHUB_TOKEN and access to "
            f"repository secrets."
        )
        return Finding(
            check_id="GHA-002",
            title="pull_request_target checks out PR head",
            severity=Severity.CRITICAL,
            resource=path,
            description=desc,
            recommendation=(
                "Use `pull_request` instead of `pull_request_target` for any "
                "workflow that must run untrusted code. If you need write "
                "scope, split the workflow: a `pull_request_target` job that "
                "labels the PR, and a separate `pull_request`-triggered job "
                "that builds it with read-only secrets."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # GHA-003 — script injection via untrusted context
    # ------------------------------------------------------------------

    @staticmethod
    def _gha003_script_injection(path: str, wf: dict[str, Any]) -> Finding:
        offenders: list[str] = []
        for job_id, job in iter_jobs(wf):
            for idx, step in enumerate(iter_steps(job)):
                run = step.get("run")
                if not isinstance(run, str):
                    continue
                if _UNTRUSTED_CONTEXT_RE.search(run):
                    offenders.append(f"{job_id}[{idx}]")
        passed = not offenders
        desc = (
            "No `run:` block interpolates attacker-controllable context fields."
            if passed else
            f"`run:` blocks interpolate untrusted github.event fields (PR "
            f"title/body, commit messages, comments) directly into shell "
            f"commands in: {', '.join(offenders)}. These fields can contain "
            f"shell metacharacters that execute as part of the build."
        )
        return Finding(
            check_id="GHA-003",
            title="Script injection via untrusted context",
            severity=Severity.HIGH,
            resource=path,
            description=desc,
            recommendation=(
                "Pass untrusted values through an intermediate `env:` variable "
                "and reference that variable from the shell script. GitHub's "
                "expression evaluation happens before shell quoting, so inline "
                "`${{ github.event.* }}` is always unsafe."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # GHA-004 — explicit permissions block
    # ------------------------------------------------------------------

    @staticmethod
    def _gha004_permissions(path: str, wf: dict[str, Any]) -> Finding:
        if "permissions" in wf:
            return Finding(
                check_id="GHA-004",
                title="Workflow has no explicit permissions block",
                severity=Severity.MEDIUM,
                resource=path,
                description="Workflow declares a top-level permissions block.",
                recommendation="No action required.",
                passed=True,
            )
        jobs_missing = [
            job_id for job_id, job in iter_jobs(wf) if "permissions" not in job
        ]
        passed = not jobs_missing
        desc = (
            "Every job declares its own permissions block."
            if passed else
            f"Workflow has no top-level permissions block and {len(jobs_missing)} "
            f"job(s) without a per-job permissions block: {', '.join(jobs_missing)}. "
            f"The GITHUB_TOKEN will default to repository-wide scope, giving any "
            f"compromised step more privilege than necessary."
        )
        return Finding(
            check_id="GHA-004",
            title="Workflow has no explicit permissions block",
            severity=Severity.MEDIUM,
            resource=path,
            description=desc,
            recommendation=(
                "Add a top-level `permissions:` block (start with `contents: "
                "read`) and grant additional scopes only on the specific jobs "
                "that need them."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # GHA-005 — long-lived AWS credentials instead of OIDC
    # ------------------------------------------------------------------

    @staticmethod
    def _gha005_aws_long_lived(path: str, wf: dict[str, Any]) -> Finding:
        static_keys = False
        oidc_role = False
        for _, job in iter_jobs(wf):
            for step in iter_steps(job):
                uses = step.get("uses") or ""
                if isinstance(uses, str) and uses.startswith(
                    "aws-actions/configure-aws-credentials@"
                ):
                    w = step.get("with") or {}
                    if "role-to-assume" in w:
                        oidc_role = True
                    if "aws-access-key-id" in w or "aws-secret-access-key" in w:
                        static_keys = True
                # Also flag raw env: references to classic access key secrets.
                env = step.get("env") or {}
                if isinstance(env, dict):
                    for value in env.values():
                        if isinstance(value, str) and (
                            "AWS_ACCESS_KEY_ID" in value
                            or "AWS_SECRET_ACCESS_KEY" in value
                        ):
                            static_keys = True
        wf_env = wf.get("env") or {}
        if isinstance(wf_env, dict):
            for value in wf_env.values():
                if isinstance(value, str) and (
                    "AWS_ACCESS_KEY_ID" in value
                    or "AWS_SECRET_ACCESS_KEY" in value
                ):
                    static_keys = True
        if not static_keys and not oidc_role:
            return Finding(
                check_id="GHA-005",
                title="AWS auth uses long-lived access keys",
                severity=Severity.MEDIUM,
                resource=path,
                description="Workflow does not configure AWS credentials.",
                recommendation="No action required.",
                passed=True,
            )
        passed = oidc_role and not static_keys
        if passed:
            desc = "AWS credentials are obtained via OIDC (`role-to-assume`)."
        elif static_keys:
            desc = (
                "Workflow authenticates to AWS with long-lived access keys "
                "(AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY). These can't be "
                "rotated on a fine-grained schedule and remain valid until "
                "manually revoked."
            )
        else:
            desc = "AWS credential configuration detected but could not be classified."
        return Finding(
            check_id="GHA-005",
            title="AWS auth uses long-lived access keys",
            severity=Severity.MEDIUM,
            resource=path,
            description=desc,
            recommendation=(
                "Use `aws-actions/configure-aws-credentials` with "
                "`role-to-assume` + `permissions: id-token: write` to obtain "
                "short-lived credentials via OIDC. Remove the static "
                "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY secrets."
            ),
            passed=passed,
        )
