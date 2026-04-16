"""Bitbucket Pipelines security checks.

BB-001  pipe: action not pinned to exact version / SHA       HIGH      CICD-SEC-3
BB-002  Script injection via attacker-controllable context   HIGH      CICD-SEC-4
BB-003  Variables / definitions contain literal secrets      CRITICAL  CICD-SEC-6
BB-004  Deploy step missing `deployment:` environment gate   MEDIUM    CICD-SEC-1
BB-005  Step has no `max-time` — unbounded build             MEDIUM    CICD-SEC-7
BB-006  Artifacts not signed                                 MEDIUM    ESF-D-SIGN-ARTIFACTS
BB-007  SBOM not produced                                    MEDIUM    ESF-D-SBOM
BB-008  Credential-shaped literal in pipeline body           CRITICAL  CICD-SEC-6
BB-009  pipe: pinned by version rather than sha256 digest    LOW       CICD-SEC-3
"""
from __future__ import annotations

import re
from typing import Any

from .._secrets import find_secret_values
from ..base import Finding, Severity, has_sbom, has_signing, is_quoted_assignment
from .base import BitbucketBaseCheck, iter_steps, step_scripts

# Bitbucket pipe ref: "org/name:version". Pinned = digest-looking, semver x.y.z,
# or 40-char SHA. Unpinned = single integer / missing tag / "latest".
_VER_OK_RE = re.compile(r":(?:\d+\.\d+(?:\.\d+)?(?:[-.][\w\d]+)*|[0-9a-f]{40})$")

# Attacker-controllable Bitbucket predefined variables.
# BITBUCKET_BRANCH / BITBUCKET_TAG are writable by anyone who can push a ref.
# BITBUCKET_PR_* include PR metadata for pull-request pipelines.
_UNTRUSTED_VAR_RE = re.compile(
    r"\$\{?(?:"
    r"BITBUCKET_BRANCH|BITBUCKET_TAG"
    r"|BITBUCKET_PR_DESTINATION_BRANCH|BITBUCKET_PR_ID"
    r"|BITBUCKET_BOOKMARK"
    r")\}?"
)

_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_SECRETISH_KEY_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|apikey|api_key|private_key)"
)

_DEPLOY_RE = re.compile(r"(?i)(deploy|release|publish|promote)")


class BitbucketPipelineChecks(BitbucketBaseCheck):
    """Runs every BB-XXX check against the loaded pipelines."""

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for p in self.ctx.pipelines:
            findings.extend(self._check_doc(p.path, p.data))
        return findings

    def _check_doc(self, path: str, doc: dict[str, Any]) -> list[Finding]:
        steps = list(iter_steps(doc))
        return [
            self._bb001_pipe_pinning(path, steps),
            self._bb002_script_injection(path, steps),
            self._bb003_literal_secrets(path, doc, steps),
            self._bb004_deploy_env(path, steps),
            self._bb005_max_time(path, steps),
            self._bb006_signing(path, doc),
            self._bb007_sbom(path, doc),
            self._bb008_literal_secrets(path, doc),
            self._bb009_digest_pinning(path, steps),
        ]

    # ------------------------------------------------------------------
    # BB-009 — prefer sha256 digest for pipe refs
    # ------------------------------------------------------------------

    @staticmethod
    def _bb009_digest_pinning(
        path: str, steps: list[tuple[str, dict[str, Any]]]
    ) -> Finding:
        tagged: list[str] = []
        for loc, step in steps:
            script = step.get("script")
            if not isinstance(script, list):
                continue
            for entry in script:
                ref: str | None = None
                if isinstance(entry, dict) and "pipe" in entry:
                    v = entry["pipe"]
                    if isinstance(v, str):
                        ref = v.strip()
                elif isinstance(entry, str):
                    m = re.match(r"\s*pipe:\s*(\S+)", entry)
                    if m:
                        ref = m.group(1).strip().strip('"').strip("'")
                if not ref or "@sha256:" in ref:
                    continue
                tagged.append(f"{loc}: {ref}")
        passed = not tagged
        desc = (
            "Every `pipe:` reference is pinned by sha256 digest."
            if passed else
            f"{len(tagged)} `pipe:` reference(s) are pinned by version "
            f"rather than digest: {', '.join(tagged[:5])}"
            f"{'…' if len(tagged) > 5 else ''}."
        )
        return Finding(
            check_id="BB-009",
            title="pipe: pinned by version rather than sha256 digest",
            severity=Severity.LOW,
            resource=path,
            description=desc,
            recommendation=(
                "Resolve each pipe to its digest (`docker buildx imagetools "
                "inspect bitbucketpipelines/<name>:<ver>`) and reference it "
                "via `@sha256:<digest>`."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # BB-008 — credential-shaped literal anywhere in the pipeline
    # ------------------------------------------------------------------

    @staticmethod
    def _bb008_literal_secrets(path: str, doc: dict[str, Any]) -> Finding:
        hits = find_secret_values(doc)
        passed = not hits
        desc = (
            "No string in the pipeline matches a known credential pattern."
            if passed else
            f"Pipeline contains {len(hits)} literal value(s) matching known "
            f"credential patterns (AWS keys, GitHub tokens, Slack tokens, JWTs): "
            f"{', '.join(hits[:5])}{'…' if len(hits) > 5 else ''}."
        )
        return Finding(
            check_id="BB-008",
            title="Credential-shaped literal in pipeline body",
            severity=Severity.CRITICAL,
            resource=path,
            description=desc,
            recommendation=(
                "Rotate the exposed credential. Move the value to a Secured "
                "Repository or Deployment Variable and reference it by name."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # BB-006 — artifact signing
    # ------------------------------------------------------------------

    @staticmethod
    def _bb006_signing(path: str, doc: dict[str, Any]) -> Finding:
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
            check_id="BB-006",
            title="Artifacts not signed",
            severity=Severity.MEDIUM,
            resource=path,
            description=desc,
            recommendation=(
                "Add a step that runs `cosign sign` against the built image or "
                "archive, using Bitbucket OIDC for keyless signing where "
                "possible. Publish the signature next to the artifact and "
                "verify it at deploy time."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # BB-007 — SBOM generation
    # ------------------------------------------------------------------

    @staticmethod
    def _bb007_sbom(path: str, doc: dict[str, Any]) -> Finding:
        passed = has_sbom(doc)
        desc = (
            "Pipeline produces an SBOM (CycloneDX / syft / Trivy-SBOM)."
            if passed else
            "Pipeline does not produce a software bill of materials (SBOM). "
            "Without an SBOM, downstream consumers cannot audit the exact set "
            "of dependencies shipped in the artifact."
        )
        return Finding(
            check_id="BB-007",
            title="SBOM not produced",
            severity=Severity.MEDIUM,
            resource=path,
            description=desc,
            recommendation=(
                "Add an SBOM step — `syft . -o cyclonedx-json`, Trivy with "
                "`--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the "
                "SBOM as a build artifact."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # BB-001 — pipe pinning
    # ------------------------------------------------------------------

    @staticmethod
    def _bb001_pipe_pinning(path: str, steps: list[tuple[str, dict[str, Any]]]) -> Finding:
        unpinned: list[str] = []
        for loc, step in steps:
            script = step.get("script")
            if not isinstance(script, list):
                continue
            for entry in script:
                ref: str | None = None
                if isinstance(entry, dict) and "pipe" in entry:
                    v = entry["pipe"]
                    if isinstance(v, str):
                        ref = v.strip()
                elif isinstance(entry, str):
                    m = re.match(r"\s*pipe:\s*(\S+)", entry)
                    if m:
                        ref = m.group(1).strip().strip('"').strip("'")
                if ref is None:
                    continue
                if "@sha256:" in ref:
                    continue
                if ":" not in ref:
                    unpinned.append(f"{loc}: {ref}")
                    continue
                if not _VER_OK_RE.search(ref):
                    unpinned.append(f"{loc}: {ref}")
        passed = not unpinned
        desc = (
            "All `pipe:` references are pinned to a specific version."
            if passed else
            f"{len(unpinned)} `pipe:` reference(s) use a floating / major-only "
            f"tag: {', '.join(unpinned[:5])}{'…' if len(unpinned) > 5 else ''}."
        )
        return Finding(
            check_id="BB-001",
            title="pipe: action not pinned to exact version",
            severity=Severity.HIGH,
            resource=path,
            description=desc,
            recommendation=(
                "Pin every `pipe:` to a full semver tag (e.g. "
                "`atlassian/aws-s3-deploy:1.4.0`) or to an immutable SHA. "
                "Floating majors like `:1` can roll to new code silently."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # BB-002 — script injection
    # ------------------------------------------------------------------

    @staticmethod
    def _bb002_script_injection(path: str, steps: list[tuple[str, dict[str, Any]]]) -> Finding:
        offenders: list[str] = []
        for loc, step in steps:
            for line in step_scripts(step):
                if _UNTRUSTED_VAR_RE.search(line) and not is_quoted_assignment(line):
                    offenders.append(loc)
                    break
        passed = not offenders
        desc = (
            "No script interpolates attacker-controllable ref / PR variables."
            if passed else
            f"Script(s) in step(s) {', '.join(sorted(set(offenders)))} "
            f"interpolate $BITBUCKET_BRANCH / $BITBUCKET_TAG / $BITBUCKET_PR_* "
            f"directly into shell commands. A crafted branch or tag name can "
            f"execute inline."
        )
        return Finding(
            check_id="BB-002",
            title="Script injection via attacker-controllable context",
            severity=Severity.HIGH,
            resource=path,
            description=desc,
            recommendation=(
                "Always double-quote interpolations of ref-derived variables "
                "(`\"$BITBUCKET_BRANCH\"`). Avoid passing them to `eval`, "
                "`sh -c`, or unquoted command arguments."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # BB-003 — literal secrets
    # ------------------------------------------------------------------

    @staticmethod
    def _bb003_literal_secrets(
        path: str,
        doc: dict[str, Any],
        steps: list[tuple[str, dict[str, Any]]],
    ) -> Finding:
        offenders: list[str] = []

        def _scan(varmap: Any, where: str) -> None:
            if not isinstance(varmap, dict):
                return
            for key, value in varmap.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    continue
                if _AWS_KEY_RE.search(value):
                    offenders.append(f"{where}.{key} (AWS access key)")
                elif _SECRETISH_KEY_RE.search(key) and value and "$" not in value:
                    offenders.append(f"{where}.{key}")

        # Bitbucket's only in-file variable surface is definitions.variables
        # (per-environment custom variables) and inline `variables:` on a step
        # is not supported; but scan both out of caution.
        defs = doc.get("definitions")
        if isinstance(defs, dict):
            _scan(defs.get("variables"), "definitions.variables")
        for loc, step in steps:
            _scan(step.get("variables"), loc)

        passed = not offenders
        desc = (
            "No YAML-declared variable holds a literal credential-shaped value."
            if passed else
            f"{len(offenders)} variable(s) contain literal credential values: "
            f"{', '.join(offenders[:5])}{'…' if len(offenders) > 5 else ''}."
        )
        severity = Severity.CRITICAL if any("AWS" in o for o in offenders) else (
            Severity.HIGH if offenders else Severity.HIGH
        )
        return Finding(
            check_id="BB-003",
            title="Variables contain literal secret values",
            severity=severity,
            resource=path,
            description=desc,
            recommendation=(
                "Store credentials as Repository / Deployment Variables in "
                "Bitbucket's Pipelines settings with the 'Secured' flag, and "
                "reference them by name. Prefer short-lived OIDC tokens for "
                "cloud access."
            ),
            passed=passed,
        )

    # ------------------------------------------------------------------
    # BB-004 — deploy step environment gate
    # ------------------------------------------------------------------

    @classmethod
    def _bb004_deploy_env(cls, path: str, steps: list[tuple[str, dict[str, Any]]]) -> Finding:
        ungated: list[str] = []
        for loc, step in steps:
            name = step.get("name") or ""
            if not isinstance(name, str):
                name = ""
            is_deploy = bool(cls._DEPLOY_RE.search(name))
            # Also flag a step that uses a deploy-ish pipe. Pipes are typically
            # parsed as ``{"pipe": "org/name:ver"}`` dict entries in the script
            # list; fall back to string form for compat.
            script = step.get("script")
            if not is_deploy and isinstance(script, list):
                for entry in script:
                    if isinstance(entry, dict):
                        v = entry.get("pipe")
                        if isinstance(v, str) and cls._DEPLOY_RE.search(v):
                            is_deploy = True
                            break
                    elif isinstance(entry, str) and "pipe:" in entry and cls._DEPLOY_RE.search(entry):
                        is_deploy = True
                        break
            if not is_deploy:
                continue
            if not step.get("deployment"):
                ungated.append(loc)
        passed = not ungated
        desc = (
            "All deploy-like steps declare a `deployment:` environment."
            if passed else
            f"{len(ungated)} deploy-like step(s) have no `deployment:` field: "
            f"{', '.join(ungated)}. Without it, Bitbucket cannot enforce "
            f"deployment-scoped variables, approvals, or deployment history."
        )
        return Finding(
            check_id="BB-004",
            title="Deploy step missing `deployment:` environment gate",
            severity=Severity.MEDIUM,
            resource=path,
            description=desc,
            recommendation=(
                "Add `deployment: production` (or `staging` / `test`) to the "
                "step. Configure the matching environment in the repo's "
                "Deployments settings with required reviewers and secured "
                "variables."
            ),
            passed=passed,
        )

    _DEPLOY_RE = _DEPLOY_RE  # class-level alias for readability

    # ------------------------------------------------------------------
    # BB-005 — max-time
    # ------------------------------------------------------------------

    @staticmethod
    def _bb005_max_time(path: str, steps: list[tuple[str, dict[str, Any]]]) -> Finding:
        unbounded: list[str] = []
        for loc, step in steps:
            if "max-time" not in step:
                unbounded.append(loc)
        passed = not unbounded
        desc = (
            "Every step declares a `max-time`."
            if passed else
            f"{len(unbounded)} step(s) have no `max-time` and will run until "
            f"Bitbucket's 120-minute default kills them: "
            f"{', '.join(unbounded[:5])}{'…' if len(unbounded) > 5 else ''}."
        )
        return Finding(
            check_id="BB-005",
            title="Step has no `max-time` — unbounded build",
            severity=Severity.MEDIUM,
            resource=path,
            description=desc,
            recommendation=(
                "Add `max-time: <minutes>` to each step, sized to the 95th "
                "percentile of historical runtime plus margin. Bounded runs "
                "limit the blast radius of a compromised build and prevent "
                "runaway minute consumption."
            ),
            passed=passed,
        )


