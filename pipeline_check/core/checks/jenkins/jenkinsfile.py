"""Jenkins pipeline security checks.

JF-001  Shared library not pinned to a tag or commit              HIGH      CICD-SEC-3
JF-002  Script step interpolates attacker-controllable env var    HIGH      CICD-SEC-4
JF-003  Pipeline uses `agent any` (no executor isolation)         MEDIUM    CICD-SEC-5
JF-004  AWS auth uses long-lived access keys via withCredentials  MEDIUM    CICD-SEC-6
JF-005  Deploy stage missing manual `input` approval              MEDIUM    CICD-SEC-1
JF-006  Artifacts not signed                                      MEDIUM    ESF-D-SIGN-ARTIFACTS
JF-007  SBOM not produced                                         MEDIUM    ESF-D-SBOM
JF-008  Credential-shaped literal in pipeline body                CRITICAL  CICD-SEC-6
JF-009  Agent docker image not pinned to sha256 digest            HIGH      CICD-SEC-3
JF-010  Long-lived AWS keys exposed via `environment { … }`       HIGH      CICD-SEC-6
JF-011  Pipeline has no `buildDiscarder` retention policy          LOW       CICD-SEC-10
JF-012  `load` step pulls Groovy from disk without integrity pin   MEDIUM    CICD-SEC-3
"""
from __future__ import annotations

import re
from typing import Any

from .._secrets import find_secret_values
from ..base import (
    Finding,
    Severity,
    SBOM_DIRECT_TOKENS,
    SIGN_TOKENS,
)
from .base import JenkinsBaseCheck, Jenkinsfile


# A library spec ``my-shared@<ref>`` is pinned when the ref looks like
# a tag (``v1.2.3`` / ``1.2.3``) or a 40-char commit SHA. ``@main``,
# ``@master``, ``@develop`` are treated as floating refs.
_PINNED_REF_RE = re.compile(r"^(?:v?\d+(?:\.\d+){0,2}|[0-9a-f]{40})$")
_FLOATING_REFS = {"main", "master", "develop", "head", "trunk", "latest"}

# Attacker-controllable Jenkins env vars (multibranch / GitHub-source
# plugin populates these from the SCM event):
#   BRANCH_NAME / GIT_BRANCH — pusher controls
#   CHANGE_TITLE / CHANGE_BRANCH / CHANGE_AUTHOR_DISPLAY_NAME — PR author controls
#   TAG_NAME — tag pusher controls
_UNTRUSTED_ENV_RE = re.compile(
    r"\$\{?\s*(?:env\.)?"
    r"(?:BRANCH_NAME|GIT_BRANCH|TAG_NAME"
    r"|CHANGE_TITLE|CHANGE_BRANCH|CHANGE_AUTHOR(?:_DISPLAY_NAME)?)"
    r"\s*\}?"
)

# A ``sh`` / ``bat`` / ``powershell`` step body — captures the string
# argument so we can grep it for env interpolations. Handles single
# and triple quotes.
_SHELL_STEP_RE = re.compile(
    r"(?:sh|bat|powershell|pwsh)\s*\(?\s*"
    r"(?:\"\"\"(?P<triple_d>.*?)\"\"\""
    r"|'''(?P<triple_s>.*?)'''"
    r"|\"(?P<dq>(?:[^\"\\]|\\.)*)\""
    r"|'(?P<sq>(?:[^'\\]|\\.)*)')",
    re.DOTALL,
)

# ``withCredentials`` block referencing an AWS-key binding — the
# `awsAccessKey`/`awsSecretKey` form binds long-lived keys; OIDC-based
# usage uses ``role-based`` plugins that don't appear here.
_AWS_KEY_BINDING_RE = re.compile(
    r"(?:string|usernamePassword|file)?\s*\(?\s*credentialsId\s*:\s*['\"][^'\"]*aws[^'\"]*['\"]",
    re.IGNORECASE,
)
_AWS_KEY_VAR_RE = re.compile(
    r"(?:accessKeyVariable|secretKeyVariable|aws_access_key_id|aws_secret_access_key)",
    re.IGNORECASE,
)

# ``agent { docker { image '<ref>' } }`` — capture the image ref so
# we can apply the same digest-vs-tag-vs-floating logic the YAML
# providers use. Single and double quotes both occur in real
# Jenkinsfiles.
_DOCKER_IMAGE_RE = re.compile(
    r"docker\s*\{\s*[^}]*?\bimage\s+['\"]([^'\"]+)['\"]",
    re.DOTALL,
)
_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
_VERSION_TAG_RE = re.compile(r":[^:]*\d[^:]*$")

# An ``environment { KEY = '...' }`` declaration where the key looks
# like a long-lived AWS credential. The Groovy assignment uses ``=``
# (not ``:`` like YAML), and the value is single- or double-quoted.
# The leading boundary is start-of-line OR whitespace OR ``{`` so the
# inline form ``environment { AWS_ACCESS_KEY_ID = '...' }`` matches
# alongside the multiline form.
_ENV_AWS_KEY_RE = re.compile(
    r"(?:^|[\s{])(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\s*=\s*['\"]([^'\"]+)['\"]",
    re.MULTILINE,
)

# ``options { buildDiscarder(...) }`` is the canonical declarative
# form; ``properties([buildDiscarder(...)])`` is the scripted
# equivalent. Either satisfies the retention check.
_BUILD_DISCARDER_RE = re.compile(
    r"\b(?:buildDiscarder|logRotator)\s*\(",
)

# ``load 'path/to/file.groovy'`` evaluates whatever the path resolves
# to at build time. Without an integrity check (Jenkins has no native
# one), this is dynamic-include territory — flag every occurrence.
_LOAD_STEP_RE = re.compile(
    r"\bload\s+['\"]([^'\"]+\.groovy)['\"]",
)


class JenkinsfileChecks(JenkinsBaseCheck):
    """Runs every JF-XXX check across every loaded Jenkinsfile."""

    def run(self) -> list[Finding]:
        out: list[Finding] = []
        for jf in self.ctx.files:
            out.extend(self._check_file(jf))
        return out

    def _check_file(self, jf: Jenkinsfile) -> list[Finding]:
        return [
            self._jf001_library_pinning(jf),
            self._jf002_script_injection(jf),
            self._jf003_agent_any(jf),
            self._jf004_aws_long_lived(jf),
            self._jf005_deploy_input(jf),
            self._jf006_signing(jf),
            self._jf007_sbom(jf),
            self._jf008_literal_secrets(jf),
            self._jf009_docker_image_pinning(jf),
            self._jf010_env_aws_keys(jf),
            self._jf011_build_discarder(jf),
            self._jf012_load_step(jf),
        ]

    # ─── JF-001 — shared library pinning ──────────────────────────────

    @staticmethod
    def _jf001_library_pinning(jf: Jenkinsfile) -> Finding:
        unpinned: list[str] = []
        for spec in jf.library_refs:
            # ``my-lib`` (no @ref) → uses the default branch — floating.
            # ``my-lib@v1.2.3`` → pinned. ``my-lib@main`` → floating.
            if "@" not in spec:
                unpinned.append(f"{spec} (no @ref)")
                continue
            _, ref = spec.rsplit("@", 1)
            if ref.lower() in _FLOATING_REFS or not _PINNED_REF_RE.match(ref):
                unpinned.append(spec)
        passed = not unpinned
        desc = (
            "Every @Library reference is pinned to a tag or commit SHA."
            if passed else
            f"{len(unpinned)} @Library reference(s) point at a floating branch "
            f"or default ref: {', '.join(sorted(set(unpinned))[:5])}"
            f"{'…' if len(set(unpinned)) > 5 else ''}. Whoever controls the "
            f"upstream library can ship code into your build by pushing to "
            f"that branch."
        )
        return Finding(
            check_id="JF-001",
            title="Shared library not pinned to a tag or commit",
            severity=Severity.HIGH,
            resource=jf.path,
            description=desc,
            recommendation=(
                "Pin every `@Library('name@<ref>')` to a release tag (e.g. "
                "`@v1.4.2`) or a 40-char commit SHA. Configure the library "
                "in Jenkins with 'Allow default version to be overridden' "
                "disabled so a pipeline can't escape the pin."
            ),
            passed=passed,
        )

    # ─── JF-002 — script injection ────────────────────────────────────

    @staticmethod
    def _jf002_script_injection(jf: Jenkinsfile) -> Finding:
        offenders: list[str] = []
        for m in _SHELL_STEP_RE.finditer(jf.text):
            body = (
                m.group("triple_d") or m.group("triple_s")
                or m.group("dq") or m.group("sq") or ""
            )
            # Single-quoted strings in Groovy don't interpolate, so a
            # ``$BRANCH_NAME`` inside ``'...'`` is a literal — only flag
            # interpolation-capable contexts.
            if m.group("sq") is not None or m.group("triple_s") is not None:
                continue
            if _UNTRUSTED_ENV_RE.search(body):
                # Use the offset as a stable identifier in the message.
                line_no = jf.text[: m.start()].count("\n") + 1
                offenders.append(f"line {line_no}")
        passed = not offenders
        desc = (
            "No shell step interpolates attacker-controllable Jenkins env vars."
            if passed else
            f"Shell step(s) at {', '.join(offenders)} interpolate "
            f"$BRANCH_NAME / $CHANGE_TITLE / $TAG_NAME directly into a "
            f"double-quoted command. A crafted branch or tag name can "
            f"execute inline."
        )
        return Finding(
            check_id="JF-002",
            title="Script step interpolates attacker-controllable env var",
            severity=Severity.HIGH,
            resource=jf.path,
            description=desc,
            recommendation=(
                "Switch the affected `sh`/`bat`/`powershell` step to a "
                "single-quoted string (Groovy doesn't interpolate single "
                "quotes), and pass values through a quoted shell variable "
                "(`sh 'echo \"$BRANCH\"'` after `withEnv([...])`)."
            ),
            passed=passed,
        )

    # ─── JF-003 — agent any ───────────────────────────────────────────

    @staticmethod
    def _jf003_agent_any(jf: Jenkinsfile) -> Finding:
        # ``agent any`` at the top of a pipeline {} block is the
        # broadest possible executor scope. ``agent { label '...' }``
        # or ``agent { docker { ... } }`` is a scoped equivalent.
        passed = not re.search(r"\bagent\s+any\b", jf.text)
        desc = (
            "Pipeline does not use `agent any`."
            if passed else
            "Pipeline declares `agent any`, so any registered executor "
            "(including ones with broader IAM/file-system access than "
            "this build needs) can be picked. A compromise of one job "
            "blast-radiates across every executor pool."
        )
        return Finding(
            check_id="JF-003",
            title="Pipeline uses `agent any` (no executor isolation)",
            severity=Severity.MEDIUM,
            resource=jf.path,
            description=desc,
            recommendation=(
                "Replace `agent any` with `agent { label 'build-pool' }` "
                "(targeting a labelled pool) or `agent { docker { image "
                "'...' } }` (ephemeral container). Reserve broad-access "
                "agents for jobs that genuinely need them."
            ),
            passed=passed,
        )

    # ─── JF-004 — long-lived AWS keys ─────────────────────────────────

    @staticmethod
    def _jf004_aws_long_lived(jf: Jenkinsfile) -> Finding:
        binding = bool(_AWS_KEY_BINDING_RE.search(jf.text))
        var = bool(_AWS_KEY_VAR_RE.search(jf.text))
        # Only flag when both signals are present — credentialsId
        # alone could be an OIDC role binding.
        passed = not (binding and var)
        desc = (
            "Pipeline does not bind long-lived AWS access keys."
            if passed else
            "Pipeline uses `withCredentials` to bind long-lived "
            "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY values. These "
            "credentials can't be rotated on a fine-grained schedule "
            "and remain valid until manually revoked."
        )
        return Finding(
            check_id="JF-004",
            title="AWS auth uses long-lived access keys via withCredentials",
            severity=Severity.MEDIUM,
            resource=jf.path,
            description=desc,
            recommendation=(
                "Switch to the AWS plugin's IAM-role / OIDC binding (e.g. "
                "`withAWS(role: 'arn:aws:iam::…:role/jenkins')`) so each "
                "build assumes a short-lived role. Remove the static "
                "AWS_ACCESS_KEY_ID secret from the Jenkins credentials "
                "store once the role is in place."
            ),
            passed=passed,
        )

    # ─── JF-005 — deploy stage approval ───────────────────────────────

    _DEPLOY_RE = re.compile(r"(?i)(deploy|release|publish|promote)")

    @classmethod
    def _jf005_deploy_input(cls, jf: Jenkinsfile) -> Finding:
        ungated: list[str] = []
        for name, body in jf.stages:
            if not cls._DEPLOY_RE.search(name):
                continue
            # ``input`` step (declarative ``input { ... }`` or scripted
            # ``input message: '...'``) is the canonical manual gate.
            has_input = bool(re.search(r"\binput\s*[({]", body)) or \
                bool(re.search(r"\binput\s+message\s*:", body))
            if not has_input:
                ungated.append(name)
        passed = not ungated
        desc = (
            "All deploy-like stages declare a manual `input` approval gate."
            if passed else
            f"{len(ungated)} deploy-like stage(s) run without a manual "
            f"`input` gate: {', '.join(ungated)}. Any push that triggers "
            f"the pipeline ships to the target with no human review."
        )
        return Finding(
            check_id="JF-005",
            title="Deploy stage missing manual `input` approval",
            severity=Severity.MEDIUM,
            resource=jf.path,
            description=desc,
            recommendation=(
                "Add an `input` step to every deploy-like stage (e.g. "
                "`input message: 'Promote to prod?', submitter: 'releasers'`). "
                "Combine with a Jenkins folder-scoped permission so only "
                "release engineers see the prompt."
            ),
            passed=passed,
        )

    # ─── JF-006 / JF-007 — signing + SBOM ─────────────────────────────

    @staticmethod
    def _jf006_signing(jf: Jenkinsfile) -> Finding:
        text = jf.text.lower()
        passed = any(tok in text for tok in SIGN_TOKENS)
        desc = (
            "Pipeline invokes a signing tool (cosign / sigstore / notation)."
            if passed else
            "Pipeline produces build artifacts but does not invoke any "
            "signing tool (cosign, sigstore, notation). Unsigned artifacts "
            "cannot be verified downstream, so a tampered build is "
            "indistinguishable from a legitimate one."
        )
        return Finding(
            check_id="JF-006",
            title="Artifacts not signed",
            severity=Severity.MEDIUM,
            resource=jf.path,
            description=desc,
            recommendation=(
                "Add a `sh 'cosign sign --yes …'` step (the cosign-installer "
                "Jenkins plugin handles binary install). Publish the "
                "signature next to the artifact and verify it at deploy."
            ),
            passed=passed,
        )

    @staticmethod
    def _jf007_sbom(jf: Jenkinsfile) -> Finding:
        text = jf.text.lower()
        direct = any(tok in text for tok in SBOM_DIRECT_TOKENS)
        trivy_sbom = "trivy" in text and ("sbom" in text or "cyclonedx" in text)
        passed = direct or trivy_sbom
        desc = (
            "Pipeline produces an SBOM (CycloneDX / syft / Trivy-SBOM)."
            if passed else
            "Pipeline does not produce a software bill of materials (SBOM). "
            "Without an SBOM, downstream consumers cannot audit the exact "
            "set of dependencies shipped in the artifact."
        )
        return Finding(
            check_id="JF-007",
            title="SBOM not produced",
            severity=Severity.MEDIUM,
            resource=jf.path,
            description=desc,
            recommendation=(
                "Add a `sh 'syft . -o cyclonedx-json > sbom.json'` step "
                "(or Trivy with `--format cyclonedx`) and archive the "
                "result with `archiveArtifacts`."
            ),
            passed=passed,
        )

    # ─── JF-008 — credential-shaped literal ───────────────────────────

    @staticmethod
    def _jf008_literal_secrets(jf: Jenkinsfile) -> Finding:
        # Reuse the cross-provider secret detector. ``find_secret_values``
        # walks dict/list/string trees; for Jenkinsfiles we wrap the
        # raw text as a single-element list so the same machinery
        # applies.
        hits = find_secret_values([jf.text])
        passed = not hits
        desc = (
            "No string in the Jenkinsfile matches a known credential pattern."
            if passed else
            f"Jenkinsfile contains {len(hits)} literal value(s) matching "
            f"known credential patterns (AWS keys, GitHub tokens, Slack "
            f"tokens, JWTs): "
            f"{', '.join(hits[:5])}{'…' if len(hits) > 5 else ''}. "
            f"Secrets committed to Groovy source are visible in every fork "
            f"and every build log."
        )
        return Finding(
            check_id="JF-008",
            title="Credential-shaped literal in pipeline body",
            severity=Severity.CRITICAL,
            resource=jf.path,
            description=desc,
            recommendation=(
                "Rotate the exposed credential. Move the value to a "
                "Jenkins credential and reference it via "
                "`withCredentials([string(credentialsId: '…', variable: '…')])`."
            ),
            passed=passed,
        )

    # ─── JF-009 — docker agent image pinning ──────────────────────────

    @staticmethod
    def _jf009_docker_image_pinning(jf: Jenkinsfile) -> Finding:
        unpinned: list[str] = []
        for ref in _DOCKER_IMAGE_RE.findall(jf.text):
            if _DIGEST_RE.search(ref):
                continue
            # No tag at all (e.g. ``image 'maven'``) is the worst case —
            # the registry's ``:latest`` follows.
            if ":" not in ref.rsplit("/", 1)[-1]:
                unpinned.append(f"{ref} (no tag)")
                continue
            tag = ref.rsplit(":", 1)[1]
            if tag == "latest" or not _VERSION_TAG_RE.search(ref):
                unpinned.append(f"{ref} (floating tag)")
                continue
            # Tag-pinned but not digest-pinned — registry operators or
            # compromised namespaces can repoint a tag, so flag at HIGH
            # alongside the floating cases.
            unpinned.append(f"{ref} (tag, not digest)")
        passed = not unpinned
        desc = (
            "Every docker agent image is pinned by sha256 digest."
            if passed else
            f"{len(unpinned)} docker agent image(s) are not digest-pinned: "
            f"{', '.join(unpinned[:5])}{'…' if len(unpinned) > 5 else ''}. "
            f"A repointed registry tag silently swaps the executor under "
            f"every subsequent build."
        )
        return Finding(
            check_id="JF-009",
            title="Agent docker image not pinned to sha256 digest",
            severity=Severity.HIGH,
            resource=jf.path,
            description=desc,
            recommendation=(
                "Resolve each image to its current digest "
                "(`docker buildx imagetools inspect <ref>` prints it) and "
                "reference it via `image '<repo>@sha256:<digest>'`. "
                "Automate refreshes with Renovate."
            ),
            passed=passed,
        )

    # ─── JF-010 — long-lived AWS keys via environment {} ──────────────

    @staticmethod
    def _jf010_env_aws_keys(jf: Jenkinsfile) -> Finding:
        offenders: list[str] = []
        for m in _ENV_AWS_KEY_RE.finditer(jf.text):
            name, value = m.group(1), m.group(2)
            # ``${env.SOMETHING}`` / Jenkins-credential references
            # like ``credentials('aws-prod')`` aren't long-lived in
            # the same way — they pull at runtime. Only flag literal
            # values or simple variable references that don't go
            # through the credentials store.
            if value.startswith("${") and "credentials" in value:
                continue
            if "credentials(" in value:
                continue
            offenders.append(name)
        passed = not offenders
        desc = (
            "No long-lived AWS credentials are bound in `environment { … }`."
            if passed else
            f"`environment {{ … }}` block declares AWS credential variable(s) "
            f"with literal or non-credentials-store values: "
            f"{', '.join(sorted(set(offenders)))}. These leak into every "
            f"`sh`/`bat` step in scope and are visible in build logs."
        )
        return Finding(
            check_id="JF-010",
            title="Long-lived AWS keys exposed via environment {} block",
            severity=Severity.HIGH,
            resource=jf.path,
            description=desc,
            recommendation=(
                "Replace the literal with a credentials-store reference: "
                "`AWS_ACCESS_KEY_ID = credentials('aws-prod-key')`. Better: "
                "switch to the AWS plugin's role binding "
                "(`withAWS(role: 'arn:…')`) so the build assumes a "
                "short-lived role per run."
            ),
            passed=passed,
        )

    # ─── JF-011 — buildDiscarder retention ────────────────────────────

    @staticmethod
    def _jf011_build_discarder(jf: Jenkinsfile) -> Finding:
        passed = bool(_BUILD_DISCARDER_RE.search(jf.text))
        desc = (
            "Pipeline declares a `buildDiscarder` / `logRotator` policy."
            if passed else
            "Pipeline has no `buildDiscarder` / `logRotator` policy. "
            "Build logs accumulate indefinitely; any secret that ever "
            "leaked into a log (an unmasked output, a stack trace, a "
            "debug print) stays available to anyone who can read jobs "
            "until the controller's disk fills up."
        )
        return Finding(
            check_id="JF-011",
            title="Pipeline has no `buildDiscarder` retention policy",
            severity=Severity.LOW,
            resource=jf.path,
            description=desc,
            recommendation=(
                "Add `options { buildDiscarder(logRotator(numToKeepStr: "
                "'30', daysToKeepStr: '90')) }` (declarative) or the "
                "`properties([buildDiscarder(...)])` equivalent in "
                "scripted pipelines. Tune the numbers to your retention "
                "policy."
            ),
            passed=passed,
        )

    # ─── JF-012 — dynamic load steps ──────────────────────────────────

    @staticmethod
    def _jf012_load_step(jf: Jenkinsfile) -> Finding:
        loaded = _LOAD_STEP_RE.findall(jf.text)
        passed = not loaded
        desc = (
            "Pipeline does not use the `load` step to pull Groovy from disk."
            if passed else
            f"Pipeline `load`s {len(loaded)} Groovy file(s) at runtime: "
            f"{', '.join(loaded[:5])}{'…' if len(loaded) > 5 else ''}. "
            f"`load` evaluates whatever exists at the path when the build "
            f"runs — there is no integrity check, so a workspace mutation "
            f"(stash, archived artifact, or a sibling step writing to "
            f"the path) can swap the loaded code."
        )
        return Finding(
            check_id="JF-012",
            title="`load` step pulls Groovy from disk without integrity pin",
            severity=Severity.MEDIUM,
            resource=jf.path,
            description=desc,
            recommendation=(
                "Move shared Groovy into a Jenkins shared library "
                "(`@Library('name@<sha>')`) — those are version-pinned "
                "and JF-001 audits them. Reserve `load` for one-off "
                "development experiments."
            ),
            passed=passed,
        )
