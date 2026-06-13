"""GL-050. Package-publish job relies on a long-lived registry token (no OIDC)."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, job_scripts

RULE = Rule(
    id="GL-050",
    title="Package-publish job relies on a long-lived registry token",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2", "CICD-SEC-6"),
    esf=("ESF-D-SECRETS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-798", "CWE-1357"),
    recommendation=(
        "Publish to public registries with GitLab OIDC trusted publishing "
        "instead of a long-lived registry token. Concretely:\n\n"
        "- **npm**: configure an `id_tokens:` block with "
        "`aud: https://registry.npmjs.org` on the publish job and run "
        "`npm publish` (npm CLI >= 11.5.1 exchanges the OIDC token for a "
        "short-lived upload token); drop the `${NPM_TOKEN}` / "
        "`${NODE_AUTH_TOKEN}` `.npmrc` line. npm's September 2025 plan "
        "disallows token-based publishing by default and lists GitLab as a "
        "supported OIDC provider.\n"
        "- **PyPI**: use PyPI trusted publishing (the GitLab OIDC provider) "
        "rather than a `${TWINE_PASSWORD}` / `${PYPI_TOKEN}`.\n"
        "- Publishing to the **GitLab Package Registry** of the same project "
        "already uses the built-in, per-job `${CI_JOB_TOKEN}` (which this "
        "rule does not flag); reserve long-lived tokens for registries that "
        "genuinely can't do OIDC, and protect those jobs with a protected "
        "environment / branch rule.\n\n"
        "A long-lived `NPM_TOKEN` in a publish job is the fuel a "
        "Shai-Hulud-shaped worm needs: once scraped from the job env or a "
        "`.npmrc` it can publish more compromised packages on the project's "
        "behalf. An OIDC token expires in minutes and is scoped to the job "
        "that requested it. The GitHub Actions analog is GHA-050."
    ),
    docs_note=(
        "Fires when a job's `script:` (or `before_script:` / "
        "`after_script:`) runs a package-publish verb AND the job, its "
        "`variables:`, or the pipeline's top-level `variables:` reference a "
        "long-lived external-registry token. Publish verbs covered: "
        "`npm` / `pnpm` / `yarn publish`, `twine upload`, `poetry publish`, "
        "`uv publish`, `gem push`, `cargo publish`. Long-lived secrets: "
        "`NPM_TOKEN`, `NODE_AUTH_TOKEN`, `NPM_AUTH_TOKEN`, `PYPI_TOKEN`, "
        "`TWINE_PASSWORD`, `POETRY_PYPI_TOKEN`, `RUBYGEMS_API_KEY`, "
        "`GEM_HOST_API_KEY`, `CARGO_REGISTRY_TOKEN`.\n\n"
        "GitLab's built-in `${CI_JOB_TOKEN}` is deliberately excluded: it is "
        "the per-job, automatically-expiring token used to publish to the "
        "project's own GitLab Package Registry (the native path), not a "
        "long-lived external credential. A publish job that uses OIDC "
        "(`id_tokens:`) and references no long-lived token does not match. "
        "The GitHub Actions analog is GHA-050; the cloud-credentials side is "
        "GL-013 (long-lived AWS keys) / GL-031 (OIDC trust)."
    ),
    known_fp=(
        "A private / internal registry that genuinely can't do OIDC "
        "(self-hosted Artifactory / Nexus without an OIDC broker) requires "
        "a static token. Gate that publish job behind a protected "
        "environment with required approvers and suppress this rule with a "
        "rationale naming the registry.",
        "First-publish bootstrap of a new package (npm and PyPI both require "
        "an initial manual publish before trusted publishing can be wired). "
        "The rule fires; suppress on the specific job until the "
        "trusted-publisher record is in place.",
    ),
    incident_refs=(
        "Shai-Hulud npm worm (2025-2026): the worm scraped `NPM_TOKEN` from "
        "the runner env / `~/.npmrc` and used it to `npm publish` patched "
        "versions of other packages the maintainer's account owned. OIDC "
        "trusted publishing turns that step into a no-op: the token doesn't "
        "survive the job.",
        "npm 'Our plan for a more secure npm supply chain' (2025-09-22): "
        "npm will disallow token-based publishing by default and expand OIDC "
        "trusted publishing, with GitLab named as a supported provider.",
    ),
    exploit_example=(
        "# Vulnerable: long-lived NPM_TOKEN, no OIDC trusted publishing.\n"
        "publish:\n"
        "  stage: deploy\n"
        "  script:\n"
        "    - echo \"//registry.npmjs.org/:_authToken=${NPM_TOKEN}\" > .npmrc\n"
        "    - npm publish\n"
        "  # NPM_TOKEN is a masked project CI/CD variable; any postinstall in\n"
        "  # a build dependency can read it from the job env and re-publish\n"
        "  # other packages the token can reach.\n"
        "\n"
        "# Safe: GitLab OIDC trusted publishing, no long-lived token.\n"
        "publish:\n"
        "  stage: deploy\n"
        "  id_tokens:\n"
        "    NPM_ID_TOKEN:\n"
        "      aud: https://registry.npmjs.org\n"
        "  script:\n"
        "    - npm publish        # npm CLI >= 11.5.1 exchanges the OIDC token"
    ),
)


# Publish verbs in script lines. Anchored on the verb so unrelated uses
# (``npm pack``, ``twine check``) don't fire.
_PUBLISH_RE = re.compile(
    r"\b(?:"
    r"(?:npm|pnpm|yarn)\s+publish"
    r"|twine\s+upload"
    r"|poetry\s+publish"
    r"|uv\s+publish"
    r"|gem\s+push"
    r"|cargo\s+publish"
    r")\b",
    re.IGNORECASE,
)

# Long-lived EXTERNAL-registry tokens. ``CI_JOB_TOKEN`` is deliberately
# excluded: it's GitLab's built-in, per-job token for the project's own
# GitLab Package Registry (the native, auto-expiring path), not a
# long-lived external credential.
_LONG_LIVED_SECRETS: tuple[str, ...] = (
    "NPM_TOKEN", "NODE_AUTH_TOKEN", "NPM_AUTH_TOKEN",
    "PYPI_TOKEN", "TWINE_PASSWORD", "POETRY_PYPI_TOKEN",
    "RUBYGEMS_API_KEY", "GEM_HOST_API_KEY", "CARGO_REGISTRY_TOKEN",
)
_LONG_LIVED_RE = re.compile(
    r"\b(?:" + "|".join(_LONG_LIVED_SECRETS) + r")\b",
    re.IGNORECASE,
)


def _variables_text(variables: Any) -> str:
    """Flatten a ``variables:`` mapping into searchable text (keys + values).

    Handles the scalar (``KEY: value``) and the typed (``KEY: {value: ...}``)
    forms GitLab accepts.
    """
    if not isinstance(variables, dict):
        return ""
    parts: list[str] = []
    for key, value in variables.items():
        if isinstance(key, str):
            parts.append(key)
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            inner = value.get("value")
            if isinstance(inner, str):
                parts.append(inner)
    return "\n".join(parts)


def check(path: str, doc: dict[str, Any]) -> Finding:
    global_vars_text = _variables_text(doc.get("variables"))
    offenders: list[str] = []
    for name, job in iter_jobs(doc):
        script_text = "\n".join(job_scripts(job))
        if not _PUBLISH_RE.search(script_text):
            continue
        haystack = "\n".join((
            script_text,
            _variables_text(job.get("variables")),
            global_vars_text,
        ))
        m = _LONG_LIVED_RE.search(haystack)
        if m is None:
            continue
        offenders.append(f"{name} ({m.group(0)})")
    passed = not offenders
    desc = (
        "No package-publish job relies on a long-lived registry token; "
        "publishing uses OIDC trusted publishing or the built-in "
        "CI_JOB_TOKEN."
        if passed else
        f"{len(offenders)} publish job(s) authenticate to a package "
        f"registry with a long-lived token: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A static publish token is the "
        f"worm-propagation fuel in the Shai-Hulud family of compromises; "
        f"migrate to GitLab OIDC trusted publishing (`id_tokens:`)."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
