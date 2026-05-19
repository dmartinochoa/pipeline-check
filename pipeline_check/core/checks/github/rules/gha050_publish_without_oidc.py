"""GHA-050. Package publish step relies on a long-lived token (no OIDC, no env gate)."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-050",
    title="Publish step relies on long-lived registry token",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2", "CICD-SEC-6"),
    esf=("ESF-D-SECRETS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-798", "CWE-1357"),
    recommendation=(
        "Replace long-lived publish tokens with OIDC trusted-publisher "
        "flows and bind the publish job to a protected ``environment:``. "
        "Concretely:\n\n"
        "- **PyPI**: use ``pypa/gh-action-pypi-publish`` with PEP 740 "
        "trusted publishing (no ``password`` input); the GHA OIDC "
        "token is exchanged at PyPI for a short-lived upload token.\n"
        "- **npm**: use ``--provenance`` on ``npm publish`` from a job "
        "that requests ``id-token: write`` (npm provenance, GA 2024); "
        "drop ``NODE_AUTH_TOKEN`` / ``NPM_TOKEN`` from the env block "
        "where possible.\n"
        "- **GHCR / ECR / GAR**: prefer ``configure-aws-credentials`` "
        "with ``role-to-assume`` (or the Azure / GCP equivalent), not "
        "static registry passwords.\n"
        "- Add ``environment: <protected-name>`` to the publish job so "
        "branch restrictions and required reviewers apply.\n\n"
        "A long-lived ``NPM_TOKEN`` is the fuel a Shai-Hulud-shaped "
        "worm needs: once stolen from any runner it can publish more "
        "compromised packages on the org's behalf. OIDC tokens expire "
        "in minutes and are scoped to the run that requested them."
    ),
    docs_note=(
        "Fires when a step matches a known package-publish primitive "
        "AND the job has no protected ``environment:`` AND the step "
        "references a long-lived registry secret. Publish primitives "
        "covered:\n\n"
        "- ``run: npm publish`` / ``pnpm publish`` / ``yarn publish``\n"
        "- ``run: twine upload`` / ``run: poetry publish`` / "
        "``run: uv publish``\n"
        "- ``run: gem push`` / ``run: cargo publish``\n"
        "- ``uses: pypa/gh-action-pypi-publish`` with a ``password`` "
        "input (the trusted-publisher path leaves ``password`` "
        "unset);\n"
        "- ``uses: JS-DevTools/npm-publish`` with a ``token`` input.\n\n"
        "Long-lived secret heuristic: the step's ``env:`` or "
        "``with:`` block references ``NPM_TOKEN``, ``NODE_AUTH_"
        "TOKEN``, ``PYPI_TOKEN``, ``TWINE_PASSWORD``, ``POETRY_"
        "PYPI_TOKEN``, ``RUBYGEMS_API_KEY``, or ``CARGO_REGISTRY_"
        "TOKEN`` from ``secrets.*``. A job that already binds to a "
        "protected ``environment:`` passes regardless, because the "
        "environment's required-reviewers / branch-rule controls "
        "compensate for the static credential.\n\n"
        "Pairs with GHA-030 (cloud OIDC trust). GHA-030 covers the "
        "cloud-credentials exchange; GHA-050 covers the package "
        "registry side."
    ),
    known_fp=(
        "Private / internal registries that don't support OIDC "
        "(legacy Artifactory, self-hosted Nexus without OIDC "
        "broker) require a static token. The right response is "
        "``environment:`` gating with required reviewers on the "
        "publish job; suppress this rule with a rationale that names "
        "the protected environment.",
        "First-publish bootstrap of a new package (npm and PyPI both "
        "require an initial manual publish before trusted-publisher "
        "can be wired). The rule fires; suppress on the specific "
        "step until the trusted-publisher record is in place.",
    ),
    incident_refs=(
        "Shai-Hulud npm worm (2026): the worm's self-propagation step "
        "scraped ``NPM_TOKEN`` from runner env / ``~/.npmrc`` and "
        "used it to ``npm publish`` patch versions of other packages "
        "the maintainer's account owned. Provenance + OIDC + "
        "environment gating turn that step into a no-op: the OIDC "
        "token doesn't survive the run, and an environment-gated "
        "publish requires a human reviewer.",
        "TanStack / Mistral compromises (May 2026): same shape, mass "
        "publish of poisoned versions using maintainer credentials. "
        "An environment gate on the publish job would have stopped "
        "the unattended release.",
    ),
    exploit_example=(
        "# Vulnerable: long-lived NPM_TOKEN, no environment gate. Any\n"
        "# postinstall in a transitive dep reaches the token via the\n"
        "# step env and can re-publish other packages the token can\n"
        "# reach.\n"
        "jobs:\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - uses: actions/setup-node@<sha>\n"
        "        with: { registry-url: 'https://registry.npmjs.org' }\n"
        "      - run: npm ci && npm publish\n"
        "        env:\n"
        "          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n"
        "\n"
        "# Safe: OIDC trusted-publisher + provenance + environment\n"
        "# gate. The publish job requires a deployment approval; the\n"
        "# upload uses a short-lived OIDC token; the tarball is\n"
        "# signed with provenance metadata npm verifies on install.\n"
        "jobs:\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    environment: npm-publish        # required reviewers\n"
        "    permissions:\n"
        "      contents: read\n"
        "      id-token: write               # OIDC\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - uses: actions/setup-node@<sha>\n"
        "        with: { registry-url: 'https://registry.npmjs.org' }\n"
        "      - run: npm ci --ignore-scripts\n"
        "      - run: npm publish --provenance --access public"
    ),
)


# Publish verbs in ``run:`` bodies. Anchored on the verb so unrelated
# uses (``npm pack``, ``twine check``) don't fire.
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

# ``uses:`` of action-based publishers. Match the action prefix; any
# version pin is allowed.
_PUBLISH_ACTIONS: tuple[str, ...] = (
    "pypa/gh-action-pypi-publish",
    "js-devtools/npm-publish",
)

# Long-lived registry secrets the heuristic looks for. Match is case-
# insensitive; the ``${{ secrets.* }}`` form is the canonical shape
# but a bare env reference is enough since the env block is where the
# secret name surfaces.
_LONG_LIVED_SECRETS: tuple[str, ...] = (
    "NPM_TOKEN", "NODE_AUTH_TOKEN", "PYPI_TOKEN",
    "TWINE_PASSWORD", "POETRY_PYPI_TOKEN",
    "RUBYGEMS_API_KEY", "CARGO_REGISTRY_TOKEN",
)
_LONG_LIVED_RE = re.compile(
    r"\b(?:" + "|".join(_LONG_LIVED_SECRETS) + r")\b",
    re.IGNORECASE,
)


def _step_publishes(step: dict[str, Any]) -> tuple[bool, str]:
    """Return ``(is_publish, label)`` for *step*.

    The label names the publisher primitive so the finding description
    can pinpoint it (``npm publish``, ``pypa/gh-action-pypi-publish``).
    """
    run = step.get("run")
    if isinstance(run, str):
        m = _PUBLISH_RE.search(run)
        if m:
            return True, m.group(0).strip()
    uses = step.get("uses")
    if isinstance(uses, str):
        action = uses.split("@", 1)[0].lower()
        for prefix in _PUBLISH_ACTIONS:
            if action.startswith(prefix):
                return True, prefix
    return False, ""


def _step_uses_long_lived_secret(step: dict[str, Any]) -> bool:
    """True when the step references a long-lived registry secret."""
    env = step.get("env")
    if isinstance(env, dict):
        for value in env.values():
            if isinstance(value, str) and _LONG_LIVED_RE.search(value):
                return True
            # Also match the bare key form (``NPM_TOKEN: ${{ secrets.X }}``)
        for key in env.keys():
            if isinstance(key, str) and _LONG_LIVED_RE.search(key):
                return True
    with_block = step.get("with")
    if isinstance(with_block, dict):
        # ``pypa/gh-action-pypi-publish`` accepts a ``password`` input;
        # any value reference there is the long-lived path (trusted
        # publishing leaves the input unset).
        if "password" in with_block:
            val = with_block["password"]
            if isinstance(val, str) and val.strip():
                return True
        # ``js-devtools/npm-publish`` accepts ``token``.
        if "token" in with_block:
            val = with_block["token"]
            if isinstance(val, str) and val.strip():
                return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations = []
    # AC-029 intersects this with the trigger / integrity legs to
    # confirm the publish-with-long-lived-token job is also the one
    # an attacker can land code in. Order-preserving dict for
    # reproducibility.
    anchor_jobs: dict[str, None] = {}
    for job_id, job in iter_jobs(doc):
        # A protected environment compensates for a static token; a
        # raw string (``environment: production``) and the dict form
        # (``environment: { name: production, url: ... }``) both count.
        env_field = job.get("environment")
        if env_field:
            continue
        for idx, step in enumerate(iter_steps(job)):
            is_pub, label = _step_publishes(step)
            if not is_pub:
                continue
            if not _step_uses_long_lived_secret(step):
                continue
            name = step.get("name") or step.get("id") or f"steps[{idx}]"
            offenders.append(f"{job_id}.{name} ({label})")
            locations.append(step_location(path, step))
            anchor_jobs[job_id] = None
    passed = not offenders
    desc = (
        "Every package-publish step either runs from an environment-"
        "gated job or uses an OIDC trusted-publisher flow."
        if passed else
        f"{len(offenders)} publish step(s) rely on a long-lived "
        f"registry token without environment gating: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Static publish tokens "
        f"are the worm-propagation fuel in the Shai-Hulud / TanStack "
        f"family of compromises."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        job_anchors=tuple(anchor_jobs),
    )
