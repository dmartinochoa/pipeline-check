"""GHA-113. OIDC trusted-publishing job without an environment gate.

The registry-publish twin of GHA-030. A job that grants
``id-token: write`` and runs a package-publish step is using (or can
use) the OIDC trusted-publishing path: the GHA OIDC token is exchanged
at the registry for a short-lived upload credential, no long-lived
``NPM_TOKEN`` / ``PYPI_TOKEN`` required. That's the recommended posture
GHA-050 points operators toward. But trusted publishing only closes
half the loop.

npm's trusted publishing (and PyPI's) validates the OIDC token against
the **organization, repository, and workflow filename** only. It does
not check the branch, the ref, or the workflow's content. So a publish
job that mints an OIDC token from *any* branch can publish, as long as
the workflow filename matches the registered publisher. The only
project-side control that pins *which ref* may publish is a GitHub
Environment with a deployment-branch rule (and, ideally, required
reviewers) bound to the publish job.

This is the gap the Red Hat npm compromise walked through (BoostSecurity,
"Trusted Publishing, Untrusted Branch", 2026): a stolen maintainer
credential pushed a counterfeit ``.github/workflows/ci.yml`` to a
throwaway ``oidc-*`` branch, a plain ``push`` trigger minted the OIDC
token, and npm accepted it because no environment was configured. The
malicious packages even carried valid SLSA provenance recording the
throwaway branch ref.

Pairs with:

* **GHA-030** (cloud OIDC without environment gate) covers the
  ``configure-aws-credentials`` / ``azure/login`` /
  ``google-github-actions/auth`` exchange. GHA-113 is the same topology
  on the package-registry side.
* **GHA-050** (publish with long-lived token) covers the *other*
  credential lane and deliberately *passes* the OIDC path, so a
  trusted-publishing job with no environment gate is invisible to it.
  GHA-113 closes that seam.
* **GHA-086** (wildcard branch trigger gates an environment deploy)
  fires when an environment *is* bound but the trigger is too broad;
  GHA-113 fires when no environment is bound at all.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-113",
    title="OIDC trusted-publishing job without an environment gate",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2", "CICD-SEC-1"),
    esf=("ESF-D-TOKEN-HYGIENE", "ESF-C-APPROVAL"),
    cwe=("CWE-284", "CWE-862"),
    recommendation=(
        "Bind every package-publish job that mints an OIDC token to a "
        "protected ``environment:`` (e.g. ``environment: "
        "npm-publish``), then configure that environment's "
        "``Deployment branches and tags`` rule to allow only the "
        "release ref (a protected branch or, better, a tag). "
        "Concretely:\n\n"
        "- Add ``environment: <name>`` to the publish job and set the "
        "environment's branch policy to ``Selected branches and "
        "tags`` -> the exact release ref. The OIDC token then mints "
        "only when the run targets that ref, so a counterfeit "
        "workflow on a throwaway branch can't publish.\n"
        "- Prefer a tag trigger (``on: push: tags:``) or "
        "``workflow_dispatch`` for the release workflow over a "
        "branch ``push`` (see GHA-114).\n"
        "- Keep ``id-token: write`` scoped to the publish job, not the "
        "whole workflow.\n"
        "- For high-blast-radius packages, enable the registry's "
        "staged-publishing-with-2FA flow so a human approves the "
        "release even after the token is minted.\n\n"
        "Trusted publishing alone validates only org + repo + workflow "
        "filename; the environment gate is what binds publication to a "
        "trusted ref."
    ),
    docs_note=(
        "Fires when a single job satisfies all three:\n\n"
        "1. It effectively has ``id-token: write`` (declared on the "
        "job's own ``permissions:`` block, inherited from a "
        "workflow-level block it didn't override, or via "
        "``permissions: write-all``).\n"
        "2. It runs a package-publish step. Run-based: ``npm`` / "
        "``pnpm`` / ``yarn publish``, ``twine upload``, ``poetry "
        "publish``, ``uv publish``, ``gem push``, ``cargo publish``. "
        "Action-based trusted publishers: ``pypa/gh-action-pypi-"
        "publish``, ``rubygems/release-gem``, ``crates-io/publish-"
        "action``.\n"
        "3. It binds no ``environment:`` (neither the short string "
        "form nor the long ``{name: ...}`` mapping).\n\n"
        "The conjunction is the trusted-publishing-without-a-trusted-"
        "ref shape: an OIDC token mintable from any branch that runs "
        "the workflow, gating publication on nothing the registry "
        "checks. A job that binds a protected ``environment:`` passes "
        "regardless, because the environment's deployment-branch rule "
        "and required reviewers constrain which ref can mint the "
        "token. A job with no ``id-token: write`` is the long-lived-"
        "token lane GHA-050 covers, not this one.\n\n"
        "Defaults to MEDIUM confidence: the rule infers the OIDC "
        "trusted-publishing path from the co-occurrence of "
        "``id-token: write`` and a publish step, not from a proven "
        "token exchange. A job that mints the OIDC token for signing "
        "or cloud credentials and publishes on a long-lived token, or "
        "a first-publish bootstrap before the trusted-publisher record "
        "exists, can over-flag."
    ),
    known_fp=(
        "First-publish bootstrap of a new package. npm and PyPI both "
        "require an initial manual publish before a trusted-publisher "
        "record exists; the workflow may carry ``id-token: write`` "
        "ahead of that. Suppress on the specific job until the "
        "trusted-publisher + environment are wired.",
        "A job that mints the OIDC token for signing / cloud "
        "credentials (cosign, configure-aws-credentials) and happens "
        "to also run a publish step on a long-lived token. GHA-050 is "
        "the more precise finding there, but the environment-gate "
        "recommendation still applies: an ungated publish job that "
        "can mint an OIDC token from any branch is the risk either "
        "way.",
    ),
    incident_refs=(
        "Red Hat npm compromise (BoostSecurity, 'Trusted Publishing, "
        "Untrusted Branch', 2026): a counterfeit ``ci.yml`` on a "
        "throwaway ``oidc-*`` branch minted an OIDC token that npm "
        "trusted publishing accepted, because it validates only "
        "org + repo + workflow filename and no GitHub Environment was "
        "configured. An environment with a deployment-branch rule "
        "would have refused to mint the token from the throwaway "
        "branch: https://labs.boostsecurity.io/articles/"
        "trusted-publishing-untrusted-branch-red-hat-npm/",
    ),
    exploit_example=(
        "# Vulnerable: the publish job mints an OIDC token for npm\n"
        "# trusted publishing but binds no environment. npm validates\n"
        "# only org + repo + workflow filename, so a counterfeit copy\n"
        "# of this workflow on a throwaway branch publishes just as\n"
        "# well as the real release run.\n"
        "on:\n"
        "  push:\n"
        "    branches: [main]\n"
        "jobs:\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "      id-token: write            # OIDC, but ungated\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - uses: actions/setup-node@<sha>\n"
        "        with: { registry-url: 'https://registry.npmjs.org' }\n"
        "      - run: npm ci --ignore-scripts\n"
        "      - run: npm publish --provenance --access public\n"
        "\n"
        "# Safe: the publish job binds a protected environment whose\n"
        "# deployment-branch rule pins the release ref. The OIDC token\n"
        "# only mints when the run targets that ref, so a throwaway\n"
        "# branch can't publish even with a matching workflow filename.\n"
        "on:\n"
        "  push:\n"
        "    tags: ['v*']\n"
        "jobs:\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    environment: npm-publish     # branch/tag rule + reviewers\n"
        "    permissions:\n"
        "      contents: read\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - uses: actions/setup-node@<sha>\n"
        "        with: { registry-url: 'https://registry.npmjs.org' }\n"
        "      - run: npm ci --ignore-scripts\n"
        "      - run: npm publish --provenance --access public"
    ),
)


# Run-based publish verbs. Anchored on the verb so unrelated uses
# (``npm pack``, ``twine check``) don't fire. Mirrors GHA-050's
# ``_PUBLISH_RE`` so the two rules recognize the same publish surface.
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

# ``uses:`` of OIDC trusted-publisher actions. These exchange the GHA
# OIDC token for a short-lived registry credential (PEP 740 for PyPI,
# the equivalents for RubyGems / crates.io). ``js-devtools/npm-publish``
# is intentionally absent: it is token-driven, the long-lived lane
# GHA-050 owns.
_PUBLISH_ACTIONS: tuple[str, ...] = (
    "pypa/gh-action-pypi-publish",
    "rubygems/release-gem",
    "crates-io/publish-action",
)


def _job_has_id_token(job: dict[str, Any], workflow: dict[str, Any]) -> bool:
    """Return True if *job* effectively has ``id-token: write``.

    A job-level ``permissions:`` block REPLACES the workflow-level
    block (GitHub's permission semantics, it does not merge). Without
    a job-level block, the job inherits the workflow's permissions.
    Both the explicit ``id-token: write`` shape and the
    ``permissions: write-all`` umbrella grant count.
    """
    job_perms = job.get("permissions")
    if isinstance(job_perms, dict):
        return job_perms.get("id-token") == "write"
    if isinstance(job_perms, str):
        return job_perms == "write-all"
    wf_perms = workflow.get("permissions")
    if isinstance(wf_perms, dict):
        return wf_perms.get("id-token") == "write"
    if isinstance(wf_perms, str):
        return wf_perms == "write-all"
    return False


def _action_matches(action_ref: str, prefix: str) -> bool:
    """``action_ref`` is *prefix* or a path under it.

    Bounded match (exact / trailing-slash) so a lookalike repo like
    ``pypa/gh-action-pypi-publish-malicious`` doesn't register as the
    real trusted publisher.
    """
    return action_ref == prefix or action_ref.startswith(prefix + "/")


def _step_publishes(step: dict[str, Any]) -> tuple[bool, str]:
    """Return ``(is_publish, label)`` for *step*.

    The label names the publisher primitive so the finding can pinpoint
    it (``npm publish``, ``pypa/gh-action-pypi-publish``).
    """
    run = step.get("run")
    if isinstance(run, str):
        # Scan per command chunk so a ``--dry-run`` packaging-validation
        # step (``npm publish --dry-run``) is not read as a real publish,
        # while a genuine publish elsewhere in the same block still is.
        for chunk in re.split(r"[\n;&|]+", run):
            m = _PUBLISH_RE.search(chunk)
            if m and "--dry-run" not in chunk:
                return True, m.group(0).strip()
    uses = step.get("uses")
    if isinstance(uses, str):
        action = uses.split("@", 1)[0].strip().lower()
        for prefix in _PUBLISH_ACTIONS:
            if _action_matches(action, prefix):
                return True, prefix
    return False, ""


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations = []
    # AC-038 intersects this with the unrestricted-trigger leg (GHA-114)
    # to confirm the OIDC publish is reachable from any branch. Order-
    # preserving dict de-dupes when a job has multiple publish steps.
    anchor_jobs: dict[str, None] = {}
    for job_id, job in iter_jobs(doc):
        if not _job_has_id_token(job, doc):
            continue
        # A bound environment (short string or the ``{name: ...}`` dict)
        # constrains which ref can mint the token, so the job passes.
        if job.get("environment"):
            continue
        for idx, step in enumerate(iter_steps(job)):
            is_pub, label = _step_publishes(step)
            if not is_pub:
                continue
            name = step.get("name") or step.get("id") or f"steps[{idx}]"
            offenders.append(f"{job_id}.{name} ({label})")
            locations.append(step_location(path, step))
            anchor_jobs[job_id] = None
    passed = not offenders
    desc = (
        "Every job that mints an OIDC token and publishes a package is "
        "bound to a protected environment."
        if passed else
        f"{len(offenders)} publish step(s) mint a workflow OIDC token "
        f"(``id-token: write``) and run with no ``environment:`` gate: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Trusted publishing "
        f"validates only org + repo + workflow filename, so without an "
        f"environment's deployment-branch rule the token mints from any "
        f"branch that runs the workflow (the Red Hat npm 'untrusted "
        f"branch' shape)."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        job_anchors=tuple(anchor_jobs),
    )
