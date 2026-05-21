"""GHA-054. ``actions/checkout`` with ``ssh-key`` AND ``persist-credentials``."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-054",
    title="actions/checkout with ssh-key persists SSH credential in repo",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-522", "CWE-538"),
    recommendation=(
        "Set ``with: persist-credentials: false`` on every "
        "``actions/checkout`` step that also passes ``ssh-key:`` "
        "from a secret. With ``persist-credentials: true`` "
        "(the default), the checkout action writes the SSH key "
        "into ``.git/config`` of the checked-out repo and "
        "configures the local repo to use that key for "
        "subsequent ``git`` invocations. Any later step in the "
        "same job that runs untrusted code (a build script, a "
        "test fixture, a postinstall) inherits the credential "
        "via the repo's git config — same shape as the "
        "``ArtiPacked`` family GHA-037 catches for "
        "``GITHUB_TOKEN``.\n\n"
        "The safe pattern: ``actions/checkout@<sha>`` with "
        "``ssh-key: ${{ secrets.DEPLOY_KEY }}`` AND "
        "``persist-credentials: false``. The action uses the "
        "key for the initial clone, then unsets it; subsequent "
        "steps don't have access. If you actually need to "
        "``git push`` later in the job using the same key, "
        "re-configure with ``GIT_SSH_COMMAND`` in just that "
        "step rather than globally."
    ),
    docs_note=(
        "Walks every step with ``uses: actions/checkout@*`` "
        "and checks the ``with:`` block. Fires when both:\n\n"
        "* ``with.ssh-key`` is set (any value — ``${{ secrets."
        "  X }}`` is the typical shape), AND\n"
        "* ``with.persist-credentials`` is not explicitly set "
        "  to ``false`` (the default behavior is ``true``).\n\n"
        "Complements GHA-037 (ArtiPacked / persist-credentials "
        "on token-based checkouts). Where GHA-037 catches the "
        "``GITHUB_TOKEN`` persistence shape, GHA-054 catches "
        "the SSH-deploy-key persistence shape — same risk, "
        "different credential type."
    ),
    known_fp=(
        "Workflows that genuinely need the SSH key to remain "
        "available in the repo (a single-job pipeline that "
        "clones, builds, and pushes back to the same repo "
        "using the same key) sometimes set ``persist-"
        "credentials: true`` deliberately. The safer pattern "
        "is to split the push into a separate job whose "
        "``actions/checkout`` re-clones with the same key but "
        "without persist; or use a fine-grained PAT for the "
        "push step. Suppress with a rationale that names the "
        "single-job constraint.",
    ),
    exploit_example=(
        "# Vulnerable: ``actions/checkout`` with ``ssh-key:`` and\n"
        "# ``persist-credentials: true`` writes the deploy SSH\n"
        "# private key into ``.git/config`` (or the ssh-agent\n"
        "# session) for the workflow's duration. A later step that\n"
        "# uploads the workspace as an artifact leaks the key the\n"
        "# same way ArtiPACKED leaks the GITHUB_TOKEN.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "        with:\n"
        "          ssh-key: ${{ secrets.DEPLOY_KEY }}\n"
        "          # default persist-credentials: true\n"
        "      - run: ./build.sh\n"
        "      - uses: actions/upload-artifact@<sha>\n"
        "        with:\n"
        "          name: build\n"
        "          path: .   # uploads .git/config + ssh setup\n"
        "\n"
        "# Safe: set ``persist-credentials: false`` and scope the\n"
        "# artifact upload to ``dist/`` (not the repo root).\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "        with:\n"
        "          ssh-key: ${{ secrets.DEPLOY_KEY }}\n"
        "          persist-credentials: false\n"
        "      - run: ./build.sh\n"
        "      - uses: actions/upload-artifact@<sha>\n"
        "        with:\n"
        "          name: build\n"
        "          path: dist/"
    ),
)


_CHECKOUT_USES_RE = re.compile(
    r"^actions/checkout(?:@|/|$)", re.IGNORECASE
)


def _is_checkout(uses: Any) -> bool:
    if not isinstance(uses, str):
        return False
    return bool(_CHECKOUT_USES_RE.match(uses.strip()))


def _ssh_key_set(with_block: dict[str, Any]) -> bool:
    """True when ``with.ssh-key`` is set to anything non-empty."""
    value = with_block.get("ssh-key")
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    # Lists / dicts are unlikely but treat as set.
    return True


def _persist_credentials_left_on(with_block: dict[str, Any]) -> bool:
    """True when ``persist-credentials`` is absent or truthy.

    The default is ``true``; only an explicit ``false`` (bool) or
    string ``'false'`` disables persistence.
    """
    raw = with_block.get("persist-credentials")
    if raw is None:
        return True
    if raw is False:
        return False
    if isinstance(raw, str) and raw.strip().lower() == "false":
        return False
    return True


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            if not _is_checkout(step.get("uses")):
                continue
            with_block = step.get("with")
            if not isinstance(with_block, dict):
                continue
            if not _ssh_key_set(with_block):
                continue
            if not _persist_credentials_left_on(with_block):
                continue
            step_label = step.get("name") or step.get("id") or f"steps[{idx}]"
            offenders.append(f"jobs.{job_id}.{step_label}")
    passed = not offenders
    desc = (
        "No ``actions/checkout`` step persists an SSH key in "
        "the working tree."
        if passed else
        f"{len(offenders)} checkout step(s) persist an SSH key "
        f"in the working tree: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Subsequent "
        f"untrusted code in the same job can use the key for "
        f"arbitrary git operations. Add ``persist-credentials: "
        f"false`` to each."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
