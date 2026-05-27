"""GHA-073. Reusable workflow declares a secret it never uses.

zizmor proposal #1044 (``unused-secrets``). A reusable workflow
that declares ``on.workflow_call.secrets.<name>:`` is asking its
caller to forward a value. If the workflow body then never
references ``${{ secrets.<name> }}`` (or its env-bound forms), the
caller is being forced to expose a secret that nothing reads.

Two failure modes follow:

  * The caller, prompted by ``required: true``, exposes a real
    secret value, increasing the workflow's secret surface for
    zero benefit.
  * The declared secret name silently goes stale across refactors,
    and reviewers reading the caller can't tell whether the value
    is load-bearing or dead.

The fix is to delete the unused declaration. If the secret is
expected to land in the body later (a feature under development),
add a ``# TODO`` reminder and an empty consumer step so the
linkage is explicit.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GHA-073",
    title="Reusable workflow declares an unused ``workflow_call`` secret",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-1100",),  # Insufficient Isolation Between Components
    recommendation=(
        "Drop the unused ``on.workflow_call.secrets.<name>:`` "
        "declaration. If the caller's pipeline relies on the "
        "name being forced (a contract enforcement), document "
        "that intent in a workflow-level comment so the next "
        "refactor doesn't delete it silently. When the secret "
        "actually does get consumed later, add the "
        "``${{ secrets.<name> }}`` reference back."
    ),
    docs_note=(
        "Fires on a workflow whose ``on.workflow_call.secrets`` "
        "block declares a name (``token`` / ``required: true`` / "
        "``required: false`` / inline shorthand) that the body "
        "never references via ``${{ secrets.<name> }}`` "
        "interpolation. The body scan covers every string value "
        "in the parsed document (``run:`` bodies, ``env:`` "
        "entries, ``with:`` values, ``if:`` expressions, and the "
        "workflow's top-level ``env``).\n\n"
        "Out of scope (deliberate carve-out): secret names that "
        "appear only inside ``secrets:`` blocks on a nested "
        "``jobs.<id>.uses:`` reusable-workflow call. Those are "
        "forward (the secret flows to a downstream callee that "
        "consumes it). Such forward references count as consumers "
        "for this rule, the leak surface is bounded by the "
        "downstream's declaration."
    ),
    known_fp=(
        "Workflows that declare a secret to enforce a contract "
        "across an organization's reusable-workflow library, "
        "even when the current body doesn't read the value. "
        "Suppress per-secret-name via ignore-file when the "
        "operator has documented the contract reason in a "
        "workflow-level comment.",
    ),
    incident_refs=(
        "zizmor proposal #1044 (unused-secrets audit): "
        "https://github.com/zizmorcore/zizmor/issues/1044",
    ),
    exploit_example=(
        "# Vulnerable: the reusable declares ``DEPLOY_TOKEN`` as\n"
        "# required, but the body never references it. Every\n"
        "# caller forward a real secret value for no reason.\n"
        "on:\n"
        "  workflow_call:\n"
        "    secrets:\n"
        "      DEPLOY_TOKEN:\n"
        "        required: true\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: ./build.sh\n"
        "\n"
        "# Safe: the declared secret is referenced in the\n"
        "# consuming step's ``env:``.\n"
        "on:\n"
        "  workflow_call:\n"
        "    secrets:\n"
        "      DEPLOY_TOKEN:\n"
        "        required: true\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - env:\n"
        "          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n"
        "        run: ./deploy.sh"
    ),
)


def _workflow_call_secret_names(doc: dict[str, Any]) -> list[str]:
    """Return declared secret names under ``on.workflow_call.secrets``."""
    on = doc.get("on")
    if on is None:
        # YAML 1.1 boolean ``on:`` shorthand.
        from typing import cast
        any_doc: dict[Any, Any] = cast("dict[Any, Any]", doc)
        on = any_doc.get(True)
    if not isinstance(on, dict):
        return []
    wf_call = on.get("workflow_call")
    if not isinstance(wf_call, dict):
        return []
    secrets = wf_call.get("secrets")
    if not isinstance(secrets, dict):
        return []
    return [str(name) for name in secrets]


def _flatten_string_values(value: Any, out: list[str]) -> None:
    """Recursively collect every string scalar reachable from *value*."""
    if isinstance(value, str):
        out.append(value)
        return
    if isinstance(value, dict):
        for v in value.values():
            _flatten_string_values(v, out)
        return
    if isinstance(value, list):
        for v in value:
            _flatten_string_values(v, out)


def _body_references_secret(doc: dict[str, Any], name: str) -> bool:
    """True when any string value in *doc* references ``secrets.<name>``."""
    # Pre-compile the exact-name pattern with word boundaries.
    # ``secrets.NAME`` followed by a non-identifier char (``}`` /
    # whitespace) so ``secrets.MY_TOKEN`` doesn't match ``MY``.
    pattern = re.compile(
        rf"secrets\.{re.escape(name)}\b"
    )
    strings: list[str] = []
    _flatten_string_values(doc, strings)
    for s in strings:
        if pattern.search(s):
            return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    declared = _workflow_call_secret_names(doc)
    if not declared:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No ``on.workflow_call.secrets`` declarations.",
            recommendation=RULE.recommendation, passed=True,
        )
    unused = [name for name in declared if not _body_references_secret(doc, name)]
    passed = not unused
    desc = (
        f"All {len(declared)} ``workflow_call.secrets`` declaration(s) are referenced in the body."
        if passed else
        f"{len(unused)} ``workflow_call.secrets`` declaration(s) "
        f"are unused: {', '.join(unused[:5])}"
        f"{'...' if len(unused) > 5 else ''}. Every caller is "
        f"forced to forward a value that nothing reads."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
