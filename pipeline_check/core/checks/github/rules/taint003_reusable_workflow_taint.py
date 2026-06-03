"""TAINT-003. Untrusted input forwarded into reusable workflow inputs.

The third TAINT rule. Reusable workflows are GitHub Actions'
canonical "function call" mechanism: a caller workflow declares
``jobs.<id>.uses: ./path/to/callee.yml`` (or a remote ref) and
forward ``with:`` parameters into the callee. The callee
consumes them via ``${{ inputs.<name> }}`` references in its
own ``run:`` / ``with:`` bodies.

The injection shape:

  caller.yml
    jobs:
      call:
        uses: ./.github/workflows/callee.yml
        with:
          title: ${{ github.event.issue.title }}   <- taint enters

  callee.yml
    on:
      workflow_call:
        inputs:
          title:
            type: string
    jobs:
      build:
        steps:
          - run: echo "${{ inputs.title }}"        <- taint exits

GHA-003 doesn't catch the caller side because the tainted
expression is in a ``with:`` block, not a ``run:`` body. The
callee's ``run:`` interpolation is technically GHA-003's
territory, but only when the callee is in the same scan as the
caller — and even then the caller-side surface (the
*forwarding* itself) is the more actionable triage point
because the operator who controls the caller is usually not
the operator who controls the callee.

TAINT-003 fires caller-side. When the callee body is loaded
into the same scan (either on disk under ``--gha-path`` for
``./local-callee.yml`` references, or fetched by the
``--resolve-remote`` resolver for remote refs), the rule also
checks whether the callee actually consumes the forwarded
input in a sink and tags the finding accordingly:

  * **Confirmed** — the callee's ``run:`` / ``with:`` references
    ``${{ inputs.<name> }}`` unquoted, so the caller-side
    forward lands in an actual injection sink. Severity HIGH,
    confidence HIGH.
  * **Unconfirmed** — either the callee wasn't loaded, or the
    callee body doesn't reference the forwarded input in any
    sink the rule can see. The forward is still a risk surface
    (a future change to the callee could expose it), but the
    end-to-end chain isn't proven. Severity HIGH, confidence
    MEDIUM.

When ``--resolve-remote`` is off and the callee isn't on
disk, every forward is unconfirmed by definition. That's the
v1 behavior preserved.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Confidence, Finding, Severity, TaintFlow
from ...rule import Rule
from .._taint_graph import TaintPath, analyze_workflow
from ..base import GitHubContext, Workflow

RULE = Rule(
    id="TAINT-003",
    title="Untrusted input forwarded into reusable workflow ``with:``",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-1"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78", "CWE-829"),
    recommendation=(
        "Sanitize the value at the caller before forwarding it "
        "across the reusable-workflow boundary. The canonical "
        "safe pattern is to copy the untrusted source into a "
        "step's ``env:`` block, run a sanitizer (``tr -dc "
        "'a-zA-Z0-9 '`` is enough for a freeform title), surface "
        "the sanitized result via ``echo \"name=$VAR\" >> "
        "$GITHUB_OUTPUT``, then forward "
        "``${{ steps.<id>.outputs.<name> }}`` as the ``with:`` "
        "input. The callee then sees a string-typed value with "
        "no expression-evaluation pass left to exploit. If the "
        "callee is under your control, also handle the input "
        "via env in the callee's ``run:`` body (not direct "
        "``${{ inputs.<name> }}`` interpolation)."
    ),
    docs_note=(
        "Detection walks every ``jobs.<id>.uses: <callee>`` "
        "reference, finds every ``with:`` value that "
        "interpolates an attacker-controllable source (direct "
        "``${{ github.event.* }}``, a tainted step output via "
        "``${{ steps.<id>.outputs.<name> }}``, or a cross-job "
        "``${{ needs.<job>.outputs.<name> }}``), and flags the "
        "forward.\n\n"
        "When the callee body is loaded into the same scan "
        "(local ``./.github/workflows/<file>.yml`` references "
        "via ``--gha-path``, or remote refs fetched by "
        "``--resolve-remote``), the rule also checks whether "
        "the callee references ``${{ inputs.<name> }}`` "
        "unquoted in a sink. Confirmed end-to-end paths get "
        "HIGH confidence; caller-side-only forward stay at "
        "MEDIUM (still a risk surface, but a future change to "
        "the callee could expose it)."
    ),
    known_fp=(
        "Callees that wrap the input safely (immediately copy "
        "into env, sanitize before use) make the caller-side "
        "forward harmless. When the callee body is loaded into "
        "the scan, the rule downgrades to MEDIUM confidence on "
        "those paths; suppress via ignore-file when the "
        "callee's handling is audited and sound. Without "
        "``--resolve-remote`` the rule can't see remote callee "
        "bodies and every forward stays at MEDIUM, the right "
        "default for unverifiable cross-repo flow.",
    ),
    exploit_example=(
        "# Vulnerable: the caller workflow passes an untrusted\n"
        "# value into a reusable workflow's ``with:`` inputs. The\n"
        "# reusable workflow inlines the input into a shell\n"
        "# command without quoting; the injection lands in the\n"
        "# reusable workflow's runtime even though the caller\n"
        "# carries the dangerous source.\n"
        "# caller.yml\n"
        "on: [issues]\n"
        "jobs:\n"
        "  call:\n"
        "    uses: myorg/repo/.github/workflows/reusable.yml@<sha>\n"
        "    with:\n"
        "      title: ${{ github.event.issue.title }}\n"
        "# reusable.yml\n"
        "on:\n"
        "  workflow_call:\n"
        "    inputs:\n"
        "      title: { required: true, type: string }\n"
        "jobs:\n"
        "  use:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps: [{ run: \"./gen --title ${{ inputs.title }}\" }]\n"
        "\n"
        "# Safe: sanitize the untrusted value at the caller\n"
        "# BEFORE forwarding it into ``with:``. The reusable\n"
        "# workflow can also defensively re-quote inside its own\n"
        "# step body via env-var indirection.\n"
        "# caller.yml\n"
        "on: [issues]\n"
        "jobs:\n"
        "  clean:\n"
        "    runs-on: ubuntu-latest\n"
        "    outputs:\n"
        "      title: ${{ steps.s.outputs.title }}\n"
        "    steps:\n"
        "      - id: s\n"
        "        env:\n"
        "          RAW: ${{ github.event.issue.title }}\n"
        "        run: |\n"
        "          clean=$(echo \"$RAW\" | tr -dc 'a-zA-Z0-9 -')\n"
        "          echo \"title=$clean\" >> \"$GITHUB_OUTPUT\"\n"
        "  call:\n"
        "    needs: clean\n"
        "    uses: myorg/repo/.github/workflows/reusable.yml@<sha>\n"
        "    with:\n"
        "      title: ${{ needs.clean.outputs.title }}"
    ),
)


# Match the unquoted-reference shape inside a callee's ``run:``
# body. Uses the same quote-state walker idea as GHA-003: strip
# double-quoted segments and re-check, since ``"${{ inputs.X }}"``
# is the safe form (the value lands in a single shell token).
_INPUT_REF_BARE_RE = re.compile(
    r"\$\{\{\s*inputs\.(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s*\}\}"
)
_DQ_SEGMENT_RE = re.compile(r'"[^"]*"')


def _consumed_unquoted(text: str, input_name: str) -> bool:
    """True when *text* references ``${{ inputs.<input_name> }}``
    outside any double-quoted segment.

    Mirrors the GHA-003 quote-state logic: a reference inside a
    ``"..."`` segment is treated as safe (the shell tokenizer
    keeps the expanded value intact). Anything still matching
    after the strip is an unquoted reference and is unsafe.
    """
    stripped = _DQ_SEGMENT_RE.sub("", text)
    for m in _INPUT_REF_BARE_RE.finditer(stripped):
        if m.group("name") == input_name:
            return True
    return False


def _consumed_in_with(value: Any, input_name: str) -> bool:
    """True when a ``with:`` block value references the input.

    ``with:`` values are a sink for downstream actions whose own
    code reads the value (``actions/github-script@<ref>``'s
    ``script:`` parameter is the canonical example). The rule
    treats any ``${{ inputs.<name> }}`` interpolation in a
    ``with:`` value as a sink, with the same quote-state
    sensitivity as for ``run:`` bodies.
    """
    if not isinstance(value, str):
        return False
    return _consumed_unquoted(value, input_name)


def _callee_consumes_input(
    callee: Workflow, input_name: str,
) -> bool:
    """Walk the callee body for unquoted ``${{ inputs.<name> }}``.

    Returns True if any step's ``run:`` body or ``with:`` block
    interpolates the named input outside a quoted token. The
    callee's own ``inputs:`` declaration is informational; the
    real signal is whether downstream code actually reads the
    value in a way that re-evaluates it.
    """
    doc = callee.data
    if not isinstance(doc, dict):
        return False
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return False
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            run = step.get("run")
            if isinstance(run, str) and _consumed_unquoted(run, input_name):
                return True
            with_block = step.get("with")
            if isinstance(with_block, dict):
                for wval in with_block.values():
                    if _consumed_in_with(wval, input_name):
                        return True
    return False


def _resolve_callee(
    ctx: GitHubContext, callee_ref: str,
) -> Workflow | None:
    """Find the loaded callee Workflow that matches the caller's ref.

    Two match shapes:

      * Remote refs (``owner/repo/path.yml@sha``) — match against
        ``Workflow.source_ref`` exactly. Only set on workflows
        the resolver fetched.
      * Local refs (``./.github/workflows/x.yml``) — match by
        path-suffix. The caller's ref is repo-relative; the
        loaded workflow's path can be absolute, relative, or
        prefixed by the GHA-path root. Suffix-match against
        the basename + parent dir handles all three.
    """
    ref = callee_ref.strip()
    if not ref:
        return None
    # Remote workflow ref.
    if "@" in ref and not ref.startswith(("/", "./")):
        for wf in ctx.workflows:
            if wf.source_ref and wf.source_ref == ref:
                return wf
        return None
    # Local ref — strip leading ``./`` and match by suffix on the
    # loaded workflows' paths. Replace backslashes for Windows.
    needle = ref.lstrip("./").replace("\\", "/")
    for wf in ctx.workflows:
        wf_path = wf.path.replace("\\", "/")
        if wf_path.endswith(needle):
            return wf
        # Path basenames often differ (caller spells
        # ``.github/workflows/x.yml`` while the loaded path is
        # ``<root>/x.yml``). Fall back to basename match.
        if wf_path.rsplit("/", 1)[-1] == needle.rsplit("/", 1)[-1]:
            return wf
    return None


def _caller_job(path: TaintPath) -> str:
    """The caller job that passes a value into the callee (``uses:`` + ``with:``).

    Pass-4 paths carry a single hop of the shape
    ``jobs.<caller_job>.with.<input>``; the caller job is the segment
    between ``jobs.`` and ``.with.``. Returns "" if the hop is absent
    (defensive; the caller filters to ``.with.`` hops before this runs).
    """
    for h in path.hops:
        if h.startswith("jobs.") and ".with." in h:
            return h[len("jobs."):].split(".with.", 1)[0]
    return ""


def _callee_ref(path: TaintPath) -> str:
    """The raw callee ref from the ``inputs.<name>@<callee-ref>`` sink."""
    return path.sink_consumer.partition("@")[2]


def _classify_path(
    path: TaintPath, ctx: GitHubContext,
) -> tuple[bool, str | None]:
    """Return ``(confirmed, callee_path_or_none)`` for a TAINT-003 path.

    Parses the engine's ``sink_consumer`` field to extract the
    forwarded input name and the callee ref, then resolves the
    callee in the context. ``confirmed`` is True iff the callee
    body's run / with bodies actually reference the forwarded
    input unquoted. ``callee_path_or_none`` is the matched
    callee's ``Workflow.path`` (for description rendering) or
    ``None`` when the callee couldn't be resolved.
    """
    # ``sink_consumer`` shape: ``inputs.<name>@<callee-ref>``.
    consumer = path.sink_consumer
    if "@" not in consumer:
        return False, None
    head, _, callee_ref = consumer.partition("@")
    if not head.startswith("inputs."):
        return False, None
    input_name = head[len("inputs."):]
    callee = _resolve_callee(ctx, callee_ref)
    if callee is None:
        return False, None
    confirmed = _callee_consumes_input(callee, input_name)
    return confirmed, callee.path


def check(
    path: str,
    doc: dict[str, Any],
    wf: Workflow,
    ctx: GitHubContext,
) -> Finding:
    # TAINT-003 paths are emitted by pass-4 of the engine. The
    # discriminator is the hop format: ``jobs.<id>.with.<name>``
    # (with-prefix). Same-job step-output paths (TAINT-001) and
    # cross-job paths (TAINT-002) use different hop shapes.
    forward_paths = [
        p for p in analyze_workflow(doc)
        if any(h.startswith("jobs.") and ".with." in h for h in p.hops)
    ]
    if not forward_paths:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No tainted ``with:`` forward into a reusable "
                "workflow detected."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    confirmed_paths: list[tuple[TaintPath, str]] = []
    unconfirmed_paths: list[TaintPath] = []
    # Structured cross-document edges for the chain engine (AC-002's
    # cross-document tier). A confirmed forward into a loaded callee
    # keys its ``sink_job`` on the resolved callee ``Workflow.path`` so a
    # chain can join it against the callee's own findings (e.g. an
    # ungated deploy). A forward whose callee wasn't loaded, or was
    # loaded but doesn't consume the input in a sink, carries the raw
    # callee ref instead: it surfaces the edge for output parity but
    # proves no end-to-end reachability, so it never matches a callee
    # resource path.
    flows: list[TaintFlow] = []
    for p in forward_paths:
        ok, callee_path = _classify_path(p, ctx)
        sink = callee_path if (ok and callee_path) else _callee_ref(p)
        flows.append(TaintFlow(
            source_job=_caller_job(p),
            sink_job=sink,
            rendered=p.render(),
            cross_document=True,
        ))
        if ok and callee_path:
            confirmed_paths.append((p, callee_path))
        else:
            unconfirmed_paths.append(p)

    # Confidence: HIGH iff every forward is end-to-end confirmed,
    # MEDIUM otherwise (a single unconfirmed path leaves uncertainty
    # in the finding's overall trust level). Default-on confidence
    # demotion in core/checks/_confidence.py would normally apply
    # here; we lock the per-finding confidence so the demotion
    # doesn't override our deliberate choice.
    confirmed_count = len(confirmed_paths)
    unconfirmed_count = len(unconfirmed_paths)
    confidence = (
        Confidence.HIGH
        if confirmed_count and not unconfirmed_count
        else Confidence.MEDIUM
    )

    rendered: list[str] = []
    for p, cpath in confirmed_paths:
        rendered.append(f"[CONFIRMED in {cpath}] {p.render()}")
    for p in unconfirmed_paths:
        rendered.append(f"[UNCONFIRMED] {p.render()}")
    total = confirmed_count + unconfirmed_count
    desc = (
        f"{total} reusable-workflow forward(s) carry untrusted data "
        f"into a callee's ``inputs:`` "
        f"({confirmed_count} confirmed end-to-end, "
        f"{unconfirmed_count} unconfirmed): "
        f"{'; '.join(rendered[:3])}"
        f"{'...' if len(rendered) > 3 else ''}."
    )
    finding = Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
        confidence=confidence,
        taint_flows=tuple(flows),
    )
    finding.confidence_locked = True
    return finding
