"""Top-level auxiliary subcommands dispatched by ``cli.main``.

Extracted from ``cli.py`` to keep that module focused on the ``scan``
command and its plumbing. These four verbs (``explain``, ``fp-stats``,
``history``, ``verify-artifact``) are self-contained: each pulls its
implementation from ``core`` via a function-local import and shares no
state with the scan path, so moving them out introduces no import cycle.
``cli`` re-imports the command objects so ``main``'s argv dispatch and the
``pipeline_check.cli.<cmd>`` references in the test suite keep working.
"""
from __future__ import annotations

import click

# ────────────────────────────────────────────────────────────────────────────
# `explain` subcommand, render a per-check reference. Mirrors the
# behavior of ``pipeline_check --explain CHECK-ID`` but is a top-level
# verb, which is what new users reach for first ("explain X") and what
# the smart-init / gate-failure trailer point them at.
# ────────────────────────────────────────────────────────────────────────────


@click.command(name="explain")
@click.argument("check_id", required=False, metavar="CHECK_ID")
def explain_cmd(check_id: str | None) -> None:
    """Print the full reference for one check (severity, fix, controls).

    Equivalent to ``pipeline_check --explain CHECK_ID`` but more
    discoverable. Same exit-code contract: 0 when the ID is known, 3
    when it's not (with a "did you mean" list).
    """
    if not check_id:
        raise click.UsageError(
            "missing CHECK_ID. Example: pipeline_check explain GHA-001"
        )
    from .core.explain import print_explain
    raise click.exceptions.Exit(print_explain(check_id))


# ────────────────────────────────────────────────────────────────────────────
# `fp-stats` subcommand, print false-positive annotation totals.
# ────────────────────────────────────────────────────────────────────────────


@click.command(name="fp-stats")
@click.option(
    "--fp-file",
    "fp_path",
    default=None,
    metavar="PATH",
    help=(
        "Path to the false-positive annotation file. Defaults to "
        "``.pipeline-check-fp.json`` at cwd."
    ),
)
def fp_stats_cmd(fp_path: str | None) -> None:
    """Print rule -> FP-vote totals from the local annotation file.

    Surfaces which rules accumulate the most ``--annotate-fp``
    annotations across the repo so rule authors can prioritize
    triage. Rules with the highest counts are likely candidates for
    re-tuning, narrower heuristics, or a default-confidence
    demotion.
    """
    from .core.fp_annotations import (
        DEFAULT_FP_PATH,
        fp_stats,
        load_annotations,
    )

    path = fp_path or DEFAULT_FP_PATH
    annotations = load_annotations(path)
    if not annotations:
        click.echo(
            f"[fp-stats] no annotations found in {path} "
            f"(file missing or empty)",
            err=True,
        )
        return

    stats = fp_stats(annotations)
    width = max((len(cid) for cid, _ in stats), default=0)
    click.echo(f"[fp-stats] {len(annotations)} annotation(s) in {path}")
    for cid, count in stats:
        suffix = "vote" if count == 1 else "votes"
        click.echo(f"  {cid:<{width}}  {count} {suffix}")


# ────────────────────────────────────────────────────────────────────────────
# `history` subcommand, render a static-HTML findings-history dashboard.
# ────────────────────────────────────────────────────────────────────────────


@click.command(name="history")
@click.option(
    "--dir",
    "history_dir",
    default=".pipeline-check-history",
    metavar="PATH",
    show_default=True,
    help=(
        "Directory of timestamped scan-output JSON files (each "
        "produced by ``pipeline_check ... --output json "
        "--output-file scan-YYYYMMDD-HHMMSS.json``)."
    ),
)
@click.option(
    "--output",
    "output_path",
    default="pipeline-check-history.html",
    metavar="PATH",
    show_default=True,
    help="Destination for the rendered HTML dashboard.",
)
@click.option(
    "--top-rules",
    "top_n",
    default=15,
    show_default=True,
    type=click.IntRange(1, 100),
    help=(
        "Number of rules to show in the burn-down table (ranked by "
        "total failed findings across the history window)."
    ),
)
def history_cmd(history_dir: str, output_path: str, top_n: int) -> None:
    """Render a self-contained HTML dashboard from past scan outputs.

    Reads every ``*.json`` under ``--dir`` (default
    ``.pipeline-check-history/``), extracts a timestamp from each
    filename (``YYYYMMDD-HHMMSS`` or ``YYYY-MM-DD``; falls back to
    mtime), and writes one static HTML page with trend graphs and a
    top-N firing-rules burn-down. No JavaScript, no CDN, no web
    server — just a file the user can open locally, email, or commit.
    """
    from pathlib import Path

    from .core.history import load_history, render_html

    try:
        report = load_history(history_dir)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    html = render_html(report, top_n=top_n)
    out = Path(output_path)
    try:
        out.write_text(html, encoding="utf-8")
    except OSError as exc:
        raise click.UsageError(
            f"[history] could not write {out}: {exc}"
        ) from exc
    click.echo(
        f"[history] {len(report.snapshots)} snapshot(s) -> {out} "
        f"({len(report.warnings)} warning(s))"
    )
    for w in report.warnings:
        click.echo(f"  warn: {w}", err=True)


# ────────────────────────────────────────────────────────────────────────────
# `verify-artifact` subcommand, run cosign / slsa-verifier / gh attestation
# against an artifact and report whether its provenance validates. Turns the
# static "you should sign" findings into a runtime pass/fail gate.
# ────────────────────────────────────────────────────────────────────────────


@click.command(name="verify-artifact")
@click.argument("ref", required=False, metavar="REF")
@click.option(
    "--source-uri",
    "source_uri",
    default=None,
    metavar="URI",
    help=(
        "Expected source repository the artifact was built from, e.g. "
        "``github.com/acme/api``. Required by slsa-verifier."
    ),
)
@click.option(
    "--builder-id",
    "builder_id",
    default=None,
    metavar="ID",
    help="Expected SLSA builder id (slsa-verifier ``--builder-id``).",
)
@click.option(
    "--certificate-identity",
    "cert_identity",
    default=None,
    metavar="IDENTITY",
    help=(
        "Exact cosign keyless signer identity (the signing workflow ref). "
        "Pair with --certificate-oidc-issuer."
    ),
)
@click.option(
    "--certificate-identity-regexp",
    "cert_identity_re",
    default=None,
    metavar="REGEXP",
    help="cosign keyless signer identity as a regexp (alternative to exact).",
)
@click.option(
    "--certificate-oidc-issuer",
    "cert_oidc_issuer",
    default=None,
    metavar="ISSUER",
    help=(
        "Expected cosign keyless OIDC issuer, e.g. "
        "``https://token.actions.githubusercontent.com``."
    ),
)
@click.option(
    "--key",
    "key",
    default=None,
    metavar="PATH|URL",
    help="cosign public key for keyed verification (alternative to keyless).",
)
@click.option(
    "--owner",
    "owner",
    default=None,
    metavar="OWNER",
    help="GitHub owner / org for ``gh attestation verify``.",
)
@click.option(
    "--provenance",
    "provenance_path",
    default=None,
    metavar="PATH",
    help="Provenance file for verifying a local file artifact with slsa-verifier.",
)
@click.option(
    "--tool",
    "tool",
    type=click.Choice(["auto", "cosign", "slsa-verifier", "gh"]),
    default="auto",
    show_default=True,
    help="Which verifier(s) to run. ``auto`` runs every applicable, installed tool.",
)
@click.option(
    "--type",
    "artifact_type",
    type=click.Choice(["auto", "oci", "file"]),
    default="auto",
    show_default=True,
    help="Treat REF as an OCI image or a local file. ``auto`` infers from REF.",
)
@click.option(
    "--timeout",
    "timeout",
    type=click.IntRange(1, 3600),
    default=120,
    show_default=True,
    metavar="SECONDS",
    help="Per-verifier subprocess timeout.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    default=False,
    help="Emit the result as JSON instead of the text summary.",
)
def verify_artifact_cmd(
    ref: str | None,
    source_uri: str | None,
    builder_id: str | None,
    cert_identity: str | None,
    cert_identity_re: str | None,
    cert_oidc_issuer: str | None,
    key: str | None,
    owner: str | None,
    provenance_path: str | None,
    tool: str,
    artifact_type: str,
    timeout: int,
    as_json: bool,
) -> None:
    """Verify an artifact's signature / SLSA provenance against a policy.

    Shells out to the supply-chain verifiers on PATH (``cosign``,
    ``slsa-verifier``, ``gh attestation``) and reports whether REF is
    verifiably built by who it claims. REF is an OCI image reference
    (``ghcr.io/acme/api:1.2.3``, optionally ``@sha256:...``) or a local
    file path.

    Exit codes follow the canonical contract: ``0`` verified, ``1``
    verification failed (gateable in CI), ``2`` bad invocation, ``3``
    could not verify (no installed tool matched the policy).
    """
    import json as _json
    from pathlib import Path

    from .core.provenance import (
        KNOWN_TOOLS,
        ProvenanceError,
        Verdict,
        VerifyPolicy,
        verify_artifact,
    )

    if not ref:
        raise click.UsageError(
            "missing REF. Example: pipeline_check verify-artifact "
            "ghcr.io/acme/api:1.2.3 --source-uri github.com/acme/api"
        )

    # Normalize the reference and decide OCI vs. file. An explicit
    # ``oci://`` prefix or --type wins; otherwise an existing path is a
    # file and anything else is an OCI ref.
    canonical = ref
    if canonical.startswith("oci://"):
        canonical = canonical[len("oci://"):]
        inferred_file = False
    elif artifact_type == "file":
        inferred_file = True
    elif artifact_type == "oci":
        inferred_file = False
    else:
        inferred_file = Path(canonical).exists()
    is_file = artifact_type == "file" or inferred_file

    # A policy with no anchor can't verify anything; fail fast with a
    # pointer at the flags each tool needs rather than running no-ops.
    has_keyless = bool(
        (cert_identity or cert_identity_re) and cert_oidc_issuer
    )
    if not (source_uri or key or has_keyless or owner):
        raise click.UsageError(
            "no verification policy supplied. Provide at least one of: "
            "--source-uri (slsa-verifier), --owner (gh attestation), "
            "--key, or --certificate-identity[-regexp] with "
            "--certificate-oidc-issuer (cosign keyless)."
        )

    policy = VerifyPolicy(
        ref=canonical,
        is_file=is_file,
        source_uri=source_uri,
        builder_id=builder_id,
        certificate_identity=cert_identity,
        certificate_identity_regexp=cert_identity_re,
        certificate_oidc_issuer=cert_oidc_issuer,
        key=key,
        owner=owner,
        provenance_path=provenance_path,
    )
    selected = KNOWN_TOOLS if tool == "auto" else (tool,)

    try:
        report = verify_artifact(policy, tools=selected, timeout=timeout)
    except ProvenanceError as exc:
        raise click.UsageError(str(exc)) from exc

    if as_json:
        click.echo(_json.dumps(report.to_dict(), indent=2))
        raise click.exceptions.Exit(report.exit_code)

    click.echo(f"verify-artifact {report.ref}\n")
    width = max((len(r.label) for r in report.results), default=0)
    for r in report.results:
        if r.ran and r.ok:
            status = "OK"
            tail = ""
        elif r.ran:
            status = "FAIL"
            tail = f"  {r.detail}"
        else:
            status = "skip"
            tail = f"  ({r.detail.removeprefix('skipped: ')})"
        click.echo(f"  {r.label:<{width}}  {status}{tail}")
    if report.builder:
        click.echo(f"\n  builder: {report.builder}")

    gloss = {
        Verdict.PASS: (
            f"provenance verified "
            f"({sum(1 for r in report.results if r.ran and r.ok)} "
            f"verifier(s) agreed)"
        ),
        Verdict.FAIL: "verification failed",
        Verdict.INCONCLUSIVE: (
            "could not verify (no installed tool matched the policy)"
        ),
    }[report.verdict]
    click.echo(f"\n  {report.verdict.value}  {gloss}")
    raise click.exceptions.Exit(report.exit_code)
