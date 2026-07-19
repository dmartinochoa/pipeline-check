"""GHA-019. GITHUB_TOKEN written to persistent storage."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Workflow, iter_jobs, iter_steps, step_location

#: Upload-artifact ``path:`` values that bundle the entire working
#: tree (and therefore the ``.git/`` directory). Match is a normalized
#: comparison after stripping whitespace and trailing slashes. Pattern
#: globs like ``**`` and ``*`` are NOT treated as workspace-root by
#: default — ``actions/upload-artifact`` glob expansion follows
#: ``@actions/glob`` semantics, which excludes hidden directories
#: (``.git/`` among them) unless an explicit dotfile-matching glob is
#: passed; only the literal-root forms reliably bundle ``.git/``.
_REPO_ROOT_PATHS: frozenset[str] = frozenset({
    ".", "./", "",
    "${{ github.workspace }}", "${{github.workspace}}",
})


def _path_includes_git_dir(path_value: object) -> bool:
    """True when *path_value* would bundle the ``.git/`` directory."""
    if isinstance(path_value, str):
        normalized = path_value.strip().rstrip("/")
        if normalized in _REPO_ROOT_PATHS:
            return True
        if ".git/" in normalized or normalized.endswith(".git"):
            return True
        return False
    if isinstance(path_value, list):
        return any(_path_includes_git_dir(p) for p in path_value)
    return False


def _action_prefix(uses: object) -> str | None:
    """Return the action name (``owner/repo``) from a ``uses:`` value,
    lowercased. ``None`` for non-string / local-action / docker uses.
    """
    if not isinstance(uses, str):
        return None
    if uses.startswith(("./", "docker://")):
        return None
    return uses.split("@", 1)[0].strip().lower()


def _checkout_persists_credentials(step: dict[str, Any]) -> bool:
    """True when *step* is an ``actions/checkout`` invocation that
    leaves ``persist-credentials`` at its default ``true`` (or sets it
    to ``true`` explicitly)."""
    if _action_prefix(step.get("uses")) != "actions/checkout":
        return False
    with_block = step.get("with")
    if not isinstance(with_block, dict):
        return True  # default is true
    pc = with_block.get("persist-credentials")
    if pc is None:
        return True
    # YAML can land this as a bool or a string. Treat any explicit
    # falsy value as opt-out.
    if pc is False:
        return False
    if isinstance(pc, str) and pc.strip().lower() in ("false", "no", "0"):
        return False
    return True


def _upload_artifact_bundles_workspace(step: dict[str, Any]) -> bool:
    """True when *step* uploads an artifact whose ``path:`` covers
    the workspace root (and therefore ``.git/``)."""
    if _action_prefix(step.get("uses")) != "actions/upload-artifact":
        return False
    with_block = step.get("with")
    if not isinstance(with_block, dict):
        return False
    return _path_includes_git_dir(with_block.get("path"))


def _find_artipacked_offender(
    job_id: str, job: dict[str, Any],
) -> tuple[str, dict[str, Any]] | None:
    """Find an ArtiPACKED-shaped pair within one job.

    Returns ``(label, upload_step)`` when the job has at least one
    ``actions/checkout`` with persist-credentials defaulted-on AND a
    subsequent ``actions/upload-artifact`` whose ``path:`` bundles
    ``.git/``. The pair must appear in that order; an upload before
    any checkout doesn't fire (no ``.git/config`` to leak yet).
    """
    seen_checkout = False
    for step in iter_steps(job):
        if _checkout_persists_credentials(step):
            seen_checkout = True
            continue
        if seen_checkout and _upload_artifact_bundles_workspace(step):
            name = step.get("name") or step.get("id") or "upload-artifact"
            return (f"{job_id}.{name} (ArtiPACKED)", step)
    return None


#: The token / secret whose persistence we track.
_SECRET_TOKEN = r"(?:GITHUB_TOKEN|\$\{\{\s*secrets\.\w+\s*\}\})"
_TOKEN_PERSIST_RE = re.compile(
    # A secret is written to a file (or ``tee``) only when an ``echo`` /
    # ``printf`` is doing the writing — i.e. the secret is the CONTENT.
    # A secret passed as a header/flag to a command whose *stdout* is
    # redirected (``curl -H "…$GITHUB_TOKEN…" url > out.json``) does NOT
    # persist the token and must not fire.
    r"(?:echo|printf)\b[^\n]*" + _SECRET_TOKEN
    + r"[^\n]*(?:>>?\s|\|\s*tee\b)"
    # A secret redirected into a GitHub special file persists it into the
    # job/step environment regardless of the writer.
    r"|" + _SECRET_TOKEN + r"[^\n]*>>?\s*\$GITHUB_(?:ENV|OUTPUT|STATE)\b"
    r"|>>?\s*\$GITHUB_(?:ENV|OUTPUT|STATE)\b[^\n]*" + _SECRET_TOKEN
)

RULE = Rule(
    id="GHA-019",
    title="GITHUB_TOKEN written to persistent storage",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-522",),
    recommendation=(
        "Never write GITHUB_TOKEN to files, artifacts, or GITHUB_ENV. "
        "Use the token inline via ${{ secrets.GITHUB_TOKEN }} in the "
        "step that needs it."
    ),
    docs_note=(
        "Two shapes are flagged:\n\n"
        "1. **Direct.** ``run:`` body writes ``GITHUB_TOKEN`` (or any "
        "``${{ secrets.* }}`` value) to a file, ``$GITHUB_ENV``, "
        "``$GITHUB_OUTPUT``, or ``$GITHUB_STATE``, or pipes it "
        "through ``tee``.\n"
        "2. **ArtiPACKED (Palo Alto Unit 42, 2024).** Pairs "
        "``actions/checkout`` (default ``persist-credentials: true``, "
        "or explicitly set to true) with a downstream "
        "``actions/upload-artifact`` whose ``path:`` covers the repo "
        "root (``.``, ``./``, ``${{ github.workspace }}``, or an "
        "explicit ``.git/`` reference). The checkout writes the "
        "runtime ``GITHUB_TOKEN`` into ``.git/config`` via "
        "``extraheader``; the upload step bundles the whole working "
        "directory including ``.git/``, so anyone with read access "
        "to the run can ``gh run download`` the artifact and read the "
        "token out of ``.git/config``. The rule fires once per "
        "offending job; the per-finding location points at the "
        "upload step.\n\n"
        "Carve-out: secrets leaked to the workflow log (via "
        "``set -x`` shell trace, ``echo $TOKEN``, or URL-embedded "
        "credentials that a process tool logs) are GHA-033's domain, "
        "not GHA-019's. ``greylag-ci/cicd-goat`` scenario 27 fires "
        "GHA-033 only — the secret leaks to log via ``set -x`` but "
        "no token persists to file / ``$GITHUB_ENV`` / artifact, "
        "which is the persistence shape GHA-019 covers."
    ),
    exploit_example=(
        "# Vulnerable: token written to a file that survives the\n"
        "# step boundary and lands in the upload-artifact bundle.\n"
        "jobs:\n"
        "  build:\n"
        "    permissions: { contents: write, packages: write }\n"
        "    steps:\n"
        "      - run: echo \"${{ secrets.GITHUB_TOKEN }}\" > /tmp/token\n"
        "      - run: make build                   # writes /tmp/token\n"
        "                                          # into ./dist/\n"
        "      - uses: actions/upload-artifact@<sha>\n"
        "        with:\n"
        "          name: build-output\n"
        "          path: dist/\n"
        "\n"
        "# Attack: any contributor (or, on public repos, anyone)\n"
        "# downloads the artifact:\n"
        "#\n"
        "#   gh run download <run-id> -n build-output\n"
        "#   cat build-output/tmp/token            # full GITHUB_TOKEN\n"
        "#\n"
        "# The token is scoped to the workflow's permissions block —\n"
        "# in this case write to ``contents`` and ``packages``,\n"
        "# enough to push tampered binaries to GHCR or rewrite the\n"
        "# branch the workflow runs on. Composes with SCM-001\n"
        "# (unprotected default branch) into XPC-004's \"open a PR,\n"
        "# fetch artifact, ship malicious binary\" loop.\n"
        "\n"
        "# Other persistence patterns the rule catches:\n"
        "#   echo \"TOKEN=$GITHUB_TOKEN\" >> $GITHUB_ENV\n"
        "#   echo \"::set-output name=tok::$GITHUB_TOKEN\"\n"
        "#   echo \"$SECRET\" | tee /tmp/cache/secret\n"
        "\n"
        "# Safe: use the token inline in the step that needs it; never\n"
        "# write it anywhere that survives the step's environment:\n"
        "      - run: gh release create v1.0.0 dist/*\n"
        "        env:\n"
        "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}"
    ),
)


def check(path: str, doc: dict[str, Any], wf: Workflow | None = None) -> Finding:
    offenders: list[str] = []
    locations = []
    anchor_jobs: dict[str, None] = {}
    for job_id, job in iter_jobs(doc):
        for step in iter_steps(job):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            if _TOKEN_PERSIST_RE.search(run):
                name = step.get("name") or step.get("id") or "unnamed"
                offenders.append(f"{job_id}.{name}")
                locations.append(step_location(path, step))
                anchor_jobs[job_id] = None
        artipacked = _find_artipacked_offender(job_id, job)
        if artipacked is not None:
            label, upload_step = artipacked
            offenders.append(label)
            locations.append(step_location(path, upload_step))
            anchor_jobs[job_id] = None
    passed = not offenders
    # When this workflow is a resolved callee invoked with
    # ``secrets: inherit``, the persistence vector is strictly
    # broader: every caller secret crosses the boundary, so a
    # ``echo $SECRET >> file`` pattern leaks the caller's universe.
    # Annotate the description so report readers see the chain.
    inherit_note = ""
    if wf is not None and wf.inherits_secrets:
        inherit_note = (
            " (callee inherits caller secrets via ``secrets: inherit``)"
        )
    desc = (
        "No GITHUB_TOKEN persistence patterns detected in this workflow."
        if passed else
        f"GITHUB_TOKEN written to persistent storage in: "
        f"{', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}." + inherit_note
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        # AC-010 / AC-013 / XPC-004 intersect these anchors with the
        # impact-side anchors (GHA-012, GHA-036, branch-protection).
        job_anchors=tuple(anchor_jobs),
    )
