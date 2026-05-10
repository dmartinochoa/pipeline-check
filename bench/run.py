"""Vulnerable-by-design benchmark runner.

Walks every case under ``bench/cases/``, runs pipeline-check
against the case's fixture set, and reports recall against the
case's hand-curated ``expected.txt`` list.

Usage::

    python bench/run.py                      # all cases, table
    python bench/run.py --case <slug>        # one case
    python bench/run.py --json               # machine-readable
    python bench/run.py --suggest            # populate expected.txt

Exit code 0 when every case hits 100 % recall on its expected
list, 1 otherwise. ``tests/test_bench.py`` runs this script as a
regression gate so a rule that silently stops firing on a case
trips the CI suite.

Design choices
--------------

  * **In-process API, not subprocess.** Importing the scanner
    directly is ~50x faster than shelling out and lets the runner
    surface stack traces from rule failures cleanly.

  * **Auto-detect the providers per case.** The runner doesn't
    take a ``--pipeline`` flag because each case's fixtures
    determine what to scan: a ``.github/workflows/`` dir → GHA, a
    ``Dockerfile`` → Dockerfile, ``manifests/*.yaml`` → K8s, etc.
    Mirrors the CLI's no-arg auto-detect.

  * **Recall, not precision.** A case's ``expected.txt`` is the
    floor — extras are reported but don't fail the run. Real
    vulnerable code triggers many incidental rules; the test
    asserts every *named* rule fires, not that nothing else does.

  * **No comparison harness yet.** The matrix vs Zizmor / Poutine
    / Checkov is tracked under ``COMPARISON.md`` and lives
    outside this script — installing four other scanners in CI
    is its own surface.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Make the repo importable when the script is run directly. The
# pipeline_check imports below have to come *after* this sys.path
# nudge, so the E402 noqa is intentional, not a style oversight.
_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from pipeline_check.core import chains as _chains  # noqa: E402
from pipeline_check.core.checks.base import Finding  # noqa: E402
from pipeline_check.core.checks.dockerfile.base import DockerfileContext  # noqa: E402
from pipeline_check.core.checks.dockerfile.pipelines import DockerfileChecks  # noqa: E402
from pipeline_check.core.checks.github.base import GitHubContext  # noqa: E402
from pipeline_check.core.checks.github.workflows import WorkflowChecks  # noqa: E402
from pipeline_check.core.checks.kubernetes.base import KubernetesContext  # noqa: E402
from pipeline_check.core.checks.kubernetes.manifests import (  # noqa: E402
    KubernetesManifestChecks,
)
from pipeline_check.core.checks.scm.base import (  # noqa: E402
    DiskSCMFetcher,
    SCMContext,
)
from pipeline_check.core.checks.scm.posture import SCMPostureChecks  # noqa: E402

CASES_DIR = Path(__file__).resolve().parent / "cases"


@dataclass(slots=True)
class CaseResult:
    slug: str
    expected: list[str]
    fired: list[str]
    extras: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    @property
    def recall(self) -> float:
        if not self.expected:
            return 1.0
        hit = sum(1 for cid in self.expected if cid in set(self.fired))
        return hit / len(self.expected)


# ── Expected file parsing ────────────────────────────────────────


def _read_expected(path: Path) -> list[str]:
    """Read a case's expected.txt. Comments (#) and blank lines
    are skipped. Order is preserved so ``--json`` output is
    stable across runs."""
    if not path.is_file():
        return []
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


# ── Per-provider scan dispatch ──────────────────────────────────


def _scan_case(case_dir: Path) -> list[str]:
    """Run every applicable provider against the case's fixtures
    AND evaluate the chain engine on the union of findings.
    Returns the list of failing check_ids (deduped, sorted), with
    chain check_ids (``AC-NNN`` / ``XPC-NNN``) included alongside
    rule check_ids.

    Each provider's input shape is auto-detected from the case
    directory layout — no explicit ``--pipeline`` config per case.
    The chain engine sees the same union the multi-provider scan
    mode would, so cross-provider chains can fire on a case that
    spans (e.g.) a Dockerfile and a Kubernetes manifest.
    """
    findings: list[Finding] = []

    # GitHub Actions: any .github/workflows directory.
    gha_dir = case_dir / ".github" / "workflows"
    if gha_dir.is_dir():
        ctx = GitHubContext.from_path(gha_dir)
        findings.extend(WorkflowChecks(ctx).run())

    # Dockerfile: any file named Dockerfile, Containerfile, or
    # ending .Dockerfile under the case root.
    dockerfiles = [
        p for p in case_dir.rglob("*")
        if p.is_file() and (
            p.name in {"Dockerfile", "Containerfile"}
            or p.name.endswith(".Dockerfile")
        )
    ]
    for df in dockerfiles:
        ctx_df = DockerfileContext.from_path(df)
        findings.extend(DockerfileChecks(ctx_df).run())

    # Kubernetes manifests: any *.yaml under manifests/ or k8s/.
    k8s_dirs = [
        d for d in (case_dir / "manifests", case_dir / "k8s")
        if d.is_dir()
    ]
    for k8s_dir in k8s_dirs:
        ctx_k8s = KubernetesContext.from_path(k8s_dir)
        findings.extend(KubernetesManifestChecks(ctx_k8s).run())

    # SCM posture: cases that exercise the GitHub-API-driven
    # provider drop a ``scm_config.json`` declaring
    # ``{"owner": "...", "name": "..."}`` plus a ``scm/``
    # subdirectory of fixture JSON files (the same shape
    # ``--scm-fixture-dir`` reads). Bench runs never hit the
    # network — fixture mode keeps the suite hermetic.
    scm_config_path = case_dir / "scm_config.json"
    scm_dir = case_dir / "scm"
    if scm_config_path.is_file() and scm_dir.is_dir():
        try:
            cfg = json.loads(
                scm_config_path.read_text(encoding="utf-8"),
            )
        except (OSError, json.JSONDecodeError):
            cfg = {}
        owner = cfg.get("owner")
        name = cfg.get("name")
        if isinstance(owner, str) and isinstance(name, str):
            ctx_scm = SCMContext.for_repo(
                owner, name, DiskSCMFetcher([scm_dir]),
            )
            findings.extend(SCMPostureChecks(ctx_scm).run())

    # Chain engine on the union. Adds one synthetic check_id per
    # firing chain (``AC-NNN`` / ``XPC-NNN``) so the bench's
    # expected.txt can assert chain coverage alongside rule
    # coverage. Same engine the CLI runs in multi-provider mode,
    # so a case that fires AC-011 here would fire AC-011 in
    # ``--pipelines dockerfile,kubernetes`` too.
    fired: set[str] = {f.check_id for f in findings if not f.passed}
    try:
        for chain in _chains.evaluate(findings):
            fired.add(chain.chain_id)
    except Exception:  # noqa: BLE001
        # The chain engine should never raise on well-formed
        # findings, but if a future chain rule introduces a bug we
        # don't want to crash the whole bench run; per-rule scan
        # output is already in ``fired`` and meaningful.
        pass

    return sorted(fired)


def _evaluate_case(case_dir: Path) -> CaseResult:
    """Scan one case and compute recall + extras vs expected."""
    expected = _read_expected(case_dir / "expected.txt")
    fired = _scan_case(case_dir)
    fired_set = set(fired)
    expected_set = set(expected)
    return CaseResult(
        slug=case_dir.name,
        expected=expected,
        fired=fired,
        extras=sorted(fired_set - expected_set),
        missing=sorted(expected_set - fired_set),
    )


# ── Reporting ───────────────────────────────────────────────────


def _print_table(results: list[CaseResult]) -> None:
    print()
    print(f"{'Case':<30}  {'Expected':>8}  {'Fired':>5}  "
          f"{'Recall':>7}  {'Missing'}")
    print("-" * 80)
    for r in results:
        miss = ", ".join(r.missing) if r.missing else "-"
        print(
            f"{r.slug:<30}  {len(r.expected):>8}  "
            f"{len(r.fired):>5}  {r.recall * 100:>6.1f}%  {miss}"
        )
    print()
    total_expected = sum(len(r.expected) for r in results)
    total_hit = sum(
        sum(1 for cid in r.expected if cid in set(r.fired))
        for r in results
    )
    overall = (
        100.0 if total_expected == 0
        else 100.0 * total_hit / total_expected
    )
    print(
        f"Total: {total_hit}/{total_expected} expected check IDs fired "
        f"({overall:.1f}% recall across {len(results)} case(s))"
    )


def _print_json(results: list[CaseResult]) -> None:
    print(json.dumps([
        {
            "case": r.slug,
            "expected": r.expected,
            "fired": r.fired,
            "extras": r.extras,
            "missing": r.missing,
            "recall": r.recall,
        }
        for r in results
    ], indent=2))


def _suggest_expected(case_dir: Path) -> None:
    """Pre-populate an expected.txt by listing every check_id the
    current scan emits. Operator hand-edits to keep ONLY the IDs
    the case is meant to demonstrate."""
    fired = _scan_case(case_dir)
    if not fired:
        print(f"[{case_dir.name}] no findings — empty case fixtures?",
              file=sys.stderr)
        return
    out_lines = [
        "# Auto-suggested by ``bench/run.py --suggest``. Hand-edit",
        "# to keep ONLY the check IDs this case is meant to",
        "# demonstrate; drop incidental fires from unrelated rules.",
        "",
    ]
    out_lines.extend(fired)
    target = case_dir / "expected.txt"
    target.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    print(f"[{case_dir.name}] wrote {len(fired)} candidate check IDs "
          f"to {target}", file=sys.stderr)


# ── Entry point ─────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Vulnerable-by-design benchmark runner",
    )
    parser.add_argument(
        "--case", default=None,
        help="Run only the case with this slug (directory name).",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit machine-readable JSON instead of the table.",
    )
    parser.add_argument(
        "--suggest", action="store_true",
        help=(
            "Write a candidate expected.txt populated with every "
            "check_id the current scan emits. Combine with --case."
        ),
    )
    args = parser.parse_args(argv)

    if not CASES_DIR.is_dir():
        print(f"bench cases dir missing: {CASES_DIR}", file=sys.stderr)
        return 2

    case_dirs = sorted(d for d in CASES_DIR.iterdir() if d.is_dir())
    if args.case:
        case_dirs = [d for d in case_dirs if d.name == args.case]
        if not case_dirs:
            print(f"unknown case: {args.case!r}. Available: "
                  f"{[d.name for d in CASES_DIR.iterdir() if d.is_dir()]}",
                  file=sys.stderr)
            return 2

    if args.suggest:
        for d in case_dirs:
            _suggest_expected(d)
        return 0

    results = [_evaluate_case(d) for d in case_dirs]
    if args.json:
        _print_json(results)
    else:
        _print_table(results)

    # Exit non-zero on any missing expected check_id.
    if any(r.missing for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
