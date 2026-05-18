"""Real-world GOAT corpus benchmark runner.

Clones each goat declared in ``bench/goats.yml`` to a tmpdir, runs
pipeline-check against it with the configured provider(s), and emits
a markdown digest covering per-goat recall (vs ``expected.txt``),
false-positive count (vs ``allowlist.txt``), and drift vs the
committed baseline.

Usage::

    python bench/goat_runner.py                  # all goats, markdown
    python bench/goat_runner.py --goat cicd-goat # one goat
    python bench/goat_runner.py --json           # machine-readable
    python bench/goat_runner.py --suggest        # seed expected.txt
                                                  # from current scan
    python bench/goat_runner.py --update-baseline  # rewrite baseline.json

Per-goat files live under ``bench/goats/<slug>/``:

    expected.txt   Hand-curated list of check IDs the goat intends
                   to demonstrate (one per line; ``#`` comments OK).
                   Empty file means "no recall claim yet" and the
                   goat contributes only drift signal.
    allowlist.txt  Known false positives in the form
                   ``CHECK-ID  # justification``. Allowlisted IDs
                   don't count against FP rate.
    baseline.json  Last committed scan output (failing findings
                   only, by check_id + severity + resource). Drift
                   is measured against this on every run.

Design choices vs ``bench/run.py``
----------------------------------

  * **Subprocess CLI, not Python API.** The synthetic-fixtures bench
    uses the Python API for speed (~50x). The goat bench's scan
    time is dominated by clone + filesystem traversal of a real
    repo, so the subprocess overhead is in the noise, and using the
    CLI gives this bench the same view a real CI run gets.

  * **Provider config is explicit in the manifest.** Auto-detect
    is convenient but tying recall numbers to "what providers
    happened to fire" lets a new auto-detect path silently change
    the bench result. Declared providers per goat keep the bench
    deterministic across pipeline-check versions.

  * **Recall AND drift, not just recall.** The synthetic bench is
    a 100% recall gate. The goat bench cannot be that, because the
    expected list is incomplete by definition on day one. Drift vs
    a committed ``baseline.json`` is the catch-all gate: if a rule
    silently stops firing, the goat's failing-finding set shrinks
    and the runner exits non-zero.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_HERE = Path(__file__).resolve().parent
GOATS_DIR = _HERE / "goats"
MANIFEST = _HERE / "goats.yml"


# Goat declared in the manifest.
@dataclass(slots=True)
class GoatSpec:
    slug: str
    repo: str
    ref: str
    pipelines: list[str]
    # Extra CLI args appended to the pipeline_check invocation,
    # forwarded verbatim. Used to point per-provider path flags
    # (``--cfn-template``, ``--k8s-path``, ...) at non-canonical
    # layouts a given goat happens to use.
    extra_args: list[str] = field(default_factory=list)
    description: str = ""
    skip: bool = False
    skip_reason: str = ""


# Per-goat scan result, plus everything render needs in one place.
@dataclass(slots=True)
class GoatResult:
    spec: GoatSpec
    skipped: bool = False
    error: str | None = None
    ref_resolved: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    expected: set[str] = field(default_factory=set)
    allowlist: dict[str, str] = field(default_factory=dict)
    baseline_fired: set[str] = field(default_factory=set)

    @property
    def fired_failing(self) -> list[dict[str, Any]]:
        return [f for f in self.findings if not f.get("passed", False)]

    @property
    def fired(self) -> set[str]:
        return {f["check_id"] for f in self.fired_failing}

    @property
    def recall(self) -> float:
        if not self.expected:
            return 1.0
        return len(self.expected & self.fired) / len(self.expected)

    @property
    def missing_expected(self) -> set[str]:
        return self.expected - self.fired

    @property
    def allowlisted_fps(self) -> set[str]:
        return self.fired & set(self.allowlist)

    @property
    def new_vs_baseline(self) -> set[str]:
        if not self.baseline_fired:
            return set()
        return self.fired - self.baseline_fired

    @property
    def resolved_vs_baseline(self) -> set[str]:
        if not self.baseline_fired:
            return set()
        return self.baseline_fired - self.fired


# ── Manifest + per-goat IO ──────────────────────────────────────


def load_manifest(path: Path = MANIFEST) -> list[GoatSpec]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out: list[GoatSpec] = []
    for entry in raw.get("goats", []):
        out.append(GoatSpec(
            slug=entry["slug"],
            repo=entry["repo"],
            ref=str(entry.get("ref", "HEAD")),
            pipelines=list(entry.get("pipelines", [])),
            extra_args=[str(a) for a in entry.get("args", [])],
            description=str(entry.get("description", "")).strip(),
            skip=bool(entry.get("skip", False)),
            skip_reason=str(entry.get("skip_reason", "")).strip(),
        ))
    return out


def _goat_dir(slug: str) -> Path:
    return GOATS_DIR / slug


def load_expected(slug: str) -> set[str]:
    p = _goat_dir(slug) / "expected.txt"
    if not p.is_file():
        return set()
    out: set[str] = set()
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Tolerate trailing comments / whitespace.
        out.add(line.split()[0].split("#")[0].strip())
    out.discard("")
    return out


def load_allowlist(slug: str) -> dict[str, str]:
    p = _goat_dir(slug) / "allowlist.txt"
    if not p.is_file():
        return {}
    out: dict[str, str] = {}
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            cid, _, reason = line.partition("#")
            cid = cid.strip()
            reason = reason.strip()
        else:
            cid, reason = line, ""
        if cid:
            out[cid] = reason
    return out


def load_baseline(slug: str) -> set[str]:
    p = _goat_dir(slug) / "baseline.json"
    if not p.is_file():
        return set()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return set()
    return {
        f["check_id"]
        for f in data.get("findings", [])
        if not f.get("passed", False) and "check_id" in f
    }


def write_baseline(result: GoatResult) -> None:
    target = _goat_dir(result.spec.slug)
    target.mkdir(parents=True, exist_ok=True)
    payload = {
        "slug": result.spec.slug,
        "ref_resolved": result.ref_resolved,
        # Trimmed shape: enough to detect drift, not so much that
        # baseline.json bloats on every rule pack update.
        "findings": sorted(
            (
                {
                    "check_id": f["check_id"],
                    "severity": f.get("severity"),
                    "resource": f.get("resource"),
                }
                for f in result.fired_failing
            ),
            key=lambda d: (d["check_id"], d.get("resource") or ""),
        ),
    }
    (target / "baseline.json").write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )


# ── Clone + scan ────────────────────────────────────────────────


def _is_sha(ref: str) -> bool:
    return len(ref) == 40 and all(c in "0123456789abcdef" for c in ref.lower())


def clone_goat(spec: GoatSpec, dest: Path) -> str:
    """Shallow-clone the goat to ``dest`` and return the resolved
    commit SHA. Handles full-SHA refs (which ``git clone --branch``
    rejects) via init + fetch + checkout."""
    dest.mkdir(parents=True, exist_ok=True)
    if _is_sha(spec.ref):
        subprocess.run(
            ["git", "init", "-q", str(dest)],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(dest), "remote", "add", "origin", spec.repo],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(dest), "fetch", "--depth", "1", "origin", spec.ref],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(dest), "checkout", "-q", spec.ref],
            check=True,
        )
    else:
        subprocess.run(
            [
                "git", "clone", "--depth", "1",
                "--branch", spec.ref, spec.repo, str(dest),
            ],
            check=True,
        )
    out = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    )
    return out.stdout.strip()


def scan_goat(
    workdir: Path,
    pipelines: list[str],
    extra_args: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Run pipeline-check against ``workdir`` and return the parsed
    findings list. Treats exit codes 0 and 1 (clean / gate-failed)
    as success since both still emit findings JSON; 2 / 3 are
    scanner / config errors and surface as a raise."""
    if len(pipelines) == 1:
        provider_flag = ["--pipeline", pipelines[0]]
    elif len(pipelines) > 1:
        provider_flag = ["--pipelines", ",".join(pipelines)]
    else:
        provider_flag = []
    cmd = [
        "pipeline_check", *provider_flag,
        *(extra_args or []),
        "--output", "json",
    ]
    proc = subprocess.run(
        cmd,
        cwd=str(workdir),
        capture_output=True,
        text=True,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(
            f"pipeline_check exit {proc.returncode}: "
            f"{proc.stderr.strip()[:400]}"
        )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "pipeline_check did not emit parseable JSON. "
            f"stdout prefix: {proc.stdout[:200]!r}"
        ) from exc
    findings = data.get("findings", [])
    if not isinstance(findings, list):
        raise RuntimeError(
            f"pipeline_check JSON has non-list ``findings`` field "
            f"of type {type(findings).__name__}"
        )
    return findings


# ── Per-goat evaluation ─────────────────────────────────────────


def evaluate_goat(spec: GoatSpec) -> GoatResult:
    expected = load_expected(spec.slug)
    allowlist = load_allowlist(spec.slug)
    baseline = load_baseline(spec.slug)
    if spec.skip:
        return GoatResult(
            spec=spec,
            skipped=True,
            expected=expected,
            allowlist=allowlist,
            baseline_fired=baseline,
        )
    tmp = Path(tempfile.mkdtemp(prefix=f"goat-{spec.slug}-"))
    try:
        sha = clone_goat(spec, tmp)
        findings = scan_goat(tmp, spec.pipelines, spec.extra_args)
        return GoatResult(
            spec=spec,
            ref_resolved=sha,
            findings=findings,
            expected=expected,
            allowlist=allowlist,
            baseline_fired=baseline,
        )
    except (subprocess.CalledProcessError, RuntimeError) as exc:
        return GoatResult(
            spec=spec,
            error=str(exc),
            expected=expected,
            allowlist=allowlist,
            baseline_fired=baseline,
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ── Reporting ───────────────────────────────────────────────────


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        if f.get("passed", False):
            continue
        sev = str(f.get("severity") or "").upper()
        if sev in out:
            out[sev] += 1
    return out


def render_markdown(results: list[GoatResult]) -> str:
    lines: list[str] = []
    # Marker the workflow uses to find an existing comment to edit
    # in place. Keep on its own line; the workflow's jq grep is a
    # substring match.
    lines.append("<!-- goat-bench-comment -->")
    lines.append("## GOAT bench report")
    lines.append("")
    scanned = sum(1 for r in results if not r.skipped and not r.error)
    skipped = sum(1 for r in results if r.skipped)
    errored = sum(1 for r in results if r.error)
    lines.append(
        f"{len(results)} goats: {scanned} scanned, "
        f"{skipped} skipped, {errored} errored."
    )
    lines.append("")
    lines.append("| Goat | Status | Findings | Recall | FPs | Drift |")
    lines.append("|------|--------|----------|--------|-----|-------|")
    for r in results:
        slug = r.spec.slug
        if r.skipped:
            reason = r.spec.skip_reason or "-"
            lines.append(
                f"| `{slug}` | skipped | - | - | - | "
                f"{_oneline(reason)} |"
            )
            continue
        if r.error:
            lines.append(
                f"| `{slug}` | error | - | - | - | "
                f"{_oneline(r.error)} |"
            )
            continue
        sc = _severity_counts(r.findings)
        sev_cell = (
            f"{sum(sc.values())} "
            f"(C{sc['CRITICAL']}/H{sc['HIGH']}/"
            f"M{sc['MEDIUM']}/L{sc['LOW']})"
        )
        recall_cell = (
            f"{len(r.expected & r.fired)}/{len(r.expected)} "
            f"({r.recall * 100:.0f}%)"
            if r.expected else "-"
        )
        fp_cell = str(len(r.allowlisted_fps))
        if r.baseline_fired:
            new = len(r.new_vs_baseline)
            res = len(r.resolved_vs_baseline)
            drift_cell = (
                f"+{new}/-{res}" if (new or res) else "stable"
            )
        else:
            drift_cell = "no baseline"
        lines.append(
            f"| `{slug}` | scanned | {sev_cell} | {recall_cell} | "
            f"{fp_cell} | {drift_cell} |"
        )
    lines.append("")
    # Per-goat detail blocks for anything interesting.
    for r in results:
        if r.skipped or r.error:
            continue
        interesting = (
            r.missing_expected
            or r.allowlisted_fps
            or r.new_vs_baseline
            or r.resolved_vs_baseline
        )
        if not interesting:
            continue
        lines.append(f"### `{r.spec.slug}`")
        lines.append("")
        if r.ref_resolved:
            lines.append(f"- Ref: `{r.ref_resolved}`")
        lines.append(f"- Pipelines: {', '.join(r.spec.pipelines) or 'auto'}")
        if r.missing_expected:
            lines.append(
                f"- **Missing expected** ({len(r.missing_expected)}): "
                f"`{'`, `'.join(sorted(r.missing_expected))}`"
            )
        if r.allowlisted_fps:
            lines.append(
                f"- **Allowlisted FPs fired**: "
                f"`{'`, `'.join(sorted(r.allowlisted_fps))}`"
            )
        if r.new_vs_baseline:
            lines.append(
                f"- **New vs baseline**: "
                f"`{'`, `'.join(sorted(r.new_vs_baseline))}`"
            )
        if r.resolved_vs_baseline:
            lines.append(
                f"- **Resolved vs baseline**: "
                f"`{'`, `'.join(sorted(r.resolved_vs_baseline))}`"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_json(results: list[GoatResult]) -> str:
    payload = []
    for r in results:
        payload.append({
            "slug": r.spec.slug,
            "skipped": r.skipped,
            "skip_reason": r.spec.skip_reason,
            "error": r.error,
            "ref_resolved": r.ref_resolved,
            "fired": sorted(r.fired),
            "expected": sorted(r.expected),
            "missing_expected": sorted(r.missing_expected),
            "allowlisted_fps_fired": sorted(r.allowlisted_fps),
            "new_vs_baseline": sorted(r.new_vs_baseline),
            "resolved_vs_baseline": sorted(r.resolved_vs_baseline),
            "recall": r.recall,
            "severity_counts": _severity_counts(r.findings),
        })
    return json.dumps(payload, indent=2)


def _oneline(s: str) -> str:
    """Collapse to a single line and strip pipe chars so it survives
    a markdown table cell."""
    return " ".join(s.split()).replace("|", " ")[:160]


# ── --suggest helper ────────────────────────────────────────────


def suggest_expected(result: GoatResult) -> None:
    if result.skipped or result.error:
        print(
            f"[{result.spec.slug}] skipping --suggest "
            f"({'skipped' if result.skipped else 'errored'})",
            file=sys.stderr,
        )
        return
    if not result.fired:
        print(
            f"[{result.spec.slug}] no findings — skipping --suggest",
            file=sys.stderr,
        )
        return
    target_dir = _goat_dir(result.spec.slug)
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / "expected.txt"
    body = [
        "# Auto-suggested by ``goat_runner.py --suggest``. Hand-edit",
        "# to keep ONLY the check IDs this goat is intended to",
        "# demonstrate; drop incidental fires from unrelated rules.",
        "",
        *sorted(result.fired),
    ]
    target.write_text("\n".join(body) + "\n", encoding="utf-8")
    print(
        f"[{result.spec.slug}] wrote {len(result.fired)} candidate "
        f"check IDs to {target}",
        file=sys.stderr,
    )


# ── Entry point ─────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Real-world GOAT corpus benchmark runner",
    )
    parser.add_argument(
        "--goat", default=None,
        help="Only run the goat with this slug (manifest entry).",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit machine-readable JSON instead of markdown.",
    )
    parser.add_argument(
        "--markdown", action="store_true",
        help="Emit the markdown digest (default).",
    )
    parser.add_argument(
        "--suggest", action="store_true",
        help=(
            "After scanning, write a candidate expected.txt per goat "
            "populated with every check ID the current scan fires."
        ),
    )
    parser.add_argument(
        "--update-baseline", action="store_true",
        help=(
            "After scanning, rewrite each goat's baseline.json from "
            "the current scan output. Commit the resulting files."
        ),
    )
    parser.add_argument(
        "--manifest", default=str(MANIFEST),
        help="Path to the goats.yml manifest.",
    )
    args = parser.parse_args(argv)

    manifest_path = Path(args.manifest)
    if not manifest_path.is_file():
        print(f"manifest missing: {manifest_path}", file=sys.stderr)
        return 2

    specs = load_manifest(manifest_path)
    if args.goat:
        specs = [s for s in specs if s.slug == args.goat]
        if not specs:
            available = [s.slug for s in load_manifest(manifest_path)]
            print(
                f"unknown goat: {args.goat!r}. Available: {available}",
                file=sys.stderr,
            )
            return 2

    results = [evaluate_goat(s) for s in specs]

    if args.suggest:
        for r in results:
            suggest_expected(r)
        return 0

    if args.update_baseline:
        for r in results:
            if r.skipped or r.error:
                continue
            write_baseline(r)
        return 0

    if args.json:
        print(render_json(results))
    else:
        print(render_markdown(results))

    # Exit non-zero if any goat:
    #   * errored (clone or scan failure),
    #   * is missing a curated expected check ID,
    #   * picked up a new finding vs baseline that isn't allowlisted.
    # Skipped goats and goats with empty expected.txt + no baseline
    # are silent — they contribute trend signal only.
    bad = False
    for r in results:
        if r.skipped:
            continue
        if r.error:
            bad = True
            continue
        if r.missing_expected:
            bad = True
        unwelcome_new = r.new_vs_baseline - set(r.allowlist)
        if unwelcome_new:
            bad = True
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
