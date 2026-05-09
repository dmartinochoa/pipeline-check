"""Per-pipeline taint graph for the GitLab CI dataflow rules.

The GitLab analogue of the GHA engine in
``pipeline_check.core.checks.github._taint_graph``. Generalises
``GL-002``'s single-job script-injection detection to a pipeline-
wide reachability problem that follows the canonical GitLab cross-
job propagation channel: ``artifacts.reports.dotenv``.

GitLab's dotenv-artifact mechanism is the direct equivalent of
GitHub Actions' ``$GITHUB_OUTPUT``. A producer job writes
``KEY=value`` lines to a file, declares
``artifacts.reports.dotenv: <file>``, and downstream jobs that
``needs:`` (or ``dependencies:``) the producer auto-import every
``KEY`` as a regular ``$KEY`` variable. The injection shape:

  extract:
    script:
      - echo "TITLE=$CI_COMMIT_TITLE" > taint.env
    artifacts:
      reports:
        dotenv: taint.env

  build:
    needs: [extract]
    script:
      - echo "$TITLE"            <- taint exits here

GL-002 catches the inner ``$CI_COMMIT_TITLE`` interpolation in
the producer's script. What it doesn't catch is the consumer:
``$TITLE`` looks like any other shell variable until you trace
it through the dotenv artifact. The engine here closes that
gap.

The engine is deliberately small. It does NOT model:

  * ``extends:`` job inheritance (taint flow through a hidden
    template job's ``variables:`` block) — flagged for v2;
  * ``include:`` cross-pipeline file inclusion — also v2;
  * GitLab's ``trigger:`` parent-child pipeline relationships;
  * ``needs:`` with ``project:`` (cross-project artifacts).

Everything those would add is incremental on top of the
single-pipeline single-file shape covered here.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from .base import iter_jobs, job_scripts
from .rules._helpers import UNTRUSTED_VAR_RE


@dataclass(frozen=True, slots=True)
class TaintSource:
    """One untrusted-input expression detected in the pipeline.

    Mirrors the GHA :class:`TaintSource`. ``expr`` is the raw
    matched ``$CI_COMMIT_*`` / ``$CI_MERGE_REQUEST_*`` token;
    ``location`` is a ``job:script[N]`` breadcrumb.
    """

    expr: str
    location: str


@dataclass(frozen=True, slots=True)
class TaintPath:
    """A computed source-to-sink path through the GitLab pipeline."""

    source: TaintSource
    hops: tuple[str, ...]
    sink_location: str
    sink_consumer: str

    def render(self) -> str:
        """One-line ``source -> hop -> ... -> sink`` rendering."""
        chain: list[str] = [
            f"${self.source.expr}@{self.source.location}",
        ]
        chain.extend(self.hops)
        chain.append(f"sink@{self.sink_location}({self.sink_consumer})")
        return " -> ".join(chain)


# ── Dotenv write detector ─────────────────────────────────────────


# Match the canonical dotenv write idiom in a script line:
#   echo "KEY=value" > taint.env
#   echo "KEY=value" >> taint.env
# Captures the var name and the RHS value text. The redirect
# target is captured separately so downstream we can confirm the
# job's ``artifacts.reports.dotenv`` exposes the same path.
_DOTENV_WRITE_RE = re.compile(
    r"""
    echo\s+
    ["']?(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<val>[^"'\n]*?)["']?\s*
    >>?\s*
    (?P<file>[^\s|;&]+)
    """,
    re.VERBOSE,
)


def _extract_dotenv_writes(script_line: str) -> list[tuple[str, str, str]]:
    """Return ``[(var_name, rhs_value, target_file), ...]`` for *script_line*.

    A single script line can contain at most one write in this
    matcher; the producer pass loops over every script line, so
    multi-line scripts still get fully covered.
    """
    out: list[tuple[str, str, str]] = []
    for m in _DOTENV_WRITE_RE.finditer(script_line):
        name = m.group("name")
        val = m.group("val")
        target = m.group("file").strip()
        if name and target:
            out.append((name, val, target))
    return out


# ── Reference detector ────────────────────────────────────────────


def _iter_var_refs(text: str, names: set[str]) -> Iterator[tuple[str, int]]:
    """Yield ``(var_name, offset)`` for each unquoted ``$<NAME>`` /
    ``${<NAME>}`` reference matching one of *names*.

    Quote-state filtering is applied here: a reference inside a
    double-quoted segment is treated as safe (the shell still
    interpolates but treats the value as a single token, no
    re-tokenization). Single-quoted segments don't interpolate at
    all in POSIX shell. The walker tracks both quote states.
    """
    if not names:
        return
    in_single = False
    in_double = False
    i = 0
    pattern = re.compile(
        r"\$\{?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\}?",
    )
    while i < len(text):
        ch = text[i]
        if ch == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            i += 1
            continue
        if ch == "$" and not (in_single or in_double):
            m = pattern.match(text, i)
            if m and m.group("name") in names:
                yield m.group("name"), i
                i = m.end()
                continue
        i += 1


# ── Engine state ──────────────────────────────────────────────────


@dataclass
class _GraphState:
    """Per-pipeline taint graph.

    Tracks every variable name a producer job leaks via dotenv
    artifact, keyed by ``(job_name, dotenv_path)``. Multiple jobs
    can leak the same variable; the consumer pass cross-references
    the leak against the consumer's ``needs:`` / ``dependencies:``
    list so we only fire on actual auto-import paths.
    """

    # ``producer_job -> var_name -> (dotenv_path, sources)``
    leaks: dict[str, dict[str, tuple[str, list[TaintSource]]]] = field(
        default_factory=dict,
    )

    def record_leak(
        self,
        producer_job: str,
        var_name: str,
        dotenv_path: str,
        source: TaintSource,
    ) -> None:
        bucket = self.leaks.setdefault(producer_job, {})
        existing = bucket.get(var_name)
        if existing is None:
            bucket[var_name] = (dotenv_path, [source])
        else:
            existing[1].append(source)

    def lookup_leak(
        self, producer_job: str, var_name: str,
    ) -> list[TaintSource]:
        bucket = self.leaks.get(producer_job, {})
        entry = bucket.get(var_name)
        return list(entry[1]) if entry is not None else []

    def producers_of(self, var_name: str) -> list[str]:
        """Producer jobs that leak the named variable via dotenv."""
        return [
            j for j, bucket in self.leaks.items()
            if var_name in bucket
        ]


# ── Public API ────────────────────────────────────────────────────


def analyze_pipeline(doc: dict[str, Any]) -> list[TaintPath]:
    """Build a taint graph for *doc* and return every source-to-sink path.

    Two passes:

      1. **Producer pass** — walk every job's scripts. For each
         line that writes a ``KEY=value`` to a target file AND the
         job's ``artifacts.reports.dotenv`` includes that file,
         classify ``value`` for taint sources and record the leak.
      2. **Consumer pass** — walk every job's scripts. For each
         unquoted ``$KEY`` reference, if a job in the consumer's
         ``needs:`` / ``dependencies:`` list leaked ``KEY`` in
         pass 1, emit a path.
    """
    if not isinstance(doc, dict):
        return []

    state = _GraphState()
    paths: list[TaintPath] = []

    # ── Pass 1: producers. ────────────────────────────────────
    for job_name, job in iter_jobs(doc):
        dotenv_targets = _dotenv_targets(job)
        if not dotenv_targets:
            continue
        for line_idx, line in enumerate(job_scripts(job)):
            for var_name, rhs, target_file in _extract_dotenv_writes(line):
                if not _matches_dotenv_target(target_file, dotenv_targets):
                    continue
                # Classify the RHS for tainted sources.
                for m in UNTRUSTED_VAR_RE.finditer(rhs):
                    expr = m.group(0).lstrip("$").strip("{}")
                    state.record_leak(
                        job_name,
                        var_name,
                        target_file,
                        TaintSource(
                            expr=expr,
                            location=f"{job_name}:script[{line_idx}]",
                        ),
                    )

    # ── Pass 2: consumers. ────────────────────────────────────
    for job_name, job in iter_jobs(doc):
        deps = _job_dependencies(job)
        if not deps:
            continue
        # Variables this job auto-imports via dotenv: union of every
        # producer's leak set.
        candidate_vars: set[str] = set()
        for dep in deps:
            candidate_vars.update(state.leaks.get(dep, {}).keys())
        if not candidate_vars:
            continue
        for line_idx, line in enumerate(job_scripts(job)):
            for var_name, _ in _iter_var_refs(line, candidate_vars):
                # Resolve which producer leaked this name; if multiple
                # do, emit one path per producer for triage clarity.
                for dep in deps:
                    sources = state.lookup_leak(dep, var_name)
                    for src in sources:
                        paths.append(TaintPath(
                            source=src,
                            hops=(
                                f"jobs.{dep}.artifacts.reports.dotenv",
                                f"${var_name}",
                            ),
                            sink_location=(
                                f"{job_name}:script[{line_idx}]"
                            ),
                            sink_consumer=f"${var_name}",
                        ))
    return paths


# ── Helpers ───────────────────────────────────────────────────────


def _dotenv_targets(job: dict[str, Any]) -> list[str]:
    """Return every dotenv path declared by *job*'s artifacts.reports."""
    artifacts = job.get("artifacts")
    if not isinstance(artifacts, dict):
        return []
    reports = artifacts.get("reports")
    if not isinstance(reports, dict):
        return []
    dotenv = reports.get("dotenv")
    if isinstance(dotenv, str):
        return [dotenv]
    if isinstance(dotenv, list):
        return [d for d in dotenv if isinstance(d, str)]
    return []


def _matches_dotenv_target(written_to: str, declared: list[str]) -> bool:
    """True when the script's redirect target matches a dotenv declaration.

    GitLab resolves both as filesystem paths inside the job's
    workspace. We match on basename + literal equality so a
    ``./taint.env`` write still matches a declared ``taint.env``.
    No glob matching: the dotenv declaration is path-literal in
    GitLab itself, even though the artifacts.paths field accepts
    globs.
    """
    written_basename = written_to.lstrip("./")
    for d in declared:
        if d == written_to:
            return True
        if d.lstrip("./") == written_basename:
            return True
    return False


def _job_dependencies(job: dict[str, Any]) -> list[str]:
    """Return the producer-job names this job auto-imports dotenv from.

    Two GitLab fields produce dotenv auto-import: ``needs:`` and
    ``dependencies:``. ``needs:`` accepts either bare strings or
    dicts ``{job: name, artifacts: true}``; we extract the job
    name for both shapes. ``dependencies:`` is always a list of
    bare strings.
    """
    deps: list[str] = []
    needs = job.get("needs")
    if isinstance(needs, list):
        for entry in needs:
            if isinstance(entry, str):
                deps.append(entry)
            elif isinstance(entry, dict):
                name = entry.get("job")
                if isinstance(name, str):
                    deps.append(name)
    dep_list = job.get("dependencies")
    if isinstance(dep_list, list):
        for entry in dep_list:
            if isinstance(entry, str):
                deps.append(entry)
    return deps


# ── Extends-chain taint analyzer ──────────────────────────────────


# Match ``$VAR`` / ``${VAR}`` references in a script line. Used by
# the extends-chain consumer pass below to detect unquoted shell
# references to inherited tainted variables.
_NAME_BOUNDARY = re.compile(
    r"\$\{?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\}?(?![A-Za-z0-9_])"
)


def _resolve_extends_chain(
    extends: Any,
    all_jobs: dict[str, dict[str, Any]],
    seen: set[str] | None = None,
) -> list[str]:
    """Return the resolved chain of template names *extends* points at.

    GitLab ``extends:`` accepts either a single string or a list
    of strings; each entry can itself reference another template,
    so we walk transitively. Cycles are broken via a visited set;
    unresolvable entries are silently dropped.
    """
    if seen is None:
        seen = set()
    if isinstance(extends, str):
        extends = [extends]
    if not isinstance(extends, list):
        return []
    out: list[str] = []
    for name in extends:
        if not isinstance(name, str) or name in seen:
            continue
        seen.add(name)
        if name in all_jobs:
            out.append(name)
            parent_extends = all_jobs[name].get("extends")
            out.extend(_resolve_extends_chain(
                parent_extends, all_jobs, seen,
            ))
    return out


def _gather_inherited_taint(
    chain: list[str],
    all_jobs: dict[str, dict[str, Any]],
) -> dict[str, TaintSource]:
    """Return ``{var_name: source, ...}`` for every tainted
    ``variables:`` entry across *chain*.

    GitLab merges variables across an extends chain (later links
    don't override earlier ones the way ``script:`` does), so we
    union every tainted entry. The first source seen wins for
    description rendering — the consumer just needs to know that
    the variable carries taint, not which specific link declared
    it.
    """
    out: dict[str, TaintSource] = {}
    for tpl_name in chain:
        tpl = all_jobs.get(tpl_name)
        if not isinstance(tpl, dict):
            continue
        variables = tpl.get("variables")
        if not isinstance(variables, dict):
            continue
        for var_name, value in variables.items():
            raw = (
                value.get("value") if isinstance(value, dict) else value
            )
            if not isinstance(raw, str):
                continue
            for m in UNTRUSTED_VAR_RE.finditer(raw):
                expr = m.group(0).lstrip("$").strip("{}")
                key = str(var_name)
                if key not in out:
                    out[key] = TaintSource(
                        expr=expr,
                        location=f"{tpl_name}.variables.{var_name}",
                    )
                break
    return out


def _references_unquoted_var(text: str, var_name: str) -> bool:
    """True when *text* references ``$<var_name>`` outside a
    quoted token.

    Mirrors the quote-state walker used by the dotenv consumer
    pass: a reference inside ``"..."`` is treated as safe
    (single-token expansion); single quotes neutralise entirely.
    """
    in_single = False
    in_double = False
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            i += 1
            continue
        if ch == "$" and not (in_single or in_double):
            m = _NAME_BOUNDARY.match(text, i)
            if m and m.group("name") == var_name:
                return True
        i += 1
    return False


# Top-level GitLab CI keywords that aren't jobs. Mirrors the set
# ``iter_jobs`` filters; we apply the same rule when building the
# extends-chain universe so non-job entries (workflow, default,
# include, etc.) don't get pulled in.
_NON_JOB_KEYS: frozenset[str] = frozenset({
    "variables", "default", "stages", "include", "workflow",
    "image", "services", "before_script", "after_script",
    "script", "cache",
})


def analyze_extends_taint(doc: dict[str, Any]) -> list[TaintPath]:
    """Find tainted variables propagated via ``extends:`` chains.

    GL-002 catches direct interpolation when the tainted variable
    is declared on the consuming job (or globally). The
    inheritance pattern this analyzer covers:

      .base:
        variables:
          TITLE: $CI_COMMIT_TITLE         # tainted, hidden template

      build:
        extends: .base
        script:
          - echo Building $TITLE          # GL-002 misses this — TITLE
                                          # isn't in this job's
                                          # variables block

    ``iter_jobs`` skips hidden templates (the GitLab convention),
    so the tainted ``variables:`` block in ``.base`` is invisible
    to single-job rules. Two-pass walk:

      1. Build a universe of every job-shaped entry (hidden
         templates included). Resolve each non-hidden job's
         ``extends:`` chain transitively, breaking cycles via a
         visited set.
      2. For every link in the chain, gather tainted variable
         names from its ``variables:`` block. Walk the consuming
         job's ``before_script:`` / ``script:`` / ``after_script:``
         lines for unquoted references to those names. Each match
         emits a :class:`TaintPath`.
    """
    if not isinstance(doc, dict):
        return []

    all_jobs: dict[str, dict[str, Any]] = {}
    for name, value in doc.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            continue
        if name in _NON_JOB_KEYS:
            continue
        all_jobs[name] = value

    paths: list[TaintPath] = []
    for job_name, job in iter_jobs(doc):
        extends = job.get("extends")
        if extends is None:
            continue
        chain = _resolve_extends_chain(extends, all_jobs)
        if not chain:
            continue
        inherited = _gather_inherited_taint(chain, all_jobs)
        if not inherited:
            continue
        for line_idx, line in enumerate(job_scripts(job)):
            for var_name, src in inherited.items():
                if _references_unquoted_var(line, var_name):
                    paths.append(TaintPath(
                        source=src,
                        hops=(
                            "extends.<chain>",
                            f"${var_name}",
                        ),
                        sink_location=(
                            f"{job_name}:script[{line_idx}]"
                        ),
                        sink_consumer=f"${var_name}",
                    ))
    return paths


__all__ = [
    "TaintPath",
    "TaintSource",
    "analyze_extends_taint",
    "analyze_pipeline",
]
